package cfg

import (
	cs "github.com/bnagy/gapstone"
	"github.com/bnagy/gootool/symlist"
	"github.com/bnagy/gootool/util"
	// "log"
	"sync"
	"sync/atomic"
)

// Basic blocks are expected to have 1 Edge, 1 TrueEdge + 1 FalseEdge or no
// exits iff they end with ret. CallEdges doesn't use *BBL because they can be
// stubs, for which no BBL exists
type BBL struct {
	Symbol    symlist.SymEntry // symbol for the head insn
	CallEdges map[uint]bool    // calls to other funcs ( don't break blocks )
	TrueEdge  *BBL             // conditional jumps, taken
	FalseEdge *BBL             // conditional jumps, fallthrough
	Edge      *BBL             // jmp or fallthrough to a new BBL
	Insns     []cs.Instruction
	Tail      []cs.Instruction // Dead code at the end of a block ( nops, junk after a ret etc)
	CrawlTag  *uint32          // Needed by concurrent crawlers
}

// Doesn't distinguish between no edge ( nil ptr ) and an edge to address 0x0.
// For cases where that's important you should check the values manually.
func (bbl *BBL) Edges() (uint64, uint64, uint64) {
	var te, fe, ae uint64
	if bbl.TrueEdge != nil {
		te = bbl.TrueEdge.Symbol.Value
	}
	if bbl.FalseEdge != nil {
		fe = bbl.FalseEdge.Symbol.Value
	}
	if bbl.Edge != nil {
		ae = bbl.Edge.Symbol.Value
	}
	return te, fe, ae
}

func NewBBL() *BBL {
	tag := uint32(0)
	return &BBL{
		CallEdges: make(map[uint]bool),
		Insns:     make([]cs.Instruction, 0),
		Tail:      make([]cs.Instruction, 0),
		CrawlTag:  &tag,
	}
}

type CFG struct {
	Graph         map[uint]*BBL
	sdb           *symlist.SymList
	thisBBL       *BBL // little state vars to make the building easier
	gatheringTail bool
}

func NewCFG(sdb *symlist.SymList) *CFG {
	return &CFG{
		Graph: make(map[uint]*BBL),
		sdb:   sdb,
	}
}

// Follows the type signature for a disasmCB in gootool.go
func (cfg *CFG) BuildNodes(insn cs.Instruction) error {

	// First pass, just fill in the instructions and add the nodes to the map

	if _, ok := cfg.sdb.At(insn.Address); ok { // starting new BBL
		sym, _, _ := cfg.sdb.Near(insn.Address)
		cfg.thisBBL = NewBBL()
		cfg.thisBBL.Symbol = sym
		cfg.Graph[insn.Address] = cfg.thisBBL
		cfg.gatheringTail = false
	}

	// Suppress nop stuff after a ret insn
	if insn.Id == cs.X86_INS_RET {
		cfg.gatheringTail = true
		cfg.thisBBL.Insns = append(cfg.thisBBL.Insns, insn)
		return nil
	}

	if insn.Id == cs.X86_INS_NOP && cfg.gatheringTail {
		cfg.thisBBL.Tail = append(cfg.thisBBL.Tail, insn)
	} else {
		cfg.gatheringTail = false
		cfg.thisBBL.Insns = append(cfg.thisBBL.Insns, insn)
	}

	return nil

}

// Call this once the CFG has been constructed, to perform second+ pass
// analysis and fixups etc.
func (cfg *CFG) LinkNodes() {

	// Second pass - link the Nodes
	for _, bbl := range cfg.Graph {

		for _, insn := range bbl.Insns {
			// CALL - add a call edge
			if util.IsCallImm(insn) {
				imm := uint(insn.X86.Operands[0].Imm)
				bbl.CallEdges[imm] = true
			}
		}

		lastInsn := bbl.Insns[len(bbl.Insns)-1]

		// Conditional jmp. Add true / false edge
		if util.IsBranchImm(lastInsn) {

			imm := uint(lastInsn.X86.Operands[0].Imm)

			bbl.TrueEdge = cfg.Graph[imm]

			if len(bbl.Tail) > 0 {
				tail := bbl.Tail[len(bbl.Tail)-1]
				fallTo := tail.Address + tail.Size
				bbl.FalseEdge = cfg.Graph[fallTo]
			} else {
				fallTo := lastInsn.Address + lastInsn.Size
				bbl.FalseEdge = cfg.Graph[fallTo]
			}

			continue

		}

		// Unconditional jmp. Add single edge to that Imm.
		if util.IsUncondImm(lastInsn) {
			imm := uint(lastInsn.X86.Operands[0].Imm)
			bbl.Edge = cfg.Graph[imm]
			continue
		}

		// RET - No exit edges from this bbl
		if lastInsn.Id == cs.X86_INS_RET {
			continue
		}

		// Everything else - add a fallthrough edge to the next BBL
		if len(bbl.Tail) > 0 {
			tail := bbl.Tail[len(bbl.Tail)-1]
			fallTo := tail.Address + tail.Size
			bbl.Edge = cfg.Graph[fallTo]
		} else {
			fallTo := lastInsn.Address + lastInsn.Size
			bbl.Edge = cfg.Graph[fallTo]
		}
	}

}

func (g *CFG) Crawl(bbl BBL, tag uint32, results chan<- BBL, wg *sync.WaitGroup) {

	for {

		swapped := atomic.CompareAndSwapUint32(bbl.CrawlTag, tag, tag+1)
		if !swapped {
			// Someone beat us here, abort.
			break
		}

		results <- bbl

		te, fe, ae := bbl.Edges()
		if te > 0 && fe > 0 {

			// spawn a new worker for the true edge
			if tbbl, exists := g.Graph[uint(te)]; exists {
				wg.Add(1)
				go g.Crawl(*tbbl, tag, results, wg)
			}

			// this worker follows the false edge
			if fbbl, exists := g.Graph[uint(fe)]; exists {
				bbl = *fbbl
				continue
			}

			// .. unless the false edge was invalid, just die
			break
		}

		if ae > 0 {
			// follow the always edge, if it exists
			if abbl, exists := g.Graph[uint(ae)]; exists {

				// SPECIAL CASE - don't crawl always edges that fall through
				// to a function head
				if s, exists := g.sdb.At(uint(ae)); exists && s.Func {
					break
				}

				bbl = *abbl
				continue
			}
			break
		}

		// No more edges.
		break
	}

	wg.Done()
	return

}

func (g *CFG) CrawlFrom(sym symlist.SymEntry, results chan<- BBL) {

	wg := &sync.WaitGroup{}
	if bbl, exists := g.Graph[uint(sym.Value)]; exists {
		// Crawlers will atomic.CompareAndSwapUint32 the tag they find in each
		// node with the new tag. If no swap was done then the node has been
		// visited, and that crawl routine will abort. This lets us spawn when
		// we hit a branch and have one routine die if the paths reconverge
		tag := *bbl.CrawlTag
		go func() {
			wg.Add(1)
			go g.Crawl(*bbl, tag, results, wg)
			wg.Wait()
			close(results)
		}()
	}

	return

}
