package cfg

import (
	"bytes"
	"fmt"
	cs "github.com/bnagy/gapstone"
	"github.com/bnagy/gootool/symlist"
	"github.com/bnagy/gootool/util"
	"log"
	"sync"
	"sync/atomic"
)

type EdgeType uint8

const (
	FalseEdge  EdgeType = 0
	TrueEdge   EdgeType = 1
	AlwaysEdge EdgeType = 2
)

type Edge struct {
	Target *BBL
	Type   EdgeType
}

// Basic blocks are expected to have 1 Edge, 1 TrueEdge + 1 FalseEdge or no
// exits iff they end with ret. CallEdges doesn't use *BBL because they can be
// stubs, for which no BBL exists
type BBL struct {
	Symbol   symlist.SymEntry // symbol for the head insn
	Calls    map[uint]bool    // calls to other funcs ( don't break blocks )
	Edges    []Edge
	Insns    []cs.Instruction
	Tail     []cs.Instruction // Dead code at the end of a block ( nops, junk after a ret etc)
	CrawlTag *uint32          // Needed by concurrent crawlers
}

func NewBBL() *BBL {
	tag := uint32(0)
	return &BBL{
		Calls:    make(map[uint]bool),
		Edges:    make([]Edge, 0),
		Insns:    make([]cs.Instruction, 0),
		Tail:     make([]cs.Instruction, 0),
		CrawlTag: &tag,
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

func (cfg *CFG) linkBBLToAddr(bbl *BBL, et EdgeType, dest uint) bool {

	// No symbol, no link
	if _, exists := cfg.sdb.At(dest); !exists {
		return false
	}

	// No destination BBL, no link
	if target, exists := cfg.Graph[dest]; exists {
		bbl.Edges = append(bbl.Edges, Edge{Target: target, Type: et})
		return true
	}

	return false

}

// Call this once the CFG has been constructed, to perform second+ pass
// analysis and fixups etc.
func (cfg *CFG) LinkNodes() {

	// Second pass - link the Nodes
	for _, bbl := range cfg.Graph {

		for _, insn := range bbl.Insns {
			// CALL - add a call
			if util.IsCallImm(insn) {
				imm := uint(insn.X86.Operands[0].Imm)
				if _, exists := cfg.sdb.At(imm); exists {
					bbl.Calls[imm] = true
				}
			}
		}

		lastInsn := bbl.Insns[len(bbl.Insns)-1]

		// Conditional jmp. Add true / false edge
		if util.IsBranchImm(lastInsn) {

			imm := uint(lastInsn.X86.Operands[0].Imm)
			cfg.linkBBLToAddr(bbl, TrueEdge, imm)

			if len(bbl.Tail) > 0 {
				tail := bbl.Tail[len(bbl.Tail)-1]
				fallTo := tail.Address + tail.Size
				cfg.linkBBLToAddr(bbl, FalseEdge, fallTo)
			} else {
				fallTo := lastInsn.Address + lastInsn.Size
				cfg.linkBBLToAddr(bbl, FalseEdge, fallTo)
			}

			continue

		}

		// Unconditional jmp. Add single edge to that Imm.
		if util.IsUncondImm(lastInsn) {
			imm := uint(lastInsn.X86.Operands[0].Imm)
			cfg.linkBBLToAddr(bbl, AlwaysEdge, imm)
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
			cfg.linkBBLToAddr(bbl, AlwaysEdge, fallTo)
		} else {
			fallTo := lastInsn.Address + lastInsn.Size
			cfg.linkBBLToAddr(bbl, AlwaysEdge, fallTo)
		}
	}

}

func (cfg *CFG) BlatBBL(bbl *BBL, buf *bytes.Buffer) {

	// This is the part where I miss Ruby ;)

	sym := bbl.Symbol
	if sym.Func { // Function head
		fmt.Fprintf(buf, "\n(0x%x): ", bbl.Symbol.Value)
	}

	fmt.Fprintf(buf, "%v Len: %v Tail: %v Edges: ",
		bbl.Symbol.Name,
		len(bbl.Insns),
		len(bbl.Tail),
	)

	for _, e := range bbl.Edges {
		switch e.Type {
		case TrueEdge:
			fmt.Fprintf(buf, " T: %s", e.Target.Symbol.Name)
		case FalseEdge:
			fmt.Fprintf(buf, " F: %s", e.Target.Symbol.Name)
		case AlwaysEdge:
			fmt.Fprintf(buf, " A: %s", e.Target.Symbol.Name)

		}
	}

	if len(bbl.Calls) > 0 {
		fmt.Fprintf(buf, " Calls ==> [")
		for addr := range bbl.Calls {
			sym, _ := cfg.sdb.At(addr)
			fmt.Fprintf(buf, " %v ", sym.Name)
		}
		fmt.Fprintf(buf, "]")
	}
	if len(bbl.Edges) == 0 { // no edges
		fmt.Fprintf(buf, " [terminal]")
	}
	fmt.Fprintf(buf, "\n")
}

func (g *CFG) Crawl(bbl BBL, tag uint32, results chan<- BBL, wg *sync.WaitGroup) {

crawl:
	for {

		swapped := atomic.CompareAndSwapUint32(bbl.CrawlTag, tag, tag+1)
		if !swapped {
			// Another crawler beat us here. Die.
			wg.Done()
			return
		}

		results <- bbl

		switch len(bbl.Edges) {
		case 0:
			// No edges to crawl. Die.
			wg.Done()
			return
		case 1:
			// SPECIAL CASE - don't crawl always edges that fall through
			// to a function head
			if bbl.Edges[0].Target.Symbol.Func {
				break crawl
			}
			bbl = *bbl.Edges[0].Target
		case 2:
			// Spin up another crawler to handle the second edge
			wg.Add(1)
			go g.Crawl(*bbl.Edges[1].Target, tag, results, wg)
			// This crawler follows the first
			bbl = *bbl.Edges[0].Target
		default:
			log.Panicf("Too many edges for BBL: %v", bbl)
		}

	}

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
