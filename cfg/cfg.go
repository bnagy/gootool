package cfg

import (
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
// exits iff they end with ret. Calls doesn't use *BBL because they can be
// stubs, for which no BBL exists
type BBL struct {
	Addr     uint
	Symbol   symlist.SymEntry // symbol for the head insn
	Calls    map[uint]bool    // calls to other funcs ( don't break blocks )
	Edges    []Edge
	Insns    []cs.Instruction
	Tail     []cs.Instruction // Dead code at the end of a block ( nops, junk after a ret etc)
	CrawlTag *uint32          // Needed by concurrent crawlers
}

func NewBBL(addr uint) *BBL {
	tag := uint32(0)
	return &BBL{
		Addr:     addr,
		Calls:    make(map[uint]bool),
		Edges:    make([]Edge, 0),
		Insns:    make([]cs.Instruction, 0),
		Tail:     make([]cs.Instruction, 0),
		CrawlTag: &tag,
	}
}

// sort.Sort interface impl
type ByAddr []BBL

func (a ByAddr) Len() int           { return len(a) }
func (a ByAddr) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByAddr) Less(i, j int) bool { return a[i].Addr < a[j].Addr }

type CFG struct {
	Graph         map[uint]*BBL
	SDB           *symlist.SymList
	thisBBL       *BBL // little state vars to make the building easier
	gatheringTail bool
}

func NewCFG(sdb *symlist.SymList) *CFG {
	return &CFG{
		Graph: make(map[uint]*BBL),
		SDB:   sdb,
	}
}

// Follows the type signature for a disasmCB in gootool.go
func (cfg *CFG) BuildNodes(insn cs.Instruction) error {

	// First pass, just fill in the instructions and add the nodes to the map

	if _, ok := cfg.SDB.At(insn.Address); ok { // starting new BBL
		sym, _, _ := cfg.SDB.Near(insn.Address)
		cfg.thisBBL = NewBBL(insn.Address)
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
	if _, exists := cfg.SDB.At(dest); !exists {
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
				if _, exists := cfg.SDB.At(imm); exists {
					bbl.Calls[imm] = true
				}
			}
		}

		lastInsn := bbl.Insns[len(bbl.Insns)-1]

		// Conditional jmp. Add true / false edge
		if util.IsBranchImm(lastInsn) {

			imm := uint(lastInsn.X86.Operands[0].Imm)
			cfg.linkBBLToAddr(bbl, TrueEdge, imm)

			var fallTo uint64
			if len(bbl.Tail) > 0 {
				tail := bbl.Tail[len(bbl.Tail)-1]
				fallTo = uint64(tail.Address + tail.Size)
			} else {
				fallTo = uint64(lastInsn.Address + lastInsn.Size)
			}

			if cfg.SDB.InText(fallTo) {
				cfg.linkBBLToAddr(bbl, FalseEdge, uint(fallTo))
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
		var fallTo uint64
		if len(bbl.Tail) > 0 {
			tail := bbl.Tail[len(bbl.Tail)-1]
			fallTo = uint64(tail.Address + tail.Size)
		} else {
			fallTo = uint64(lastInsn.Address + lastInsn.Size)
		}

		if cfg.SDB.InText(fallTo) {
			cfg.linkBBLToAddr(bbl, AlwaysEdge, uint(fallTo))
		}
	}

	cfg.consolidateCalls()

}

func (g *CFG) consolidateCalls() {
	// Crawl the BBLs that are reachable from each function head and add their
	// calls to the map of the head BBL
	for e := g.SDB.Front(); e != nil; e = e.Next() {

		if sym := e.Value.(symlist.SymEntry); sym.IsFunc() {

			bbl, ok := g.Graph[uint(sym.Value)]
			if !ok {
				continue
			}

			for node := range g.CrawlFrom(sym) {
				for addr := range node.Calls {
					if _, ok := g.SDB.At(addr); ok {
						bbl.Calls[addr] = true
					}
				}
			}
		}

	}
}

func (g *CFG) crawl(bbl BBL, tag uint32, results chan<- BBL, wg *sync.WaitGroup) {

	for {

		// Atomically increment the BBL tag
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
			if bbl.Edges[0].Target.Symbol.IsFunc() {
				wg.Done()
				return
			}
			bbl = *bbl.Edges[0].Target
		case 2:
			// Spin up another crawler to handle the second edge
			wg.Add(1)
			go g.crawl(*bbl.Edges[1].Target, tag, results, wg)
			// This crawler follows the first
			bbl = *bbl.Edges[0].Target
		default:
			log.Panicf("Too many edges for BBL: %v", bbl)
		}

	}

}

func (g *CFG) CrawlFrom(sym symlist.SymEntry) <-chan BBL {

	results := make(chan BBL)
	wg := &sync.WaitGroup{}
	if bbl, exists := g.Graph[uint(sym.Value)]; exists {
		tag := *bbl.CrawlTag
		go func() {
			wg.Add(1)
			go g.crawl(*bbl, tag, results, wg)
			wg.Wait()
			close(results)
		}()
	}

	return results

}
