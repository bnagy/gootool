package cfg

import (
	cs "github.com/bnagy/gapstone"
	"github.com/bnagy/gootool/symlist"
	"github.com/bnagy/gootool/util"
	"log"
	"sync"
	"sync/atomic"
)

// EdgeType is mainly for pretty rendering
type EdgeType uint8

// Available EdgeTypes
const (
	FalseEdge  EdgeType = 0
	TrueEdge   EdgeType = 1
	AlwaysEdge EdgeType = 2
)

// Edge links two Nodes
type Edge struct {
	Target *Node
	Type   EdgeType
}

// Node is the fundamental graph element. Nodes are expected to have 1 Edge, 1
// TrueEdge + 1 FalseEdge or no exits iff they end with ret OR they end with a
// call to a stub. The Calls member doesn't use *Node because they can be
// stubs, for which no Node exists
type Node struct {
	Addr     uint
	Symbol   symlist.SymEntry // symbol for the head insn
	Calls    map[uint]bool    // calls to other funcs ( don't break blocks )
	Edges    []Edge
	Insns    []cs.Instruction
	Tail     []cs.Instruction // Dead code at the end of a block ( nops, junk after a ret etc)
	CrawlTag *uint32          // Needed by concurrent crawlers
}

// NewNode initializes a Node
func NewNode(addr uint) *Node {
	tag := uint32(0)
	return &Node{
		Addr:     addr,
		Calls:    make(map[uint]bool),
		Edges:    make([]Edge, 0),
		Insns:    make([]cs.Instruction, 0),
		Tail:     make([]cs.Instruction, 0),
		CrawlTag: &tag,
	}
}

// ByAddr is an interface for sort.Sort
type ByAddr []Node

func (a ByAddr) Len() int           { return len(a) }
func (a ByAddr) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByAddr) Less(i, j int) bool { return a[i].Addr < a[j].Addr }

// CFG is the combination of a Graph and a symbol DB
type CFG struct {
	Graph         map[uint]*Node
	SDB           *symlist.SymList
	thisNode      *Node // little state vars to make the building easier
	gatheringTail bool
}

// NewCFG initializes a new CFG
func NewCFG(sdb *symlist.SymList) *CFG {
	return &CFG{
		Graph: make(map[uint]*Node),
		SDB:   sdb,
	}
}

// BuildNodes follows the type signature for a disasmCB in gootool.go. It only
// tries to create the Nodes for the graph, Edges are added in later steps.
func (cfg *CFG) BuildNodes(insn cs.Instruction) error {

	// First pass, just fill in the instructions and add the nodes to the map

	if _, ok := cfg.SDB.At(insn.Address); ok { // starting new Node
		sym, _, _ := cfg.SDB.Near(insn.Address)
		cfg.thisNode = NewNode(insn.Address)
		cfg.thisNode.Symbol = sym
		cfg.Graph[insn.Address] = cfg.thisNode
		cfg.gatheringTail = false
	}

	// Suppress nop stuff after a ret insn
	if insn.Id == cs.X86_INS_RET {
		cfg.gatheringTail = true
		cfg.thisNode.Insns = append(cfg.thisNode.Insns, insn)
		return nil
	}

	if insn.Id == cs.X86_INS_NOP && cfg.gatheringTail {
		cfg.thisNode.Tail = append(cfg.thisNode.Tail, insn)
	} else {
		cfg.gatheringTail = false
		cfg.thisNode.Insns = append(cfg.thisNode.Insns, insn)
	}

	return nil

}

func (cfg *CFG) linkNodeToAddr(bbl *Node, et EdgeType, dest uint) bool {

	// No symbol, no link
	if _, exists := cfg.SDB.At(dest); !exists {
		return false
	}

	// No destination Node, no link
	if target, exists := cfg.Graph[dest]; exists {
		bbl.Edges = append(bbl.Edges, Edge{Target: target, Type: et})
		return true
	}

	return false

}

// LinkNodes must be called once the CFG has been constructed, to
// perform second+ pass analysis and fixups etc.
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
			cfg.linkNodeToAddr(bbl, TrueEdge, imm)

			var fallTo uint64
			if len(bbl.Tail) > 0 {
				tail := bbl.Tail[len(bbl.Tail)-1]
				fallTo = uint64(tail.Address + tail.Size)
			} else {
				fallTo = uint64(lastInsn.Address + lastInsn.Size)
			}

			if cfg.SDB.InText(fallTo) {
				cfg.linkNodeToAddr(bbl, FalseEdge, uint(fallTo))
			}

			continue

		}

		// Unconditional jmp. Add single edge to that Imm.
		if util.IsUncondImm(lastInsn) {
			imm := uint(lastInsn.X86.Operands[0].Imm)
			cfg.linkNodeToAddr(bbl, AlwaysEdge, imm)
			continue
		}

		// RET - No exit edges from this bbl
		if lastInsn.Id == cs.X86_INS_RET {
			continue
		}

		// Everything else - add a fallthrough edge to the next Node
		var fallTo uint64
		if len(bbl.Tail) > 0 {
			tail := bbl.Tail[len(bbl.Tail)-1]
			fallTo = uint64(tail.Address + tail.Size)
		} else {
			fallTo = uint64(lastInsn.Address + lastInsn.Size)
		}

		if cfg.SDB.InText(fallTo) {
			cfg.linkNodeToAddr(bbl, AlwaysEdge, uint(fallTo))
		}
	}

	cfg.consolidateCalls()

}

func (cfg *CFG) consolidateCalls() {
	// Crawl the Nodes that are reachable from each function head and add their
	// calls to the map of the head Node
	for e := cfg.SDB.Front(); e != nil; e = e.Next() {

		if sym := e.Value.(symlist.SymEntry); sym.IsFunc() {

			bbl, ok := cfg.Graph[uint(sym.Value)]
			if !ok {
				continue
			}

			for node := range cfg.CrawlFrom(sym) {
				for addr := range node.Calls {
					if _, ok := cfg.SDB.At(addr); ok {
						bbl.Calls[addr] = true
					}
				}
			}
		}

	}
}

func (cfg *CFG) crawl(bbl Node, tag uint32, results chan<- Node, wg *sync.WaitGroup) {

	for {

		// Atomically increment the Node tag
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
			go cfg.crawl(*bbl.Edges[1].Target, tag, results, wg)
			// This crawler follows the first
			bbl = *bbl.Edges[0].Target
		default:
			log.Panicf("Too many edges for Node: %v", bbl)
		}

	}

}

// CrawlFrom will concurrently crawl all reachable Nodes from a given symbol
// and return them on a channel.
func (cfg *CFG) CrawlFrom(sym symlist.SymEntry) <-chan Node {

	results := make(chan Node)
	wg := &sync.WaitGroup{}
	if bbl, exists := cfg.Graph[uint(sym.Value)]; exists {
		tag := *bbl.CrawlTag
		go func() {
			wg.Add(1)
			go cfg.crawl(*bbl, tag, results, wg)
			wg.Wait()
			close(results)
		}()
	}

	return results

}
