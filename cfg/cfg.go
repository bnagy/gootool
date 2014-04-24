package cfg

import (
	cs "github.com/bnagy/gapstone"
	"github.com/bnagy/gootool/symlist"
)

// Basic blocks are expected to have 1 Edge, 1 TrueEdge + 1 FalseEdge or no
// exits iff they end with ret
type BBL struct {
	Symbol    symlist.SymEntry // symbol for the head insn
	CallEdges []*BBL           // calls to other funcs ( don't break blocks )
	TrueEdge  *BBL             // conditional jumps, taken
	FalseEdge *BBL             // conditional jumps, fallthrough
	Edge      *BBL             // jmp or fallthrough to a new BBL
	Insns     []cs.Instruction
	Tail      []cs.Instruction // Dead code at the end of a block ( nops, junk after a ret etc)
}

func NewBBL() *BBL {
	return &BBL{
		CallEdges: make([]*BBL, 0),
		Insns:     make([]cs.Instruction, 0),
		Tail:      make([]cs.Instruction, 0),
	}
}
