package cfg

import (
	cs "github.com/bnagy/gapstone"
	"github.com/bnagy/gootool/symlist"
)

func inGroup(insn cs.Instruction, grp uint) bool {
	for _, g := range insn.Groups {
		if g == grp {
			return true
		}
	}
	return false
}

// Conditional JMP to an immediate
func isBranchImm(insn cs.Instruction) bool {
	if inGroup(insn, cs.X86_GRP_JUMP) && insn.Id != cs.X86_INS_JMP {
		if insn.X86.Operands[0].Type == cs.X86_OP_IMM {
			return true
		}
	}
	return false
}

// Unconditional JMP to an immediate ( JMP / LONGJMP )
func isUncondImm(insn cs.Instruction) bool {
	if insn.Id == cs.X86_INS_JMP && insn.X86.Operands[0].Type == cs.X86_OP_IMM {
		return true
	}
	return false
}

// Any JMP to an immediate
func isJmpImm(insn cs.Instruction) bool {
	if inGroup(insn, cs.X86_GRP_JUMP) && insn.X86.Operands[0].Type == cs.X86_OP_IMM {
		return true
	}
	return false
}

// CALL of an immediate
func isCallImm(insn cs.Instruction) bool {
	if insn.Id == cs.X86_INS_CALL && insn.X86.Operands[0].Type == cs.X86_OP_IMM {
		return true
	}
	return false
}

// Any JMP or CALL to an immediate
func isAnyImm(insn cs.Instruction) bool {
	if inGroup(insn, cs.X86_GRP_JUMP) || insn.Id == cs.X86_INS_CALL {
		if insn.X86.Operands[0].Type == cs.X86_OP_IMM {
			return true
		}
	}
	return false
}

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

type CFG struct {
	Graph         map[uint]*BBL
	thisBBL       *BBL
	gatheringTail bool
}

func NewCFG() *CFG {
	return &CFG{
		Graph: make(map[uint]*BBL),
	}
}

func (cfg *CFG) BuildNodes(insn cs.Instruction, sdb *symlist.SymList) error {

	// First pass, just fill in the instructions and add the nodes to the map

	if _, ok := sdb.At(insn.Address); ok { // starting new BBL
		sym, _, _ := sdb.Near(insn.Address)
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

func (cfg *CFG) LinkNodes() {

	// Second pass - link the Nodes
	for _, bbl := range cfg.Graph {

		lastInsn := bbl.Insns[len(bbl.Insns)-1]

		// Conditional jmp. Add true / false edge
		if isBranchImm(lastInsn) {

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
		if isUncondImm(lastInsn) {
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
