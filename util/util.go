package util

import (
	cs "github.com/bnagy/gapstone"
)

func InGroup(insn cs.Instruction, grp uint) bool {
	for _, g := range insn.Groups {
		if g == grp {
			return true
		}
	}
	return false
}

// Conditional JMP to an immediate
func IsBranchImm(insn cs.Instruction) bool {
	if InGroup(insn, cs.X86_GRP_JUMP) && insn.Id != cs.X86_INS_JMP {
		if insn.X86.Operands[0].Type == cs.X86_OP_IMM {
			return true
		}
	}
	return false
}

// Unconditional JMP to an immediate ( JMP / LONGJMP )
func IsUncondImm(insn cs.Instruction) bool {
	if insn.Id == cs.X86_INS_JMP && insn.X86.Operands[0].Type == cs.X86_OP_IMM {
		return true
	}
	return false
}

// Any JMP to an immediate
func IsJmpImm(insn cs.Instruction) bool {
	if InGroup(insn, cs.X86_GRP_JUMP) && insn.X86.Operands[0].Type == cs.X86_OP_IMM {
		return true
	}
	return false
}

// CALL of an immediate
func IsCallImm(insn cs.Instruction) bool {
	if insn.Id == cs.X86_INS_CALL && insn.X86.Operands[0].Type == cs.X86_OP_IMM {
		return true
	}
	return false
}

// Any JMP or CALL to an immediate
func IsJmpCallImm(insn cs.Instruction) bool {
	if InGroup(insn, cs.X86_GRP_JUMP) || insn.Id == cs.X86_INS_CALL {
		if insn.X86.Operands[0].Type == cs.X86_OP_IMM {
			return true
		}
	}
	return false
}
