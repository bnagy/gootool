package util

import (
	cs "github.com/bnagy/gapstone"
)

// InGroup - bool, is the instruction in a given capstone group (as a uint)
func InGroup(insn cs.Instruction, grp uint) bool {
	for _, g := range insn.Groups {
		if g == grp {
			return true
		}
	}
	return false
}

// IsBranchImm - bool, is it a conditional JMP to an immediate
func IsBranchImm(insn cs.Instruction) bool {
	if InGroup(insn, cs.X86_GRP_JUMP) && insn.Id != cs.X86_INS_JMP {
		if insn.X86.Operands[0].Type == cs.X86_OP_IMM {
			return true
		}
	}
	return false
}

// IsUncondImm - bool, is it an unconditional JMP to an immediate ( JMP / LONGJMP )
func IsUncondImm(insn cs.Instruction) bool {
	if insn.Id == cs.X86_INS_JMP && insn.X86.Operands[0].Type == cs.X86_OP_IMM {
		return true
	}
	return false
}

// IsJmpImm - bool, is it any JMP to an immediate ( conditional or not )
func IsJmpImm(insn cs.Instruction) bool {
	if InGroup(insn, cs.X86_GRP_JUMP) && insn.X86.Operands[0].Type == cs.X86_OP_IMM {
		return true
	}
	return false
}

// IsCallImm - bool, is it a CALL of an immediate
func IsCallImm(insn cs.Instruction) bool {
	if insn.Id == cs.X86_INS_CALL && insn.X86.Operands[0].Type == cs.X86_OP_IMM {
		return true
	}
	return false
}

// IsJmpCallImm - bool, is it any JMP to or CALL of an immediate
func IsJmpCallImm(insn cs.Instruction) bool {
	if InGroup(insn, cs.X86_GRP_JUMP) || insn.Id == cs.X86_INS_CALL {
		if insn.X86.Operands[0].Type == cs.X86_OP_IMM {
			return true
		}
	}
	return false
}
