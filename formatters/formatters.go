package formatters

import (
	"bytes"
	"encoding/hex"
	"fmt"
	cs "github.com/bnagy/gapstone"
	"github.com/bnagy/gootool/symlist"
	"github.com/bnagy/gootool/util"
)

func dumpResolvedImmediate(buf *bytes.Buffer, insn cs.Instruction, sym symlist.SymEntry, off int) {
	if off > 0 {
		fmt.Fprintf(
			buf,
			"0x%x: %-24.24s %-12.12s%s+0x%x",
			insn.Address,
			hex.EncodeToString(insn.Bytes),
			insn.Mnemonic,
			sym.Name,
			off,
		)
	} else {
		fmt.Fprintf(
			buf,
			"0x%x: %-24.24s %-12.12s%s",
			insn.Address,
			hex.EncodeToString(insn.Bytes),
			insn.Mnemonic,
			sym.Name,
		)
	}
}

func dumpUnresolvedImmediate(buf *bytes.Buffer, insn cs.Instruction) {
	fmt.Fprintf(
		buf,
		"0x%x: %-24.24s %-12.12s%s [ ??? ]",
		insn.Address,
		hex.EncodeToString(insn.Bytes),
		insn.Mnemonic,
		insn.OpStr,
	)
}

func dumpDefault(buf *bytes.Buffer, insn cs.Instruction) {
	fmt.Fprintf(
		buf,
		"0x%x: %-24.24s %-12.12s%s",
		insn.Address,
		hex.EncodeToString(insn.Bytes),
		insn.Mnemonic,
		insn.OpStr,
	)
}

func DumpInsn(insn cs.Instruction, sdb *symlist.SymList, outbuf *bytes.Buffer) {

	// Try to symbolically resolve any jmp/call with an immediate operand
	if util.IsJmpCallImm(insn) {

		imm := uint(insn.X86.Operands[0].Imm)
		if sym, off, found := sdb.Near(imm); found {
			dumpResolvedImmediate(outbuf, insn, sym, off)
		} else {
			dumpUnresolvedImmediate(outbuf, insn)
		}

	} else {

		dumpDefault(outbuf, insn)
	}

}
