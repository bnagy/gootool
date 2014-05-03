package formatters

import (
	"bytes"
	// "encoding/hex"
	"fmt"
	cs "github.com/bnagy/gapstone"
	"github.com/bnagy/gootool/cfg"
	"github.com/bnagy/gootool/symlist"
	"github.com/bnagy/gootool/util"
)

func dumpResolvedImmediate(buf *bytes.Buffer, insn cs.Instruction, sym symlist.SymEntry, off int) {
	if off > 0 {
		fmt.Fprintf(
			buf,
			"0x%x: %-12.12s%s+0x%x",
			insn.Address,
			insn.Mnemonic,
			sym.Name,
			off,
		)
	} else {
		fmt.Fprintf(
			buf,
			"0x%x: %-12.12s%s",
			insn.Address,
			insn.Mnemonic,
			sym.Name,
		)
	}
}

func dumpUnresolvedImmediate(buf *bytes.Buffer, insn cs.Instruction) {
	fmt.Fprintf(
		buf,
		"0x%x: %-12.12s%s [ ??? ]",
		insn.Address,
		insn.Mnemonic,
		insn.OpStr,
	)
}

func dumpDefault(buf *bytes.Buffer, insn cs.Instruction) {
	fmt.Fprintf(
		buf,
		"0x%x: %-12.12s%s",
		insn.Address,
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

func DumpBBL(bbl *cfg.BBL, sdb *symlist.SymList, buf *bytes.Buffer) {

	// This is the part where I miss Ruby ;)

	sym := bbl.Symbol
	if sym.IsFunc() { // Function head
		fmt.Fprintf(buf, "\n(0x%x): ", bbl.Symbol.Value)
	}

	fmt.Fprintf(buf, "%v Len: %v Tail: %v Edges: ",
		bbl.Symbol.Name,
		len(bbl.Insns),
		len(bbl.Tail),
	)

	for _, e := range bbl.Edges {
		switch e.Type {
		case cfg.TrueEdge:
			fmt.Fprintf(buf, " T: %s", e.Target.Symbol.Name)
		case cfg.FalseEdge:
			fmt.Fprintf(buf, " F: %s", e.Target.Symbol.Name)
		case cfg.AlwaysEdge:
			fmt.Fprintf(buf, " A: %s", e.Target.Symbol.Name)

		}
	}

	if len(bbl.Calls) > 0 {
		fmt.Fprintf(buf, " Calls ==> [")
		for addr := range bbl.Calls {
			sym, _ := sdb.At(addr)
			fmt.Fprintf(buf, " %v ", sym.Name)
		}
		fmt.Fprintf(buf, "]")
	}
	if len(bbl.Edges) == 0 { // no edges
		fmt.Fprintf(buf, " [terminal]")
	}
	fmt.Fprintf(buf, "\n")
}
