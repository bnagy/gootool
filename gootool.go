package main

import (
	"bytes"
	"debug/macho"
	"encoding/hex"
	"flag"
	"fmt"
	cs "github.com/bnagy/gapstone"
	"github.com/bnagy/gootool/cfg"
	"github.com/bnagy/gootool/symlist"
	"log"
	"os"
	"path"
)

const N_SECT = uint8(0x0e)

var outbuf = new(bytes.Buffer) // This will go away once we convert to graphy stuff
type disasmCB func(insn cs.Instruction, symDB *symlist.SymList) error

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

func dumpResolvedImmediate(buf *bytes.Buffer, insn cs.Instruction, sym symlist.SymEntry, off int) {
	if off > 0 {
		fmt.Fprintf(
			buf,
			"0x%x: %-24.24s %-12.12s%s+0x%x [ %s ]\n",
			insn.Address,
			hex.EncodeToString(insn.Bytes),
			insn.Mnemonic,
			sym.Name,
			off,
			insn.OpStr,
		)
	} else {
		fmt.Fprintf(
			buf,
			"0x%x: %-24.24s %-12.12s%s [ %s ]\n",
			insn.Address,
			hex.EncodeToString(insn.Bytes),
			insn.Mnemonic,
			sym.Name,
			insn.OpStr,
		)
	}
}

func dumpUnresolvedImmediate(buf *bytes.Buffer, insn cs.Instruction) {
	fmt.Fprintf(
		buf,
		"0x%x: %-24.24s %-12.12s%s [ ??? ]\n",
		insn.Address,
		hex.EncodeToString(insn.Bytes),
		insn.Mnemonic,
		insn.OpStr,
	)
}

func dumpInsn(buf *bytes.Buffer, insn cs.Instruction) {
	fmt.Fprintf(
		buf,
		"0x%x: %-24.24s %-12.12s%s\n",
		insn.Address,
		hex.EncodeToString(insn.Bytes),
		insn.Mnemonic,
		insn.OpStr,
	)
}

func disasm(engine *cs.Engine, callback disasmCB, code []byte, sdb *symlist.SymList) {

	base := sdb.Front().Value.(symlist.SymEntry).Value
	cursor := uint64(0)

disasm:
	for {

		if cursor >= uint64(len(code)) {
			break disasm
		}

		insns, _ := engine.Disasm(
			code[cursor:], // code buffer
			cursor+base,   // starting address
			0,             // insns to disassemble, 0 for all
		)

		for _, insn := range insns {
			cursor = uint64(insn.Address) - base
			callback(insn, sdb)
		}

		// If there's a symbol > the end cursor, start disassembling again
		// from that symbol, in case we have:
		// 0x2000 __text: CODE
		// 0x2ff8 GARBAGE ( capstone disassembly will error )
		// 0x3000 some_new_sym: MORE CODE
		for s := sdb.Front(); s != nil; s = s.Next() {
			this := s.Value.(symlist.SymEntry)
			if this.Value > cursor+base {
				cursor = this.Value - base
				continue disasm
			}
		}

		break

	} // end disasm loop

}

func symboliseBBLs(insn cs.Instruction, sdb *symlist.SymList) error {
	if isAnyImm(insn) {
		// Add a BBL head symbol for the target of any jmp or call with an
		// immediate operand
		imm := uint64(insn.X86.Operands[0].Imm)
		if _, exists := sdb.At(uint(imm)); !exists {
			sdb.AddBBL(
				macho.Symbol{
					Name:  fmt.Sprintf("loc_0x%x", imm),
					Type:  N_SECT,
					Sect:  uint8(1),
					Desc:  uint16(0),
					Value: imm,
				},
			)
		}
		if isJmpImm(insn) {
			if _, exists := sdb.At(insn.Address + insn.Size); !exists {
				sdb.AddBBL(
					macho.Symbol{
						Name:  fmt.Sprintf("loc_0x%x", insn.Address+insn.Size),
						Type:  N_SECT,
						Sect:  uint8(1),
						Desc:  uint16(0),
						Value: uint64(insn.Address + insn.Size),
					},
				)
			}
		}
	}

	return nil
}

func dumpBlocks(insn cs.Instruction, sdb *symlist.SymList) error {

	outbuf.Reset()

	// Mark up symbols as ( hopefully ) function heads
	if _, ok := sdb.At(insn.Address); ok {
		// The Lookup names are usually nicer - eg you get
		// main.validateSignature instead of _text
		s, _, _ := sdb.Near(insn.Address)
		fmt.Printf("\n%v:\n", s.Name)
	}

	// Try to symbolically resolve any jmp/call with an immediate operand
	if (inGroup(insn, cs.X86_GRP_JUMP) || insn.Id == cs.X86_INS_CALL) &&
		insn.X86.Operands[0].Type == cs.X86_OP_IMM {

		imm := uint(insn.X86.Operands[0].Imm)
		if sym, off, found := sdb.Near(imm); found {
			dumpResolvedImmediate(outbuf, insn, sym, off)
		} else {
			dumpUnresolvedImmediate(outbuf, insn)
		}

		fmt.Print(outbuf.String())
		// if the NEXT instruction does not exist in the symbol DB, and this
		// is any jmp, this is the end of a basic block, and we mark up the
		// head of the next one. call instructions don't end a basic block
		// node
		if _, exists := sdb.At(insn.Address + insn.Size); !exists && insn.Id != cs.X86_INS_CALL {
			fmt.Printf("\nloc_0x%x:\n", insn.Address+insn.Size)
		}
		return nil

	}

	// fallthrough
	dumpInsn(outbuf, insn)
	fmt.Print(outbuf.String())
	return nil

}

func main() {

	flag.Parse()

	machOObj, err := macho.Open(flag.Arg(0))
	if err != nil {
		fmt.Fprintf(
			os.Stderr,
			"Unable to open Mach-O binary \"%v\": %v\n"+
				"Usage: %s [filename]\n",
			flag.Arg(0),
			err,
			path.Base(os.Args[0]),
		)
		os.Exit(1)
	}

	textSection := machOObj.Section("__text")
	if textSection == nil {
		log.Fatal("Text section not found.")
	}

	textBytes, err := textSection.Data()
	if err != nil {
		log.Fatalf("Error parsing __text: %v", err)
	}

	sdb, err := symlist.NewSymList(machOObj)
	if err != nil {
		log.Fatalf("Unable to create SymList: %v", err)
	}

	engine, err := cs.New(
		cs.CS_ARCH_X86,
		cs.CS_MODE_64,
	)
	if err == nil {

		defer engine.Close()
		engine.SetOption(cs.CS_OPT_DETAIL, cs.CS_OPT_ON)
		log.Println("Symbolizing...")

		disasm(&engine, symboliseBBLs, textBytes, sdb)

		log.Println("Building graph...")
		g := cfg.NewCFG()
		disasm(&engine, g.BuildNodes, textBytes, sdb)
		g.LinkNodes()

		for _, bbl := range g.Graph {
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
			fmt.Printf("\n%v Len: %v Tail: %v Edges: T:0x%x F:0x%x A:0x%x\n",
				bbl.Symbol.Name,
				len(bbl.Insns),
				len(bbl.Tail),
				te,
				fe,
				ae,
			)
			for _, insn := range bbl.Insns {
				dumpBlocks(insn, sdb)
			}
			for _, insn := range bbl.Tail {
				dumpBlocks(insn, sdb)
			}
		}
	}

}
