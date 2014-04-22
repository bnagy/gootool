package main

import (
	"bytes"
	"debug/macho"
	"encoding/hex"
	"flag"
	"fmt"
	cs "github.com/bnagy/gapstone"
	"github.com/bnagy/gootool/symlist"
	"log"
	"os"
	"path"
)

// https://developer.apple.com/library/mac/documentation/DeveloperTools/Conceptual/MachORuntime/Reference/reference.html#//apple_ref/doc/uid/20001298-BAJFFCGF
// N_SECT (0xe)—The symbol is defined in the section number given in n_sect.
// ( if this bit is set in the type byte, it means the n_value will be an address )
const N_SECT = uint8(0x0e)
const REFERENCED_DYNAMICALLY = uint16(0x0010)

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

func dumpResolvedImmediate(buf *bytes.Buffer, insn cs.Instruction, sym macho.Symbol, off int) {
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
		"=>0x%x: %-24.24s %-12.12s%s [ ??? ]\n",
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

func disasm(engine *cs.Engine, code []byte, userCB disasmCB, sdb *symlist.SymList) error {

	base := sdb.Front().Value.(macho.Symbol).Value
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

		// if err != nil {
		// 	//log.Fatalf("Disassembly error: %v", err)
		// 	panic("Disassembly error")
		// }

		for _, insn := range insns {
			cursor = uint64(insn.Address) - base
			err := userCB(insn, sdb)
			if err != nil {
				return err
			}

		} // end insn loop

		// If there's a symbol > the end cursor, start disassembling again
		// from that symbol, in case we have:
		// 0x2000 __text: CODE
		// 0x2ff8 GARBAGE ( capstone disassembly will error )
		// 0x3000 some_new_sym: MORE CODE
		for s := sdb.Front(); s != nil; s = s.Next() {
			this := s.Value.(macho.Symbol)
			if this.Value > cursor+base {
				cursor = this.Value - base
				continue disasm
			}
		}

		break

	} // end disasm loop

	return nil

}

func symboliseBBLs(insn cs.Instruction, sdb *symlist.SymList) error {

	if inGroup(insn, cs.X86_GRP_JUMP) || insn.Id == cs.X86_INS_CALL {

		if insn.X86.Operands[0].Type == cs.X86_OP_IMM {
			// Add a BBL head symbol for the target of any jmp or call with an
			// immediate operand
			imm := uint64(insn.X86.Operands[0].Imm)
			if _, exists := sdb.At(uint(imm)); !exists {
				sdb.Add(
					macho.Symbol{
						Name:  fmt.Sprintf("_loc 0x%x", imm),
						Type:  N_SECT,
						Sect:  uint8(1),
						Desc:  uint16(0),
						Value: imm,
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
		s, _, _ := sdb.Near(uint64(insn.Address))
		fmt.Printf("\n%v:\n", s.Name)
	}

	// Try to symbolically resolve any jmp/call with an immediate operand
	if (inGroup(insn, cs.X86_GRP_JUMP) || insn.Id == cs.X86_INS_CALL) &&
		insn.X86.Operands[0].Type == cs.X86_OP_IMM {

		imm := uint64(insn.X86.Operands[0].Imm)
		if sym, off, found := sdb.Near(imm); found {
			dumpResolvedImmediate(outbuf, insn, sym, off)
		} else {
			dumpUnresolvedImmediate(outbuf, insn)
		}

		fmt.Print(outbuf.String())
		if _, exists := sdb.At(insn.Address + insn.Size); !exists && insn.Id != cs.X86_INS_CALL {
			fmt.Printf("\n_loc 0x%x:\n", insn.Address+insn.Size)
		}
		return nil

	}

	// fallthrough
	dumpInsn(outbuf, insn)
	fmt.Print(outbuf.String())
	if _, exists := sdb.At(insn.Address + insn.Size); insn.Id != cs.X86_INS_RET && exists {
		// We're NOT a jmp or call, but there's a symbol for the next
		// instruction, so this is the end of an 'unterminated' BB.
		fmt.Printf("\t|\n\tV\n")
	}
	return nil

}

func dumpSymtab(st *macho.Symtab) {
	for _, sym := range st.Syms {
		fmt.Printf("%#v\n", sym)
	}
}

func dumpDysymtab(st *macho.Dysymtab) {
	// TODO: Work out how to get the stubs for external symbols, right now
	// libSystem stuff isn't resolved
	for _, sym := range st.IndirectSyms {
		fmt.Printf("%#v\n", sym)
	}
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

	symList := symlist.NewSymList()
	for _, sym := range machOObj.Symtab.Syms {
		// TODO: MACH-O SYMBOLS, HOW DO THEY WORK?
		if sym.Sect == 1 && // text section
			sym.Type&N_SECT > 0 && // N_SECT ( internal or external )
			sym.Name != "" && // Don't know what these blank names are :/
			sym.Desc != REFERENCED_DYNAMICALLY {

			symList.Add(sym)

		}
	}

	engine, err := cs.New(
		cs.CS_ARCH_X86,
		cs.CS_MODE_64,
	)
	if err == nil {

		defer engine.Close()
		engine.SetOption(cs.CS_OPT_DETAIL, cs.CS_OPT_ON)
		disasm(&engine, textBytes, symboliseBBLs, symList)
		disasm(&engine, textBytes, dumpBlocks, symList)

	}

}
