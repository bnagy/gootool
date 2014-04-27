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
func isJmpCallImm(insn cs.Instruction) bool {
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
	if isJmpCallImm(insn) {
		// Add a BBL head symbol for the target of any jmp or call with an
		// immediate operand
		imm := uint64(insn.X86.Operands[0].Imm)
		if _, exists := sdb.At(uint(imm)); !exists &&
			imm > sdb.TextBase && // don't add BBL heads outside the text section
			imm < sdb.TextBase+sdb.TextSize {

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
		// For any kind of JMP ( but not call ), add a symbol for the next
		// instruction, since it needs to become a BBL head
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

func blatBBL(bbl cfg.BBL, sym symlist.SymEntry, sdb *symlist.SymList) {
	te, fe, ae := bbl.Edges()

	if sym.Func { // Function head
		fmt.Printf("\n(0x%x): ", bbl.Symbol.Value)
	}

	fmt.Printf("%v Len: %v Tail: %v Edges: T:0x%x F:0x%x A:0x%x",
		bbl.Symbol.Name,
		len(bbl.Insns),
		len(bbl.Tail),
		te,
		fe,
		ae,
	)

	// This is the part where I miss Ruby ;)
	if len(bbl.CallEdges) > 0 {
		fmt.Printf(" Calls ==> [")
		for addr := range bbl.CallEdges {
			sym, _ := sdb.At(addr)
			fmt.Printf(" %v ", sym.Name)
		}
		fmt.Print("]")
	}
	if te+fe+ae == 0 { // no edges
		fmt.Print(" [terminal]")
	}
	fmt.Print("\n")
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

		log.Println("Linking graph nodes...")
		g.LinkNodes()

		for e := sdb.Front(); e != nil; e = e.Next() {

			sym := e.Value.(symlist.SymEntry)
			if sym.Stub {
				continue
			}

			bbl, ok := g.Graph[uint(sym.Value)]
			if !ok {
				log.Printf("Missing node for sym %v %v", sym.Name, sym.Value)
				continue
			}

			blatBBL(*bbl, sym, sdb)

		}

		if m, ok := sdb.Name("_release_dotlock"); ok {
			log.Printf("Crawling %s", m.Name)
			results := make(chan cfg.BBL)
			go g.CrawlFrom(m, sdb, results)
			for rbbl := range results {
				blatBBL(rbbl, rbbl.Symbol, sdb)
			}
		}

	}

}
