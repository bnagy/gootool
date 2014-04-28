package main

import (
	"bytes"
	"debug/macho"
	"flag"
	"fmt"
	cs "github.com/bnagy/gapstone"
	"github.com/bnagy/gootool/cfg"
	"github.com/bnagy/gootool/formatters"
	"github.com/bnagy/gootool/symlist"
	"log"
	"os"
	"path"
)

const N_SECT = uint8(0x0e)

var outbuf = new(bytes.Buffer)

type disasmCB func(insn cs.Instruction) error

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
			callback(insn)
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
		disasm(&engine, sdb.SymboliseBBLs, textBytes, sdb)

		log.Println("Building graph...")
		g := cfg.NewCFG(sdb)
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

			outbuf.Reset()
			g.BlatBBL(bbl, outbuf)
			fmt.Print(outbuf.String())
		}

		if m, ok := sdb.Name("_needfree"); ok {
			log.Printf("Crawling %s", m.Name)
			funcs := make(map[string]bool)
			results := make(chan cfg.BBL)
			go g.CrawlFrom(m, results)
			for bbl := range results {

				outbuf.Reset()
				g.BlatBBL(&bbl, outbuf)
				fmt.Print(outbuf.String())

				for _, insn := range bbl.Insns {
					outbuf.Reset()
					formatters.DumpInsn(insn, sdb, outbuf)
					fmt.Printf("\t%s\n", outbuf.String())
				}

				for addr := range bbl.Calls {
					sym, ok := sdb.At(addr)
					if ok {
						funcs[sym.Name] = true
					}
				}
			}
			fmt.Printf("\nALL %s calls => [", m.Name)
			for fn := range funcs {
				fmt.Printf(" %v ", fn)
			}
			fmt.Printf(" ]\n")
		}

	}

}
