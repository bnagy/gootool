package main

import (
	"bytes"
	"debug/macho"
	"flag"
	"fmt"
	cs "github.com/bnagy/gapstone"
	"github.com/bnagy/gootool/cfg"
	// "github.com/bnagy/gootool/formatters"
	"github.com/bnagy/gootool/graph"
	"github.com/bnagy/gootool/symlist"
	"log"
	"net/http"
	"os"
	"path"
	"strings"
)

const N_SECT = uint8(0x0e)

var outbuf = new(bytes.Buffer)

type disasmCB func(insn cs.Instruction) error

func disasm(engine *cs.Engine, callback disasmCB, code []byte, sdb *symlist.SymList) {

	base := sdb.TextBase
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

		if len(insns) > 0 {
			cursor = uint64(insns[len(insns)-1].Address) - base
		}

		for _, insn := range insns {
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

		// for e := sdb.Front(); e != nil; e = e.Next() {

		// 	sym := e.Value.(symlist.SymEntry)
		// 	if sym.IsStub() {
		// 		continue
		// 	}

		// 	bbl, ok := g.Graph[uint(sym.Value)]
		// 	if !ok {
		// 		log.Printf("Missing node for sym %v %v", sym.Name, sym.Value)
		// 		continue
		// 	}

		// 	outbuf.Reset()
		// 	formatters.DumpBBL(bbl, sdb, outbuf)
		// 	fmt.Print(outbuf.String())
		// 	for _, insn := range bbl.Insns {
		// 		outbuf.Reset()
		// 		formatters.DumpInsn(insn, sdb, outbuf)
		// 		fmt.Printf("\t%s\n", outbuf.String())
		// 	}
		// }

		pageBytes, err := graph.RenderFuncGraph(g)
		if err == nil {

			http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "image/svg+xml")
				w.Write(pageBytes)
			})

			http.HandleFunc("/func/", func(w http.ResponseWriter, r *http.Request) {
				if m, ok := g.SDB.Name(r.RequestURI[strings.LastIndex(r.RequestURI, "/")+1:]); ok {
					w.Header().Set("Content-Type", "image/svg+xml")
					page, _ := graph.RenderGraph(m, g)
					w.Write(page)
				}
			})

			log.Fatal(http.ListenAndServe(":8080", nil))

		} else {
			log.Fatal(err)
		}

	}

}
