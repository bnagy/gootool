package graph

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/bnagy/gootool/cfg"
	"github.com/bnagy/gootool/formatters"
	"github.com/bnagy/gootool/symlist"
	"os/exec"
	"sort"
	"strings"
)

func render(in, out *bytes.Buffer) error {
	cmd := exec.Command("dot", "-Tsvg")
	cmd.Stdin = in
	cmd.Stdout = out
	if err := cmd.Run(); err != nil {
		return err
	}

	p := out.Bytes()
	if i := bytes.Index(p, []byte("<svg")); i >= 0 {
		out.Reset()
		out.Write(p[i:])
		return nil
	}
	return errors.New("<svg not found")

}

// RenderCFG shells out to dot to render the BBL graph
func RenderCFG(sym symlist.SymEntry, g *cfg.CFG) ([]byte, error) {

	var in, out, tmp bytes.Buffer

	fmt.Fprintf(&in, "digraph %s { \nsplines=\"ortho\"\n", sym.Name)

	var nodes []cfg.Node
	for node := range g.CrawlFrom(sym) {
		nodes = append(nodes, node)
	}
	sort.Sort(cfg.ByAddr(nodes))

	for _, node := range nodes {

		// Dump all the nodes first, that seems to determine the rankings /
		// Ypos of the boxes
		var label []string
		for _, insn := range node.Insns {
			tmp.Reset()
			formatters.DumpInsn(insn, g.SDB, &tmp)
			label = append(label, tmp.String())
		}

		fmt.Fprintf(
			&in,
			// \l is dot language for left justify
			" \"0x%x\" [shape=box,fontname=menlo,label=\"%s \\l\"];\n",
			node.Addr,
			strings.Join(label, "\\l"),
		)

	}

	for _, node := range nodes {

		// Now the edges.
		for _, edge := range node.Edges {
			fmt.Fprintf(&in, " \"0x%x\" -> \"0x%x\"", node.Addr, edge.Target.Addr)
			switch edge.Type {
			case cfg.TrueEdge:
				fmt.Fprintf(&in, "[color=green];\n")
			case cfg.FalseEdge:
				fmt.Fprintf(&in, "[color=red];\n")
			case cfg.AlwaysEdge:
				fmt.Fprintf(&in, "[color=blue];\n")
			}
		}

	}
	in.WriteString("}")

	err := render(&in, &out)
	return out.Bytes(), err
}

// RenderFuncGraph shells out to dot to render the initial function graph
func RenderFuncGraph(g *cfg.CFG) ([]byte, error) {

	var in, out bytes.Buffer

	fmt.Fprintf(&in, "digraph functions { \nsplines=\"ortho\"\n")

	for e := g.SDB.Front(); e != nil; e = e.Next() {

		sym := e.Value.(symlist.SymEntry)
		if sym.Type == symlist.BBL { //  Only graph Stubs or Funcs
			continue
		}

		var calls []string
		if bbl, ok := g.Graph[uint(sym.Value)]; ok {
			for call := range bbl.Calls {
				if target, ok := g.SDB.At(call); ok {
					calls = append(calls, target.Name)
				}
			}
		}

		switch sym.Type {
		default:
			panic("Unknown sym type in function render")
		case symlist.Func:
			// Dump all the nodes first, that seems to determine the rankings /
			// Ypos of the boxes
			fmt.Fprintf(
				&in,
				" \"%s\" [shape=box,fillcolor=lightblue,style=filled,fontname=menlo,label=\"%s\",tooltip =\"%s calls -> %s\",URL=\"%s\"];\n",
				sym.Name,
				sym.Name,
				sym.Name,
				strings.Join(calls, " "),
				fmt.Sprintf("/func/%s", sym.Name),
			)
		case symlist.Stub:
			fmt.Fprintf(
				&in,
				// leet newline technique to better align the label in the furry pug belly
				" \"%s\" [shape=none,image=\"pug.jpg\",fontname=menlo,label=\"   %s\n\n\"];\n",
				sym.Name,
				sym.Name,
			)
		}

	}

	for e := g.SDB.Front(); e != nil; e = e.Next() {

		sym := e.Value.(symlist.SymEntry)
		if sym.Type == symlist.BBL {
			continue
		}

		bbl, ok := g.Graph[uint(sym.Value)]
		if !ok {
			continue
		}

		for call := range bbl.Calls {
			if destSym, ok := g.SDB.At(call); ok {
				fmt.Fprintf(
					&in,
					"\"%s\" ->\"%s\";\n",
					sym.Name,
					destSym.Name,
				)
			}
		}

	}
	in.WriteString("}")

	err := render(&in, &out)
	return out.Bytes(), err
}
