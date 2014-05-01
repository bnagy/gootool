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

func RenderGraph(sym symlist.SymEntry, g *cfg.CFG, sdb *symlist.SymList) ([]byte, error) {

	var in, out, tmp bytes.Buffer

	fmt.Fprintf(&in, "digraph %s { \nsplines=\"ortho\"\n", sym.Name)
	nodes := make([]cfg.BBL, 0)
	for node := range g.CrawlFrom(sym) {
		nodes = append(nodes, node)
	}
	sort.Sort(cfg.ByAddr(nodes))

	for _, node := range nodes {

		label := make([]string, 0)
		for _, insn := range node.Insns {
			tmp.Reset()
			formatters.DumpInsn(insn, sdb, &tmp)
			label = append(label, tmp.String())
		}

		fmt.Fprintf(
			&in,
			" %d [shape=box,fontname=menlo,label=\"%s\\l\"];\n",
			node.Symbol.Value,
			strings.Join(label, "\\l"),
		)

	}

	for _, node := range nodes {

		for _, edge := range node.Edges {
			fmt.Fprintf(&in, " %d -> %d", node.Symbol.Value, edge.Target.Symbol.Value)
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
	cmd := exec.Command("dot", "-Tsvg")
	cmd.Stdin = &in
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, err
	}

	p := out.Bytes()
	if i := bytes.Index(p, []byte("<svg")); i < 0 {
		return nil, errors.New("<svg not found")
	} else {
		p = p[i:]
	}
	return p, nil
}
