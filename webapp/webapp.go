package webapp

import (
	"github.com/bnagy/gootool/cfg"
	"github.com/bnagy/gootool/graph"
	"net/http"
	"strings"
)

// Serve the webapp for a given CFG. Initial page is a function graph,
// clicking non-stub nodes will link to a BBL-based disassembly of that
// function.
func Serve(cfg *cfg.CFG) error {

	pageBytes, err := graph.RenderFuncGraph(cfg)
	if err == nil {

		// Render the full function graph on /
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "image/svg+xml")
			w.Write(pageBytes)
		})

		// Clicks on Func nodes link to /func/<symbol>
		http.HandleFunc("/func/", func(w http.ResponseWriter, r *http.Request) {
			if m, ok := cfg.SDB.Name(r.RequestURI[strings.LastIndex(r.RequestURI, "/")+1:]); ok {
				w.Header().Set("Content-Type", "image/svg+xml")
				page, _ := graph.RenderCFG(m, cfg)
				w.Write(page)
			}
		})

		// Serve the pug. The pug must be served. SERVE THE PUG.
		http.HandleFunc("/pug.jpg", func(w http.ResponseWriter, r *http.Request) {
			w.Write(graph.Pug)
		})

		return http.ListenAndServe(":8080", nil)

	}
	return err
}
