package webapp

import (
	"github.com/bnagy/gootool/cfg"
	"github.com/bnagy/gootool/graph"
	"net/http"
	"strings"
)

func Serve(g *cfg.CFG) error {

	if pageBytes, err := graph.RenderFuncGraph(g); err == nil {

		// Render the full function graph on /
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "image/svg+xml")
			w.Write(pageBytes)
		})

		// Clicks on Func nodes link to /func/<symbol>
		http.HandleFunc("/func/", func(w http.ResponseWriter, r *http.Request) {
			if m, ok := g.SDB.Name(r.RequestURI[strings.LastIndex(r.RequestURI, "/")+1:]); ok {
				w.Header().Set("Content-Type", "image/svg+xml")
				page, _ := graph.RenderCFG(m, g)
				w.Write(page)
			}
		})

		// Serve the pug. The pug must be served. SERVE THE PUG.
		http.HandleFunc("/pug.jpg", func(w http.ResponseWriter, r *http.Request) {
			w.Write(graph.Pug)
		})

		return http.ListenAndServe(":8080", nil)

	} else {
		return err
	}
}
