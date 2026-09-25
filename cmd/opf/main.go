// Command opf serves a web UI for managing an OpenBSD system through its
// own configuration files.
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"time"

	"github.com/dantecatalfamo/OPF/internal/config"
	"github.com/dantecatalfamo/OPF/internal/run"
	"github.com/dantecatalfamo/OPF/internal/web"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8080", "address to listen on")
	stateDir := flag.String("state", "/var/opf", "directory for staged changes and history")
	root := flag.String("root", "", "prefix for every managed path (for development)")
	dry := flag.Bool("dry", false, "log system commands instead of running them")
	timeout := flag.Duration("confirm-timeout", 60*time.Second, "how long to wait for confirmation before reverting")
	flag.Parse()

	var runner run.Runner = run.Exec{}
	if *dry {
		runner = run.Dry{Log: log.Default()}
	}

	store, err := config.New(config.Options{
		Root:           *root,
		StateDir:       *stateDir,
		Files:          config.DefaultFiles(),
		Runner:         runner,
		ConfirmTimeout: *timeout,
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	if err := store.Recover(ctx); err != nil {
		log.Printf("recovering unfinished commits: %v", err)
	}
	cancel()

	srv, err := web.New(store)
	if err != nil {
		log.Fatal(err)
	}
	handler := http.NewCrossOriginProtection().Handler(srv)

	log.Printf("listening on http://%s", *listen)
	log.Fatal(http.ListenAndServe(*listen, handler))
}
