// Command opf serves a web UI for managing an OpenBSD system through its
// own configuration files.
//
// It runs as two processes (see package privsep): a privileged parent
// that owns the configuration, and an unprivileged child, re-executed
// from this binary, that serves HTTP.
package main

import (
	"context"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/dantecatalfamo/OPF/internal/config"
	"github.com/dantecatalfamo/OPF/internal/privsep"
	"github.com/dantecatalfamo/OPF/internal/run"
	"github.com/dantecatalfamo/OPF/internal/web"
)

func main() {
	if privsep.IsChild() {
		serveWeb()
		return
	}

	listen := flag.String("listen", "127.0.0.1:8080", "address to listen on")
	stateDir := flag.String("state", "/var/opf", "directory for staged changes and history")
	root := flag.String("root", "", "prefix for every managed path (for development)")
	dry := flag.Bool("dry", false, "log system commands instead of running them")
	timeout := flag.Duration("confirm-timeout", 60*time.Second, "how long to wait for confirmation before reverting")
	webUser := flag.String("user", "_opf", "unprivileged user for the web process")
	flag.Parse()
	log.SetPrefix("opf: ")

	exe, err := executable()
	if err != nil {
		log.Fatal(err)
	}

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

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	if err := privsep.SandboxParent(store.WritableDirs(), exe); err != nil {
		log.Fatal(err)
	}

	sigCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	log.Printf("listening on http://%s", ln.Addr())
	err = privsep.RunParent(sigCtx, privsep.ParentOptions{
		Store:      store,
		Listener:   ln,
		User:       *webUser,
		Executable: exe,
	})
	if err != nil {
		log.Print(err)
	}

	// Don't leave an unconfirmed commit loaded after OPF stops.
	if store.Pending() != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		if err := store.Revert(ctx); err != nil {
			log.Printf("reverting unconfirmed commit: %v", err)
		} else {
			log.Printf("reverted unconfirmed commit")
		}
		cancel()
	}
	if err != nil {
		os.Exit(1)
	}
}

func serveWeb() {
	log.SetPrefix("opf web: ")
	err := privsep.RunChild(func(m config.Manager, ln net.Listener) error {
		srv, err := web.New(m)
		if err != nil {
			return err
		}
		hs := &http.Server{
			Handler:           http.NewCrossOriginProtection().Handler(srv),
			ReadHeaderTimeout: 10 * time.Second,
		}
		return hs.Serve(ln)
	})
	log.Fatal(err)
}

func executable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(exe)
}
