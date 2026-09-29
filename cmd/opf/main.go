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

	"github.com/dantecatalfamo/OPF/internal/appliance"
	"github.com/dantecatalfamo/OPF/internal/config"
	"github.com/dantecatalfamo/OPF/internal/leases"
	"github.com/dantecatalfamo/OPF/internal/pf"
	"github.com/dantecatalfamo/OPF/internal/privsep"
	"github.com/dantecatalfamo/OPF/internal/run"
	"github.com/dantecatalfamo/OPF/internal/web"
	"github.com/dantecatalfamo/OPF/ui"
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
	mock := flag.Bool("mock", false, "serve the web UI's API from a sample model in a scratch directory, logging commands instead of running them (for frontend development)")
	seed := flag.String("seed", "ui/src/model/sample-model.json", "model the mock server starts from")
	flag.Parse()
	log.SetPrefix("opf: ")

	if *mock {
		addr := "127.0.0.1:18080" // where the UI's dev server proxies /api
		flag.Visit(func(f *flag.Flag) {
			if f.Name == "listen" {
				addr = *listen
			}
		})
		log.Fatal(runMock(addr, *seed, *timeout))
	}

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
	api, err := appliance.New(store)
	if err != nil {
		log.Fatal(err)
	}
	leasesFile := filepath.Join(*root, leases.Path)
	if err := privsep.SandboxParent(store.WritableDirs(), []string{leasesFile}, exe); err != nil {
		log.Fatal(err)
	}

	sigCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// DHCP clients' names in DNS, when the model asks for them.
	var resolver leases.Resolver = leases.Unbound{Runner: runner, Config: "/var/unbound/etc/unbound.conf"}
	if *dry {
		resolver = &leases.Memory{Log: log.Default()}
	}
	watcher := &leases.Watcher{File: leasesFile, Model: liveModel(api), Resolver: resolver, Log: log.Default()}
	api.OnChange(watcher.Kick)
	api.SetLeaseWatcher(watcher)
	go watcher.Run(sigCtx)

	log.Printf("listening on http://%s", ln.Addr())
	err = privsep.RunParent(sigCtx, privsep.ParentOptions{
		API:        api,
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
	err := privsep.RunChild(func(api appliance.API, ln net.Listener) error {
		hs := &http.Server{
			Handler:           http.NewCrossOriginProtection().Handler(web.New(api, ui.Files())),
			ReadHeaderTimeout: 10 * time.Second,
		}
		return hs.Serve(ln)
	})
	log.Fatal(err)
}

func liveModel(api *appliance.Manager) func() (*pf.Model, error) {
	return func() (*pf.Model, error) {
		c, err := api.Live()
		if err != nil {
			return nil, err
		}
		return c.Model, nil
	}
}

func executable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(exe)
}
