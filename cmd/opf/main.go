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
	checks := flag.Bool("checks", false, "with -dry, still run the validators (pfctl -n, dhcpd -n, ...), which change nothing")
	dry := flag.Bool("dry", false, "log commands that change the system instead of running them (state is still read, and diagnostic tools still run)")
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
	var checkRunner run.Runner // the store's Runner
	if *dry && *checks {
		checkRunner = run.Exec{}
	}
	store, err := config.New(config.Options{
		Root:           *root,
		StateDir:       *stateDir,
		Files:          config.DefaultFiles(),
		Runner:         runner,
		CheckRunner:    checkRunner,
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
	api.Actions = runner // dry-run with -dry
	leasesFile := filepath.Join(*root, leases.Path)
	// Before the sandbox: the lookup reads /etc/passwd, and making the
	// listener's file needs "inet", which the parent doesn't pledge.
	cred, err := privsep.Credential(*webUser)
	if err != nil {
		log.Fatal(err)
	}
	lf, err := privsep.ListenerFile(ln)
	if err != nil {
		log.Fatal(err)
	}
	// Downloads handle what a server on the internet sends: run them as
	// the unprivileged user too (a dedicated one is in TODO).
	api.Fetcher = run.Exec{Credential: cred}
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
	go api.RunRefresher(sigCtx, time.Minute) // downloaded lists, as they fall due

	log.Printf("listening on http://%s", ln.Addr())
	err = privsep.RunParent(sigCtx, privsep.ParentOptions{
		API:        api,
		Listener:   lf,
		Credential: cred,
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
