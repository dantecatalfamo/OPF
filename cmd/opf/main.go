// Command opf serves a web UI for managing an OpenBSD system through its
// own configuration files.
//
// It runs as two processes (see package privsep): a privileged parent
// that owns the configuration, and an unprivileged child, re-executed
// from this binary, that serves HTTP.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/dantecatalfamo/OPF/internal/appliance"
	"github.com/dantecatalfamo/OPF/internal/auth"
	"github.com/dantecatalfamo/OPF/internal/config"
	"github.com/dantecatalfamo/OPF/internal/leases"
	"github.com/dantecatalfamo/OPF/internal/pf"
	"github.com/dantecatalfamo/OPF/internal/privsep"
	"github.com/dantecatalfamo/OPF/internal/run"
	"github.com/dantecatalfamo/OPF/internal/tlscert"
	"github.com/dantecatalfamo/OPF/internal/web"
	"github.com/dantecatalfamo/OPF/internal/webhook"
	"github.com/dantecatalfamo/OPF/ui"
)

func main() {
	if os.Getenv(appliance.SenderEnv) == "1" {
		sendWebhook()
		return
	}
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
	tlsMode := flag.String("tls", "auto", "serve HTTPS: on, off (only on a loopback address, for ssh -L), or auto (on unless the address is loopback)")
	mock := flag.Bool("mock", false, "serve the web UI's API from a sample model in a scratch directory, logging commands instead of running them (for frontend development)")
	seed := flag.String("seed", "ui/src/model/sample-model.json", "model the mock server starts from")
	mockLogin := flag.String("mock-login", "", "with -mock, require signing in, as name:password (an admin); without it the mock has no accounts")
	flag.Parse()
	log.SetPrefix("opf: ")

	if *mock {
		addr := "127.0.0.1:18080" // where the UI's dev server proxies /api
		flag.Visit(func(f *flag.Flag) {
			if f.Name == "listen" {
				addr = *listen
			}
		})
		log.Fatal(runMock(addr, *seed, *timeout, *mockLogin))
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

	useTLS, err := wantTLS(*tlsMode, *listen)
	if err != nil {
		log.Fatal(err)
	}
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

	// Who can sign in: the system's accounts in OPF's groups, which are
	// made on first start.
	sessions := auth.NewSessions(auth.SystemBSDAuth)
	audit := auditor(api, *dry)
	sessions.Log = func(e auth.Event) { recordSignIn(audit, e) }
	admin := &auth.Admin{Passwd: "/etc/master.passwd", Group: "/etc/group", Created: filepath.Join(*stateDir, "accounts.json"),
		W: auth.System{Runner: runner, Feeder: run.Exec{}}}
	gctx, gcancel := context.WithTimeout(context.Background(), time.Minute)
	if err := admin.EnsureGroups(gctx); err != nil {
		log.Printf("OPF's groups: %v", err)
	}
	gcancel()
	var tlsPair *privsep.TLSPair
	if useTLS {
		tlsPair, err = certificate(api, *stateDir, *listen)
		if err != nil {
			log.Fatal(err)
		}
	}
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
	// So does the webhook sender, this binary started again.
	api.Sender, api.Exe = run.Exec{Credential: cred}, exe
	// Unveil skips a directory that doesn't exist, and then nothing can
	// be created in it; make the ones OPF writes before hiding the rest.
	for _, d := range store.WritableDirs() {
		if err := os.MkdirAll(d, 0755); err != nil {
			log.Fatal(err)
		}
	}
	// Checking a password reads the account files; the login helpers
	// are run (SandboxParent's exec directories).
	readable := []string{leasesFile, "/etc/master.passwd", "/etc/group", "/etc/login.conf"}
	if err := privsep.SandboxParent(store.WritableDirs(), readable, exe); err != nil {
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
	go api.RunCollector(sigCtx)              // the graphs' history
	go api.RunUpdateChecker(sigCtx)          // security patches, every couple of hours
	go api.RunWebhooks(sigCtx)               // events to webhooks

	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	log.Printf("listening on %s://%s", scheme, ln.Addr())
	err = privsep.RunParent(sigCtx, privsep.ParentOptions{
		API:        api,
		Accounts:   privsep.ServeOptions{Sessions: sessions, Admin: admin, Audit: audit, TLS: tlsPair},
		Listener:   lf,
		Credential: cred,
		Executable: exe,
	})
	if err != nil {
		log.Print(err)
	}

	if err := api.SaveMetrics(); err != nil {
		log.Printf("saving the graphs: %v", err)
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

// sendWebhook is the webhook sender: started by the parent as the
// unprivileged user, it reads one delivery on stdin, sends it, and
// says how that went on stdout, exiting 1 if it failed.
func sendWebhook() {
	if err := privsep.SandboxSender(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	var req webhook.Request
	if err := json.NewDecoder(io.LimitReader(os.Stdin, webhook.MaxRequest)).Decode(&req); err != nil {
		fmt.Println("couldn't read the delivery")
		os.Exit(1)
	}
	if err := webhook.Send(context.Background(), req, time.Now()); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println("delivered")
}

func serveWeb() {
	log.SetPrefix("opf web: ")
	err := privsep.RunChild(func(c *privsep.Client, ln net.Listener) error {
		pair, err := c.TLS()
		if err != nil {
			return err
		}
		srv := web.New(c, ui.Files())
		fingerprint := ""
		if pair != nil {
			cert, err := tls.X509KeyPair(pair.Cert, pair.Key)
			if err != nil {
				return err
			}
			ln = tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
			fingerprint = tlscert.Fingerprint(pair.Cert)
		}
		srv.RequireAuth(web.AuthOf(c.Login, c.WithToken), fingerprint)
		hs := &http.Server{
			Handler:           http.NewCrossOriginProtection().Handler(srv),
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

// wantTLS decides whether to serve HTTPS. Passwords cross the
// connection, so plain HTTP is only allowed on a loopback address,
// reached with ssh -L.
func wantTLS(mode, listen string) (bool, error) {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return false, err
	}
	ip := net.ParseIP(host)
	loopback := host == "localhost" || ip != nil && ip.IsLoopback()
	switch mode {
	case "on":
		return true, nil
	case "auto":
		return !loopback, nil
	case "off":
		if !loopback {
			return false, fmt.Errorf("-tls off is only allowed on a loopback address, not %s: passwords would cross the network in the clear", listen)
		}
		return false, nil
	}
	return false, fmt.Errorf("-tls is on, off or auto, not %q", mode)
}

// certificate is the web interface's, made self-signed on first start
// for the firewall's names and the address listened on.
func certificate(api *appliance.Manager, stateDir, listen string) (*privsep.TLSPair, error) {
	hosts := []string{}
	if c, err := api.Live(); err == nil && c.Model != nil {
		s := c.Model.System
		if s.Hostname != "" && s.Domain != "" {
			hosts = append(hosts, s.Hostname+"."+s.Domain)
		}
		if s.Hostname != "" {
			hosts = append(hosts, s.Hostname)
		}
		for _, i := range c.Model.Interfaces {
			if i.Role != pf.RoleWAN && i.IPv4.Address != "" {
				hosts = append(hosts, i.IPv4.Address)
			}
		}
	}
	if host, _, err := net.SplitHostPort(listen); err == nil && host != "" && net.ParseIP(host) != nil && !net.ParseIP(host).IsUnspecified() {
		hosts = append(hosts, host)
	}
	hosts = append(hosts, "localhost", "127.0.0.1")
	seen := map[string]bool{}
	hosts = slices.DeleteFunc(hosts, func(h string) bool {
		dup := seen[h]
		seen[h] = true
		return dup
	})
	cert, key, made, err := tlscert.Ensure(filepath.Join(stateDir, "tls"), hosts, time.Now())
	if err != nil {
		return nil, fmt.Errorf("the web interface's certificate: %w", err)
	}
	if made {
		log.Printf("made a self-signed certificate for %s", strings.Join(hosts, ", "))
	}
	// To compare with what the browser shows before trusting it.
	log.Printf("certificate SHA-256 %s", tlscert.Fingerprint(cert))
	return &privsep.TLSPair{Cert: cert, Key: key}, nil
}

// auditor records sign-ins and changes to accounts: in OPF's log, the
// event log, and syslog's authlog through logger(1), which -dry only
// logs.
func auditor(api *appliance.Manager, dry bool) func(warning bool, subject, msg string) {
	return func(warning bool, subject, msg string) {
		log.Print(msg)
		api.RecordEvent(appliance.Event{Kind: appliance.EventLogin, Warning: warning, Subject: subject, Message: msg})
		line := strings.Map(func(r rune) rune {
			if r < 0x20 || r == 0x7f {
				return '?'
			}
			return r
		}, msg)
		if dry {
			log.Printf("dry-run: logger -p auth.notice -t opf %q", line)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if out, err := (run.Exec{}).RunInput(ctx, []byte(line+"\n"), []string{}, "logger", "-p", "auth.notice", "-t", "opf"); err != nil {
			log.Printf("logger: %v: %s", err, strings.TrimSpace(string(out)))
		}
	}
}

// recordSignIn records a sign-in, refusal or sign-out.
func recordSignIn(audit func(warning bool, subject, msg string), e auth.Event) {
	switch e.Kind {
	case "login":
		audit(false, e.User, fmt.Sprintf("%s %s, from %s", e.User, e.Message, e.Source))
	case "refused":
		audit(true, e.User, fmt.Sprintf("Refused signing in as %q from %s: %s", e.User, e.Source, e.Message))
	case "logout":
		audit(false, e.User, fmt.Sprintf("%s signed out", e.User))
	default:
		audit(false, e.User, fmt.Sprintf("%s's %s", e.User, e.Message))
	}
}
