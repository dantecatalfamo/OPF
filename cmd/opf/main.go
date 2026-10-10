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
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
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
	mockMachine := flag.String("mock-machine", "", "with -mock -readonly, a directory of a machine's own files (laid out as on it) to monitor and take over, in place of the seed's")
	mockLogin := flag.String("mock-login", "", "with -mock, require signing in, as name:password (an admin); without it the mock has no accounts")
	readOnly := flag.Bool("readonly", false, "only monitor this machine: change nothing on it, and refuse every change through the web UI (kept on in the state directory until the machine is taken over)")
	watchdog := flag.String("watchdog", "", "run as the watchdog of the commit with this id (OPF starts these itself)")
	flag.Parse()
	log.SetPrefix("opf: ")

	if *mock {
		addr := "127.0.0.1:18080" // where the UI's dev server proxies /api
		flag.Visit(func(f *flag.Flag) {
			if f.Name == "listen" {
				addr = *listen
			}
		})
		log.Fatal(runMock(addr, *seed, *timeout, *mockLogin, *readOnly, *mockMachine))
	}

	var runner run.Runner = run.Exec{}
	if *dry {
		runner = run.Dry{Log: log.Default()}
	}
	var checkRunner run.Runner // the store's Runner
	if *dry && *checks {
		checkRunner = run.Exec{}
	}
	storeOptions := config.Options{
		Root:           *root,
		StateDir:       *stateDir,
		Files:          config.DefaultFiles(),
		Runner:         runner,
		CheckRunner:    checkRunner,
		ConfirmTimeout: *timeout,
	}
	if *watchdog != "" {
		runWatchdog(*watchdog, storeOptions)
		return
	}

	exe, err := executable()
	if err != nil {
		log.Fatal(err)
	}
	// Held until OPF exits (see config.Lock). A watchdog reverting a
	// commit holds it for a moment; another OPF holds it for good.
	lock, err := config.Lock(*stateDir, 0)
	if errors.Is(err, config.ErrLocked) {
		log.Printf("waiting for %s's lock: another OPF is running, or a commit's watchdog is reverting", *stateDir)
		lock, err = config.Lock(*stateDir, 2*time.Minute)
	}
	if err != nil {
		log.Fatal(err)
	}
	defer lock.Close()

	store, err := config.New(storeOptions)
	if err != nil {
		log.Fatal(err)
	}
	ro, err := readOnlyMode(*stateDir, *readOnly)
	if err != nil {
		log.Fatal(err)
	}
	// A watchdog for each commit that waits, in case OPF dies first.
	var watchdogArgs []string
	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "state", "root", "dry", "checks":
			watchdogArgs = append(watchdogArgs, "-"+f.Name+"="+f.Value.String())
		}
	})
	store.OnPending(func(e config.Entry) { startWatchdog(exe, e.ID, watchdogArgs) })
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
	if appliance.TakeOverPending(*stateDir) {
		ro = finishTakeOver(api, runner, *stateDir, ro, *readOnly)
	}
	api.SetReadOnly(ro) // and read-only, nothing runs at all
	if ro {
		log.Printf("read-only: monitoring this machine, changing nothing on it (%s)", filepath.Join(*stateDir, appliance.ReadOnlyMarker))
	}
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
	if ro {
		// Its groups are the one thing OPF makes, so people can sign in;
		// accounts are then changed by hand, not by OPF.
		admin.W = auth.System{Runner: run.Refuse{Log: log.Default()}, Feeder: run.Exec{}}
	}
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
	// be created in it; make the ones OPF writes before hiding the rest
	// (read-only, only its state directory).
	for _, d := range store.WritableDirs() {
		if ro && filepath.Clean(d) != filepath.Clean(*stateDir) {
			continue
		}
		if err := os.MkdirAll(d, 0755); err != nil {
			log.Fatal(err)
		}
	}
	// Checking a password reads the account files; the login helpers
	// are run (SandboxParent's exec directories).
	readable := []string{leasesFile, "/etc/master.passwd", "/etc/group", "/etc/login.conf"}
	writable := store.WritableDirs()
	if ro {
		// Read-only, OPF may write its state directory and nothing else:
		// the rest of what it would manage it can only read. (Unveiling
		// the state directory "r" too would take its "rwc" away: the
		// last unveil of a path wins.)
		for _, d := range writable {
			if filepath.Clean(d) != filepath.Clean(*stateDir) {
				readable = append(readable, d)
			}
		}
		writable = []string{*stateDir}
	}
	if err := privsep.SandboxParent(writable, readable, exe); err != nil {
		log.Fatal(err)
	}

	sigCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	// Taking the machine over from read-only mode stops OPF, which then
	// starts again without -readonly, out of its sandbox
	// (appliance.TakeOver, restartWithRC).
	runCtx, stopRun := context.WithCancel(sigCtx)
	defer stopRun()
	takingOver := make(chan struct{})
	if ro {
		api.OnTakeOver(func() {
			time.Sleep(time.Second) // for the answer to reach the browser
			close(takingOver)
			stopRun()
		})
	}

	// DHCP clients' names in DNS, when the model asks for them.
	var resolver leases.Resolver = leases.Unbound{Runner: runner, Config: "/var/unbound/etc/unbound.conf"}
	if *dry || ro {
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
	err = privsep.RunParent(runCtx, privsep.ParentOptions{
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
		if err := store.RevertStopping(ctx); err != nil {
			log.Printf("reverting unconfirmed commit: %v", err)
		} else {
			log.Printf("reverted unconfirmed commit")
		}
		cancel()
	}
	select {
	case <-takingOver:
		if !*dry {
			restartWithRC(runner)
		}
		startAgain(exe)
	default:
	}
	if err != nil {
		os.Exit(1)
	}
}

// restartWithRC hands the restart out of read-only mode to rc when rc
// started OPF. rc.subr finds a running daemon by the command line it
// saved in /var/run/rc.d/opf when it started it, with -readonly: OPF
// starting itself again without it would leave rc unable to check,
// stop or restart it. So -readonly comes out of opf_flags first and a
// detached rcctl restart stops this OPF and starts the managed one,
// which takes the state directory's lock once this one is gone. It
// returns only if rc didn't start OPF, or the restart didn't stop it,
// for OPF to start again itself.
func restartWithRC(runner run.Runner) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, err := runner.Run(ctx, "rcctl", "check", "opf"); err != nil {
		return // rc didn't start this OPF
	}
	if err := dropReadOnlyFlag(ctx, runner); err != nil {
		log.Printf("taking over: %v; starting again in place", err)
		return
	}
	cmd := exec.Command("rcctl", "restart", "opf")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	// rc stops OPF with SIGTERM, which now ends it.
	signal.Reset(syscall.SIGINT, syscall.SIGTERM)
	if err := cmd.Start(); err != nil {
		log.Printf("taking over: rcctl restart opf: %v; starting again in place", err)
		return
	}
	log.Printf("taking over: rcctl restart opf, to start again without -readonly")
	// rc.subr waits daemon_timeout (30 s) before it kills.
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(2 * time.Minute):
	}
	// Still here: rc didn't stop this OPF. If it started the managed one
	// anyway (its command line has no -readonly, so it's what rc
	// checks now), that one waits for the lock: leave it to it.
	cctx, ccancel := context.WithTimeout(context.Background(), time.Minute)
	defer ccancel()
	if _, err := runner.Run(cctx, "rcctl", "check", "opf"); err == nil {
		log.Printf("taking over: rc started OPF again; this one stops")
		os.Exit(0)
	}
	log.Printf("taking over: rcctl restart opf didn't restart OPF; starting again in place")
}

// startAgain execs OPF again, without -readonly, to finish taking the
// machine over (finishTakeOver). An exec drops the sandbox, and every
// descriptor (the listener, the state directory's lock) is close-on-exec.
func startAgain(exe string) {
	args := append([]string{os.Args[0]}, withoutReadOnly(os.Args[1:])...)
	log.Printf("starting again out of read-only mode: %s", strings.Join(args, " "))
	err := syscall.Exec(exe, args, os.Environ())
	log.Fatalf("starting again: %v", err)
}

// withoutReadOnly is a command line without -readonly.
func withoutReadOnly(args []string) []string {
	var out []string
	for _, a := range args {
		name, val, hasVal := strings.Cut(strings.TrimLeft(a, "-"), "=")
		if strings.HasPrefix(a, "-") && name == "readonly" {
			if on, err := strconv.ParseBool(val); !hasVal || (err == nil && on) {
				continue
			}
		}
		out = append(out, a)
	}
	return out
}

// finishTakeOver finishes taking the machine over after OPF started again
// out of read-only mode (startAgain): -readonly comes out of
// rc.conf.local's opf_flags first, so rc doesn't start OPF read-only
// again; then the import is staged; and only then does the read-only
// marker go. Anything failing leaves the marker, and OPF read-only. It
// returns whether OPF is read-only.
func finishTakeOver(api *appliance.Manager, runner run.Runner, stateDir string, ro, flagged bool) bool {
	discard := func() { os.Remove(filepath.Join(stateDir, appliance.TakeOverFile)) }
	switch {
	case !ro:
		// Not read-only: a leftover, which the managed OPF doesn't need.
		discard()
		return false
	case flagged:
		// Started with -readonly again by hand: that's the admin's word.
		log.Printf("taking over: started with -readonly, so the machine isn't taken over")
		discard()
		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := dropReadOnlyFlag(ctx, runner); err != nil {
		log.Printf("taking over: %v; still read-only", err)
		discard()
		return true
	}
	if err := api.ResumeTakeOver(); err != nil {
		log.Printf("taking over: staging the machine's configuration: %v; still read-only", err)
		return true
	}
	if err := os.Remove(filepath.Join(stateDir, appliance.ReadOnlyMarker)); err != nil {
		log.Printf("taking over: %v; still read-only", err)
		return true
	}
	log.Printf("taken over: no longer read-only; the machine's configuration is staged, to review and commit")
	return false
}

// dropReadOnlyFlag takes -readonly out of opf_flags in rc.conf.local,
// with rcctl. OPF started some other way has none there.
func dropReadOnlyFlag(ctx context.Context, runner run.Runner) error {
	out, err := runner.Run(ctx, "rcctl", "get", "opf", "flags")
	if err != nil {
		return nil // not rc's
	}
	flags := strings.Fields(strings.TrimSpace(string(out)))
	kept := withoutReadOnly(flags)
	if len(kept) == len(flags) {
		return nil
	}
	if _, err := runner.Run(ctx, append([]string{"rcctl", "set", "opf", "flags"}, kept...)...); err != nil {
		return fmt.Errorf("taking -readonly out of opf_flags (rcctl set opf flags): %w", err)
	}
	log.Printf("taking over: opf_flags is now %q", strings.Join(kept, " "))
	return nil
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

// startWatchdog starts the watchdog of a commit waiting for confirmation:
// this binary again, as root, in a session of its own so that whatever
// takes OPF down doesn't take it too. Its command line differs from
// OPF's, so rc.d's pexp doesn't match it. Its output goes where OPF's
// does.
func startWatchdog(exe, id string, args []string) {
	cmd := exec.Command(exe, append([]string{"-watchdog", id}, args...)...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Start(); err != nil {
		log.Printf("starting the watchdog of commit %s: %v", id, err)
		return
	}
	go cmd.Wait()
}

// runWatchdog is a commit's watchdog (config.Store.Watch): it reverts
// the commit if OPF is gone when it should have been confirmed.
func runWatchdog(id string, opts config.Options) {
	log.SetPrefix("opf watchdog: ")
	store, err := config.New(opts)
	if err != nil {
		log.Fatal(err)
	}
	if err := privsep.SandboxWatchdog(store.WritableDirs()); err != nil {
		log.Fatal(err)
	}
	msg, err := store.Watch(context.Background(), id, time.Sleep)
	if err != nil {
		log.Fatalf("commit %s: %v", id, err)
	}
	log.Print(msg)
}

// readOnlyMode says whether OPF runs read-only: while the state
// directory has the marker. -readonly makes it; taking the machine over
// takes it away, so starting later without the flag doesn't hand OPF
// control.
func readOnlyMode(stateDir string, flagged bool) (bool, error) {
	marker := filepath.Join(stateDir, appliance.ReadOnlyMarker)
	if flagged {
		if err := os.MkdirAll(stateDir, 0700); err != nil {
			return false, err
		}
		if _, err := os.Stat(marker); errors.Is(err, os.ErrNotExist) {
			msg := "OPF only monitors this machine (opf -readonly) and changes nothing on it. Taking it over removes this file.\n"
			if err := os.WriteFile(marker, []byte(msg), 0600); err != nil {
				return false, err
			}
		}
	}
	if _, err := os.Stat(marker); err == nil {
		return true, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	return false, nil
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
