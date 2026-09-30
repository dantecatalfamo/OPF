package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/dantecatalfamo/OPF/internal/appliance"
	"github.com/dantecatalfamo/OPF/internal/config"
	"github.com/dantecatalfamo/OPF/internal/leases"
	"github.com/dantecatalfamo/OPF/internal/pf"
	"github.com/dantecatalfamo/OPF/internal/run"
	"github.com/dantecatalfamo/OPF/internal/web"
	"github.com/dantecatalfamo/OPF/ui"
)

// runMock serves the web UI's API against a throwaway system generated
// from a sample model, for developing the frontend anywhere. It runs as
// one process with the real generators, parser and staging engine, but
// nothing outside a scratch directory is read or written and commands
// are logged instead of run.
func runMock(listen, seedPath string, timeout time.Duration) error {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return err
	}
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return fmt.Errorf("the mock server has no authentication and only listens on loopback, not %s", host)
	}

	seed, err := os.ReadFile(seedPath)
	if err != nil {
		return fmt.Errorf("reading the seed model (run from the repository root, or pass -seed): %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(seed))
	dec.DisallowUnknownFields()
	var model pf.Model
	if err := dec.Decode(&model); err != nil {
		return fmt.Errorf("seed model %s: %w", seedPath, err)
	}
	if errs := pf.Validate(&model); len(errs) > 0 {
		return fmt.Errorf("seed model %s is invalid: %v", seedPath, errs)
	}

	// Addresses the UI's sample status data reports, so generated
	// route-to lines match what the pages show.
	pf.GatewayStatuses["gw_wan"] = pf.GatewayStatus{Address: "203.0.113.1"}

	dir, err := os.MkdirTemp("", "opf-mock-")
	if err != nil {
		return err
	}
	root := filepath.Join(dir, "root")
	// The "live" system is what the seed model generates, written the
	// way a commit would write it, so the first diff shows only the
	// changes made in the UI.
	write := func(path string, data []byte, mode os.FileMode) error {
		p := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			return err
		}
		return os.WriteFile(p, data, mode)
	}
	for _, f := range pf.GenerateFiles(&model) {
		if err := write(f.Path, config.Normalize([]byte(f.Content)), 0644); err != nil {
			return err
		}
	}
	enc, err := appliance.EncodeModel(&model)
	if err != nil {
		return err
	}
	if err := write(config.ModelPath, enc, 0600); err != nil {
		return err
	}
	if err := write(leases.Path, mockLeases(time.Now()), 0644); err != nil {
		return err
	}
	// unbound has run before, so its trust anchor is there; the URL
	// alias's list isn't, so the first commit shows it being downloaded.
	if err := write(pf.RootKeyPath, []byte(". IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D\n"), 0644); err != nil {
		return err
	}

	store, err := config.New(config.Options{
		Root:           root,
		StateDir:       filepath.Join(dir, "state"),
		Files:          config.DefaultFiles(),
		Runner:         run.Dry{Log: log.Default()},
		ConfirmTimeout: timeout,
		FileLog:        log.Default(),
	})
	if err != nil {
		return err
	}
	api, err := appliance.New(store)
	if err != nil {
		return err
	}
	api.Runner = mockSystem{start: time.Now(), model: liveModel(api), pf: &mockPf{}, dnsNames: func() int {
		n := 0
		ls, _ := api.DNSLists()
		for _, l := range ls {
			if l.Enabled {
				n += l.Blocked + l.Allowed
			}
		}
		return n
	}, next: run.Dry{Log: log.Default()}}
	srv := web.New(api, ui.Files())

	watcher := &leases.Watcher{
		File:     filepath.Join(root, leases.Path),
		Model:    liveModel(api),
		Resolver: &leases.Memory{Log: log.Default()},
		Log:      log.Default(),
	}
	api.OnChange(watcher.Kick)
	api.SetLeaseWatcher(watcher)
	go watcher.Run(context.Background())
	go api.RunRefresher(context.Background(), time.Minute)
	if m, err := liveModel(api)(); err == nil {
		seedHistory(api.MetricsStore(), m, time.Now())
	}
	go api.RunCollector(context.Background())

	log.Printf("mock: files in %s (kept on exit); file operations are logged with the real path first", dir)
	log.Printf("mock: API on http://%s; `make mock` also starts the UI, whose dev server proxies to 127.0.0.1:18080", listen)
	hs := &http.Server{
		Addr:              listen,
		Handler:           http.NewCrossOriginProtection().Handler(srv),
		ReadHeaderTimeout: 10 * time.Second,
	}
	return hs.ListenAndServe()
}

// mockLeases is a dhcpd.leases file with the dynamic clients the UI's
// sample data shows (ui/src/model/live.ts), plus clients asking for
// names they mustn't get, so the log shows what's registered and what
// isn't.
func mockLeases(now time.Time) []byte {
	clients := []struct {
		ip, mac, name string
		left          time.Duration
	}{
		{"192.168.1.112", "3c:22:fb:91:04:7d", "priya-mbp", 1402 * time.Minute},
		{"192.168.1.118", "f0:18:98:2e:aa:13", "sam-thinkpad", 610 * time.Minute},
		{"192.168.1.131", "8c:85:90:4b:77:02", "reception-pc", 95 * time.Minute},
		{"192.168.1.144", "b8:27:eb:5a:19:c4", "door-display", 1177 * time.Minute},
		{"192.168.20.101", "68:57:2d:10:e3:41", "thermostat", 402 * time.Minute},
		{"192.168.20.102", "50:02:91:7c:3a:0f", "camera-front", 655 * time.Minute},
		{"192.168.20.103", "50:02:91:7c:3a:1a", "camera-dock", 612 * time.Minute},
		{"192.168.20.117", "d8:f1:5b:8e:22:90", "tv-lobby", 38 * time.Minute},
		// Not registered:
		{"192.168.1.150", "02:00:00:00:00:01", "wpad", time.Hour},                // reserved name
		{"192.168.20.140", "02:00:00:00:00:02", "gw", time.Hour},                 // the router's name
		{"192.168.20.141", "02:00:00:00:00:03", "printer", time.Hour},            // a reservation's name
		{"192.168.20.142", "02:00:00:00:00:04", "Priya's iPad", time.Hour},       // not a host name
		{"192.168.20.143", "02:00:00:00:00:05", "files.evil.example", time.Hour}, // not a single label
		{"192.168.1.160", "02:00:00:00:00:06", "old-laptop", -time.Hour},         // expired
	}
	stamp := func(t time.Time) string {
		t = t.UTC()
		return fmt.Sprintf("%d %s UTC", t.Weekday(), t.Format("2006/01/02 15:04:05"))
	}
	var b bytes.Buffer
	for _, c := range clients {
		start := now.Add(-time.Hour)
		if c.left < 0 {
			start = now.Add(c.left - time.Hour)
		}
		fmt.Fprintf(&b, "lease %s {\n\tstarts %s;\n\tends %s;\n\thardware ethernet %s;\n\tclient-hostname \"%s\";\n}\n",
			c.ip, stamp(start), stamp(now.Add(c.left)), c.mac, c.name)
	}
	return b.Bytes()
}
