package main

import (
	"bytes"
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
	"github.com/dantecatalfamo/OPF/internal/pf"
	"github.com/dantecatalfamo/OPF/internal/run"
	"github.com/dantecatalfamo/OPF/internal/web"
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
	srv := web.New(api)

	log.Printf("mock: files in %s (kept on exit); file operations are logged with the real path first", dir)
	log.Printf("mock: API on http://%s; `make mock` also starts the UI, whose dev server proxies to 127.0.0.1:18080", listen)
	hs := &http.Server{
		Addr:              listen,
		Handler:           http.NewCrossOriginProtection().Handler(srv),
		ReadHeaderTimeout: 10 * time.Second,
	}
	return hs.ListenAndServe()
}
