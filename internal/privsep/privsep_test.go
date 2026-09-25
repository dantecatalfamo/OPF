package privsep

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dantecatalfamo/OPF/internal/config"
)

// When the test binary is re-executed as the child it serves a tiny
// HTTP handler backed by the parent's Store.
func TestMain(m *testing.M) {
	if IsChild() {
		err := RunChild(func(mgr config.Manager, ln net.Listener) error {
			return http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/crash" {
					os.Exit(3)
				}
				data, _, err := mgr.Live("pf")
				if err != nil {
					http.Error(w, err.Error(), 500)
					return
				}
				fmt.Fprintf(w, "pid=%d pf=%s", os.Getpid(), data)
			}))
		})
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

type failRunner struct{ fail string }

func (r failRunner) Run(ctx context.Context, argv ...string) ([]byte, error) {
	if r.fail != "" && strings.Contains(strings.Join(argv, " "), r.fail) {
		return []byte("syntax error\n"), errors.New("exit status 1")
	}
	return nil, nil
}

func newStore(t *testing.T, fail string) (*config.Store, string) {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc/pf.conf"), []byte("pass\n"), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := config.New(config.Options{
		Root: root, StateDir: t.TempDir(), Runner: failRunner{fail},
		Files: []config.File{
			{Name: "pf", Path: "/etc/pf.conf", Check: []string{"pfctl", "-n", "-f", "{}"}, Apply: []string{"pfctl", "-f", "{}"}, Confirm: true},
			{Name: "ntpd", Path: "/etc/ntpd.conf", Check: []string{"ntpd", "-n", "-f", "{}"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return s, root
}

func newClient(t *testing.T, s *config.Store) *Client {
	t.Helper()
	a, b := net.Pipe()
	go Serve(s, a)
	c, err := NewClient(b)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func TestRPCRoundTrip(t *testing.T) {
	s, root := newStore(t, "")
	c := newClient(t, s)

	if len(c.Files()) != 2 {
		t.Fatalf("files = %v", c.Files())
	}
	if data, ok, err := c.Live("pf"); err != nil || !ok || string(data) != "pass\n" {
		t.Fatalf("Live = %q %v %v", data, ok, err)
	}
	if _, _, err := c.Live("nope"); !errors.Is(err, config.ErrUnknownFile) {
		t.Fatalf("unknown file: %v", err)
	}
	if err := c.Stage("pf", []byte("block\n")); err != nil {
		t.Fatal(err)
	}
	changes, err := c.Changes()
	if err != nil || len(changes) != 1 || !strings.Contains(changes[0].Diff, "+block") {
		t.Fatalf("changes = %+v, %v", changes, err)
	}
	e, err := c.Commit(context.Background())
	if err != nil || e.Status != config.StatusPending {
		t.Fatalf("commit = %+v, %v", e, err)
	}
	if p := c.Pending(); p == nil || p.ID != e.ID {
		t.Fatalf("pending = %+v", p)
	}
	if err := c.Stage("ntpd", []byte("x\n")); !errors.Is(err, config.ErrPending) {
		t.Fatalf("stage while pending: %v", err)
	}
	if _, err := c.Commit(context.Background()); !errors.Is(err, config.ErrPending) {
		t.Fatalf("commit while pending: %v", err)
	}
	if err := c.Confirm(); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(filepath.Join(root, "etc/pf.conf")); string(data) != "block\n" {
		t.Fatalf("pf.conf = %q", data)
	}
	if err := c.Confirm(); !errors.Is(err, config.ErrNoPending) {
		t.Fatalf("second confirm: %v", err)
	}
	if _, err := c.Commit(context.Background()); !errors.Is(err, config.ErrNoChanges) {
		t.Fatalf("empty commit: %v", err)
	}

	h, err := c.History()
	if err != nil || len(h) != 1 {
		t.Fatalf("history = %v, %v", h, err)
	}
	if diff, err := c.EntryDiff(h[0].ID, "pf"); err != nil || !strings.Contains(diff, "-pass") {
		t.Fatalf("entry diff = %q, %v", diff, err)
	}
	if _, err := c.Entry("../../etc"); err == nil {
		t.Fatal("expected invalid id error")
	}
	if err := c.StageFromHistory(h[0].ID, "pf", true); err != nil {
		t.Fatal(err)
	}
	if data, _, _ := c.Staged("pf"); string(data) != "pass\n" {
		t.Fatalf("restaged = %q", data)
	}
}

func TestRPCTypedErrors(t *testing.T) {
	s, root := newStore(t, "pfctl -n")
	c := newClient(t, s)

	if err := c.Stage("pf", []byte("garbage\n")); err != nil {
		t.Fatal(err)
	}
	out, ok, err := c.CheckContent(context.Background(), "pf", []byte("garbage\n"))
	if err != nil || ok || !strings.Contains(out, "syntax error") {
		t.Fatalf("check = %q %v %v", out, ok, err)
	}
	_, err = c.Commit(context.Background())
	var ce *config.CheckError
	if !errors.As(err, &ce) || ce.File != "/etc/pf.conf" || !strings.Contains(ce.Output, "syntax error") {
		t.Fatalf("commit err = %#v", err)
	}

	if err := c.Discard("pf"); err != nil {
		t.Fatal(err)
	}
	if err := c.Stage("ntpd", []byte("servers a\n")); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(root, "etc/ntpd.conf"), []byte("hand edit\n"), 0644)
	_, err = c.Commit(context.Background())
	var de *config.DriftError
	if !errors.As(err, &de) || len(de.Files) != 1 {
		t.Fatalf("drift err = %#v", err)
	}
}

func TestWaitReturnsWhenParentGoesAway(t *testing.T) {
	s, _ := newStore(t, "")
	a, b := net.Pipe()
	go Serve(s, a)
	c, err := NewClient(b)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error)
	go func() { done <- c.Wait() }()
	a.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Wait did not return")
	}
}

func TestParentRunsAndRestartsChild(t *testing.T) {
	s, _ := newStore(t, "")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan error)
	go func() { stopped <- RunParent(ctx, ParentOptions{Store: s, Listener: ln, Executable: exe}) }()

	base := "http://" + ln.Addr().String()
	hc := &http.Client{Timeout: 2 * time.Second}
	get := func(path string) (string, error) {
		resp, err := hc.Get(base + path)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		return string(body), err
	}
	waitFor := func() string {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for {
			body, err := get("/")
			if err == nil {
				return body
			}
			if time.Now().After(deadline) {
				t.Fatalf("child never served: %v", err)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}

	first := waitFor()
	if !strings.Contains(first, "pf=pass") || strings.Contains(first, fmt.Sprintf("pid=%d ", os.Getpid())) {
		t.Fatalf("unexpected response %q", first)
	}
	hc.Post(base+"/crash", "", nil) // child exits; parent should start another
	time.Sleep(200 * time.Millisecond)
	second := waitFor()
	if second == first {
		t.Fatalf("child was not restarted: %q", second)
	}

	cancel()
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("RunParent did not stop")
	}
	// The listener is still open in this process, so connections are
	// accepted by the kernel, but nothing should answer them.
	if body, err := get("/"); err == nil {
		t.Fatalf("child still serving after shutdown: %q", body)
	}
}
