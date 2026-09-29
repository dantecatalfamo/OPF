package privsep

import (
	"context"
	"encoding/json"
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

	"github.com/dantecatalfamo/OPF/internal/appliance"
	"github.com/dantecatalfamo/OPF/internal/config"
	"github.com/dantecatalfamo/OPF/internal/pf"
)

// When the test binary is re-executed as the child it serves a tiny
// HTTP handler backed by the parent's API.
func TestMain(m *testing.M) {
	if IsChild() {
		err := RunChild(func(api appliance.API, ln net.Listener) error {
			return http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/crash" {
					os.Exit(3)
				}
				st, err := api.Status()
				if err != nil {
					http.Error(w, err.Error(), 500)
					return
				}
				fmt.Fprintf(w, "pid=%d live=%s", os.Getpid(), st.Live)
			}))
		})
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

type failRunner struct{ fail string }

func (r *failRunner) Run(ctx context.Context, argv ...string) ([]byte, error) {
	if r.fail != "" && strings.Contains(strings.Join(argv, " "), r.fail) {
		return []byte("syntax error\n"), errors.New("exit status 1")
	}
	return nil, nil
}

// newAPI is a Manager on a scratch system generated from the sample
// model.
func newAPI(t *testing.T) *appliance.Manager {
	api, _ := newAPIRunner(t)
	return api
}

func newAPIRunner(t *testing.T) (*appliance.Manager, *failRunner) {
	t.Helper()
	data, err := os.ReadFile("../../ui/src/model/sample-model.json")
	if err != nil {
		t.Fatal(err)
	}
	var model pf.Model
	if err := json.Unmarshal(data, &model); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	write := func(path string, b []byte) {
		p := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range pf.GenerateFiles(&model) {
		write(f.Path, config.Normalize([]byte(f.Content)))
	}
	enc, _ := appliance.EncodeModel(&model)
	write(config.ModelPath, enc)
	r := &failRunner{}
	store, err := config.New(config.Options{Root: root, StateDir: t.TempDir(), Files: config.DefaultFiles(), Runner: r, ConfirmTimeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	api, err := appliance.New(store)
	if err != nil {
		t.Fatal(err)
	}
	return api, r
}

func newClient(t *testing.T, api *appliance.Manager) *Client {
	t.Helper()
	a, b := net.Pipe()
	go Serve(api, a)
	c := NewClient(b)
	t.Cleanup(func() { c.Close() })
	return c
}

func code(err error) appliance.Code {
	var e *appliance.Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

func TestRPCRoundTrip(t *testing.T) {
	api := newAPI(t)
	c := newClient(t, api)

	live, err := c.Live()
	if err != nil || live.Model == nil || len(live.Model.Interfaces) != 5 {
		t.Fatalf("Live = %+v, %v", live, err)
	}
	live.Model.System.NTPServers = []string{"rpc.example"}
	staged, err := c.Stage(appliance.StageRequest{Base: live.Version, Model: live.Model})
	if err != nil || len(staged.Changes) != 2 {
		t.Fatalf("Stage = %+v, %v", staged, err)
	}
	if st, err := c.Status(); err != nil || st.Staged != staged.Version {
		t.Fatalf("Status = %+v, %v", st, err)
	}
	commit, err := c.Commit(appliance.CommitRequest{Staged: staged.Version, Message: "NTP", Changes: []config.ChangeNote{{Area: "system", Summary: "Time servers"}}})
	if err != nil || commit.Status != appliance.StatusApplied || commit.Message != "NTP" {
		t.Fatalf("Commit = %+v, %v", commit, err)
	}
	list, err := c.Commits()
	if err != nil || len(list) != 1 || list[0].Changes[0].Summary != "Time servers" {
		t.Fatalf("Commits = %+v, %v", list, err)
	}
	d, err := c.GetCommit(commit.ID)
	if err != nil || len(d.Diffs) != 2 {
		t.Fatalf("GetCommit = %+v, %v", d, err)
	}
	if n, err := c.LeaseNames(); err != nil || n == nil || n.Registered == nil {
		t.Fatalf("LeaseNames = %+v, %v", n, err)
	}
	if l, err := c.DHCPLeases(); err != nil || l == nil || l.Leases == nil {
		t.Fatalf("DHCPLeases = %+v, %v", l, err)
	}
	back, err := c.CommitConfig(commit.ID, appliance.Before)
	if err != nil || back.Model == nil {
		t.Fatalf("CommitConfig = %+v, %v", back, err)
	}
	now, err := c.Live()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Stage(appliance.StageRequest{Base: now.Version, Model: back.Model}); err != nil {
		t.Fatal(err)
	}
	if err := c.Discard(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Staged(); code(err) != appliance.CodeNothingStaged {
		t.Fatalf("Staged after discard: %v", err)
	}
}

func TestRPCErrors(t *testing.T) {
	api, r := newAPIRunner(t)
	c := newClient(t, api)
	live, _ := c.Live()

	bad := *live.Model
	bad.System.Hostname = "gw; reboot"
	_, err := c.Stage(appliance.StageRequest{Base: live.Version, Model: &bad})
	var e *appliance.Error
	if !errors.As(err, &e) || e.Code != appliance.CodeInvalid || e.Details[0].Path != "system.hostname" {
		t.Fatalf("invalid model: %#v", err)
	}
	if _, err := c.Stage(appliance.StageRequest{Base: "old", Model: live.Model}); code(err) != appliance.CodeConflict {
		t.Fatalf("stale base: %v", err)
	}
	if _, err := c.Confirm("20000101-000000.000"); code(err) != appliance.CodeNotFound {
		t.Fatalf("unknown commit: %v", err)
	}

	m := *live.Model
	m.System.NTPServers = []string{"x.example"}
	staged, err := c.Stage(appliance.StageRequest{Base: live.Version, Model: &m})
	if err != nil {
		t.Fatal(err)
	}
	r.fail = "ntpd -n"
	_, err = c.Commit(appliance.CommitRequest{Staged: staged.Version})
	if !errors.As(err, &e) || e.Code != appliance.CodeCheckFailed || e.Details[0].Path != "/etc/ntpd.conf" || !strings.Contains(e.Details[0].Output, "syntax error") {
		t.Fatalf("check failure: %#v", err)
	}
}

// Internal errors are logged in the privileged process and reach the
// web process without their details.
func TestRPCInternalErrorsAreSanitized(t *testing.T) {
	var r Result
	r.set("Test", errors.New("open /var/opf/secret: permission denied"))
	if r.Err.Code != appliance.CodeInternal || strings.Contains(r.Err.Message, "/var/opf") {
		t.Fatalf("leaked: %+v", r.Err)
	}
	var ok Result
	ok.set("Test", nil)
	if ok.remoteErr() != nil {
		t.Fatal("nil error came back non-nil")
	}
}

func TestWaitReturnsWhenParentGoesAway(t *testing.T) {
	api := newAPI(t)
	a, b := net.Pipe()
	go Serve(api, a)
	c := NewClient(b)
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
	api := newAPI(t)
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
	go func() { stopped <- RunParent(ctx, ParentOptions{API: api, Listener: ln, Executable: exe}) }()

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
	if !strings.Contains(first, "live=") || strings.Contains(first, "live=none") || strings.Contains(first, fmt.Sprintf("pid=%d ", os.Getpid())) {
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
