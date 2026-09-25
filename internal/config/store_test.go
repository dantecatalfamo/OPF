package config

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeRunner records commands and fails any whose joined form contains
// one of the substrings in fail.
type fakeRunner struct {
	mu   sync.Mutex
	cmds []string
	fail []string
}

func (r *fakeRunner) Run(ctx context.Context, argv ...string) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	line := strings.Join(argv, " ")
	r.cmds = append(r.cmds, line)
	for _, f := range r.fail {
		if strings.Contains(line, f) {
			return []byte("boom\n"), errors.New("exit status 1")
		}
	}
	return nil, nil
}

func (r *fakeRunner) commands() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.cmds...)
}

func (r *fakeRunner) ran(prefix string) bool {
	for _, c := range r.commands() {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

var testFiles = []File{
	{Name: "rc", Path: "/etc/rc.conf.local", Check: []string{"sh", "-n", "{}"}, Mode: 0644},
	{Name: "pf", Path: "/etc/pf.conf", Check: []string{"pfctl", "-n", "-f", "{}"}, Apply: []string{"pfctl", "-f", "{}"}, Confirm: true, Mode: 0600},
	{Name: "ntpd", Path: "/etc/ntpd.conf", Check: []string{"ntpd", "-n", "-f", "{}"}, Service: "ntpd", ServiceAction: "restart", Mode: 0644},
}

func newTestStore(t *testing.T, timeout time.Duration) (*Store, *fakeRunner, string) {
	t.Helper()
	root := t.TempDir()
	r := &fakeRunner{}
	s, err := New(Options{Root: root, StateDir: t.TempDir(), Files: testFiles, Runner: r, ConfirmTimeout: timeout})
	if err != nil {
		t.Fatal(err)
	}
	writeLive(t, root, "/etc/pf.conf", "pass\n")
	writeLive(t, root, "/etc/ntpd.conf", "servers pool.ntp.org\n")
	return s, r, root
}

func writeLive(t *testing.T, root, path, data string) {
	t.Helper()
	p := filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
}

func readLive(t *testing.T, root, path string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, path))
	if errors.Is(err, os.ErrNotExist) {
		return "<missing>"
	} else if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func stage(t *testing.T, s *Store, name, data string) {
	t.Helper()
	if err := s.Stage(name, []byte(data)); err != nil {
		t.Fatal(err)
	}
}

func staged(t *testing.T, s *Store) []string {
	t.Helper()
	changes, err := s.Changes()
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, c := range changes {
		names = append(names, c.File.Name)
	}
	return names
}

func TestStageNormalizesAndUnstagesWhenUnchanged(t *testing.T) {
	s, _, _ := newTestStore(t, time.Minute)
	stage(t, s, "pf", "block\r\npass")
	data, ok, _ := s.Staged("pf")
	if !ok || string(data) != "block\npass\n" {
		t.Fatalf("staged = %q, %v", data, ok)
	}
	changes, _ := s.Changes()
	if len(changes) != 1 || !strings.Contains(changes[0].Diff, "+block") {
		t.Fatalf("unexpected changes: %+v", changes)
	}

	stage(t, s, "pf", "pass\r\n")
	if got := staged(t, s); got != nil {
		t.Fatalf("staging live contents should unstage, still staged: %v", got)
	}
}

func TestCommitInstallsAndReloadsRunningService(t *testing.T) {
	s, r, root := newTestStore(t, time.Minute)
	stage(t, s, "ntpd", "servers time.example\n")
	stage(t, s, "rc", "ntpd_flags=\n") // file doesn't exist yet

	e, err := s.Commit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if e.Status != StatusApplied {
		t.Fatalf("status = %s", e.Status)
	}
	if got := readLive(t, root, "/etc/ntpd.conf"); got != "servers time.example\n" {
		t.Fatalf("ntpd.conf = %q", got)
	}
	if got := readLive(t, root, "/etc/rc.conf.local"); got != "ntpd_flags=\n" {
		t.Fatalf("rc.conf.local = %q", got)
	}
	if !r.ran("rcctl restart ntpd") {
		t.Fatalf("ntpd not restarted: %v", r.commands())
	}
	if got := staged(t, s); got != nil {
		t.Fatalf("still staged after commit: %v", got)
	}

	// Rolling back is staging the old version.
	if err := s.StageFromHistory(e.ID, "ntpd", true); err != nil {
		t.Fatal(err)
	}
	data, _, _ := s.Staged("ntpd")
	if string(data) != "servers pool.ntp.org\n" {
		t.Fatalf("restaged old = %q", data)
	}
	if err := s.StageFromHistory(e.ID, "rc", true); err == nil {
		t.Fatal("expected error staging a file that didn't exist before")
	}
}

func TestCommitSkipsStoppedService(t *testing.T) {
	s, r, _ := newTestStore(t, time.Minute)
	r.fail = []string{"rcctl check ntpd"}
	stage(t, s, "ntpd", "servers time.example\n")
	if _, err := s.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.ran("rcctl restart") {
		t.Fatalf("restarted a stopped service: %v", r.commands())
	}
}

func TestCheckFailureLeavesSystemAlone(t *testing.T) {
	s, r, root := newTestStore(t, time.Minute)
	r.fail = []string{"pfctl -n"}
	stage(t, s, "pf", "garbage\n")
	stage(t, s, "ntpd", "servers time.example\n")

	_, err := s.Commit(context.Background())
	var ce *CheckError
	if !errors.As(err, &ce) || ce.File != "/etc/pf.conf" {
		t.Fatalf("err = %v", err)
	}
	if got := readLive(t, root, "/etc/ntpd.conf"); got != "servers pool.ntp.org\n" {
		t.Fatalf("ntpd.conf changed: %q", got)
	}
	if len(staged(t, s)) != 2 {
		t.Fatal("staged changes lost")
	}
	if h, _ := s.History(); len(h) != 0 {
		t.Fatalf("history written for rejected commit: %v", h)
	}
}

func TestDriftBlocksCommit(t *testing.T) {
	s, _, root := newTestStore(t, time.Minute)
	stage(t, s, "ntpd", "servers time.example\n")
	writeLive(t, root, "/etc/ntpd.conf", "edited over ssh\n")
	_, err := s.Commit(context.Background())
	var de *DriftError
	if !errors.As(err, &de) {
		t.Fatalf("err = %v", err)
	}
	if got := readLive(t, root, "/etc/ntpd.conf"); got != "edited over ssh\n" {
		t.Fatalf("hand edit clobbered: %q", got)
	}
}

func TestApplyFailureRevertsEverything(t *testing.T) {
	s, r, root := newTestStore(t, time.Minute)
	r.fail = []string{"pfctl -f " + s.dir} // loading the staged copy fails
	stage(t, s, "ntpd", "servers time.example\n")
	stage(t, s, "pf", "block\n")

	e, err := s.Commit(context.Background())
	if err == nil {
		t.Fatal("expected failure")
	}
	if e.Status != StatusFailed {
		t.Fatalf("status = %s", e.Status)
	}
	if got := readLive(t, root, "/etc/ntpd.conf"); got != "servers pool.ntp.org\n" {
		t.Fatalf("ntpd.conf not restored: %q", got)
	}
	if !r.ran("pfctl -f " + filepath.Join(root, "/etc/pf.conf")) {
		t.Fatalf("live pf.conf not reloaded: %v", r.commands())
	}
	if len(staged(t, s)) != 2 {
		t.Fatal("staged changes should be kept after a failed commit")
	}
}

func TestConfirm(t *testing.T) {
	s, r, root := newTestStore(t, time.Minute)
	stage(t, s, "pf", "block\n")

	e, err := s.Commit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if e.Status != StatusPending || s.Pending() == nil {
		t.Fatalf("status = %s", e.Status)
	}
	if !r.ran("pfctl -f " + s.historyFile(e.ID, "new", "/etc/pf.conf")) {
		t.Fatalf("staged copy not loaded: %v", r.commands())
	}
	if got := readLive(t, root, "/etc/pf.conf"); got != "pass\n" {
		t.Fatalf("pf.conf written before confirmation: %q", got)
	}
	if err := s.Stage("ntpd", []byte("x\n")); !errors.Is(err, ErrPending) {
		t.Fatalf("staging while pending: %v", err)
	}

	if err := s.Confirm(); err != nil {
		t.Fatal(err)
	}
	if got := readLive(t, root, "/etc/pf.conf"); got != "block\n" {
		t.Fatalf("pf.conf after confirm = %q", got)
	}
	if s.Pending() != nil {
		t.Fatal("still pending")
	}
	if e, _ := s.Entry(e.ID); e.Status != StatusConfirmed {
		t.Fatalf("status = %s", e.Status)
	}
}

func TestUnconfirmedCommitReverts(t *testing.T) {
	s, r, root := newTestStore(t, 50*time.Millisecond)
	stage(t, s, "pf", "block\n")
	stage(t, s, "ntpd", "servers time.example\n")

	e, err := s.Commit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := readLive(t, root, "/etc/ntpd.conf"); got != "servers time.example\n" {
		t.Fatalf("ntpd.conf = %q", got)
	}

	deadline := time.Now().Add(2 * time.Second)
	for s.Pending() != nil {
		if time.Now().After(deadline) {
			t.Fatal("never reverted")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := readLive(t, root, "/etc/ntpd.conf"); got != "servers pool.ntp.org\n" {
		t.Fatalf("ntpd.conf not restored: %q", got)
	}
	if got := readLive(t, root, "/etc/pf.conf"); got != "pass\n" {
		t.Fatalf("pf.conf = %q", got)
	}
	if !r.ran("pfctl -f " + filepath.Join(root, "/etc/pf.conf")) {
		t.Fatalf("live pf.conf not reloaded: %v", r.commands())
	}
	if got := staged(t, s); len(got) != 2 {
		t.Fatalf("reverted changes should be staged again, got %v", got)
	}
	if e, _ := s.Entry(e.ID); e.Status != StatusReverted {
		t.Fatalf("status = %s", e.Status)
	}
	if err := s.Confirm(); !errors.Is(err, ErrNoPending) {
		t.Fatalf("confirm after revert: %v", err)
	}
}

func TestRecoverRevertsPendingCommit(t *testing.T) {
	s, r, root := newTestStore(t, time.Hour)
	stage(t, s, "pf", "block\n")
	stage(t, s, "ntpd", "servers time.example\n")
	e, err := s.Commit(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	s.pending.timer.Stop()

	// Simulate a restart.
	s2, err := New(Options{Root: root, StateDir: s.dir, Files: testFiles, Runner: r})
	if err != nil {
		t.Fatal(err)
	}
	if err := s2.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := readLive(t, root, "/etc/ntpd.conf"); got != "servers pool.ntp.org\n" {
		t.Fatalf("ntpd.conf not restored: %q", got)
	}
	if e, _ := s2.Entry(e.ID); e.Status != StatusReverted {
		t.Fatalf("status = %s", e.Status)
	}
}

func TestConfirmRequiresPathApply(t *testing.T) {
	_, err := New(Options{StateDir: t.TempDir(), Files: []File{
		{Name: "x", Path: "/etc/x", Apply: []string{"sh", "/etc/netstart"}, Confirm: true},
	}})
	if err == nil {
		t.Fatal("expected error")
	}
}
