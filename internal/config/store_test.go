package config

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"reflect"
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

	e, err := s.Commit(context.Background(), CommitInfo{})
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
	if _, err := s.Commit(context.Background(), CommitInfo{}); err != nil {
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

	_, err := s.Commit(context.Background(), CommitInfo{})
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
	_, err := s.Commit(context.Background(), CommitInfo{})
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

	e, err := s.Commit(context.Background(), CommitInfo{})
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

	e, err := s.Commit(context.Background(), CommitInfo{})
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

	e, err := s.Commit(context.Background(), CommitInfo{})
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
	e, err := s.Commit(context.Background(), CommitInfo{})
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

func newPatternStore(t *testing.T) (*Store, *fakeRunner, string) {
	t.Helper()
	root := t.TempDir()
	r := &fakeRunner{}
	files := append([]File{{
		Name: "hostname.*", Path: "/etc/hostname.*", Match: `[a-z]+[0-9]+`,
		Apply: []string{"sh", "/etc/netstart", "{*}"}, Mode: 0640,
	}}, testFiles...)
	s, err := New(Options{Root: root, StateDir: t.TempDir(), Files: files, Runner: r, ConfirmTimeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	writeLive(t, root, "/etc/pf.conf", "pass\n")
	return s, r, root
}

func TestPatternLookup(t *testing.T) {
	s, _, _ := newPatternStore(t)
	f, err := s.Lookup("hostname.vlan20")
	if err != nil || f.Path != "/etc/hostname.vlan20" || f.Apply[2] != "vlan20" {
		t.Fatalf("Lookup = %+v, %v", f, err)
	}
	for _, bad := range []string{"hostname.*", "hostname.", "hostname.../etc/passwd", "hostname.em0/x", "hostname.EM0", "hostname.em", "xhostname.em0"} {
		if _, err := s.Lookup(bad); !errors.Is(err, ErrUnknownFile) {
			t.Errorf("Lookup(%q) = %v, want unknown file", bad, err)
		}
	}
}

func TestPatternFilesCommitFirst(t *testing.T) {
	s, r, root := newPatternStore(t)
	stage(t, s, "pf", "block\n")
	stage(t, s, "hostname.em1", "inet 192.168.1.1/24\nup\n")
	stage(t, s, "hostname.em0", "inet autoconf\nup\n")

	if got := staged(t, s); !reflect.DeepEqual(got, []string{"hostname.em0", "hostname.em1", "pf"}) {
		t.Fatalf("changes in order %v", got)
	}
	e, err := s.Commit(context.Background(), CommitInfo{})
	if err != nil {
		t.Fatal(err)
	}
	if got := readLive(t, root, "/etc/hostname.em1"); got != "inet 192.168.1.1/24\nup\n" {
		t.Fatalf("hostname.em1 = %q", got)
	}
	fi, err := os.Stat(filepath.Join(root, "/etc/hostname.em1"))
	if err != nil || fi.Mode().Perm() != 0640 {
		t.Fatalf("mode = %v, %v", fi.Mode(), err)
	}
	// Checks run first; then interfaces are applied before pf.
	var applied []string
	for _, c := range r.commands() {
		if strings.HasPrefix(c, "sh /etc/netstart") || strings.HasPrefix(c, "pfctl -f") {
			applied = append(applied, strings.Fields(c)[2])
		}
	}
	if len(applied) != 3 || applied[0] != "em0" || applied[1] != "em1" || !strings.HasSuffix(applied[2], "pf.conf") {
		t.Fatalf("apply order %v, commands %v", applied, r.commands())
	}
	if err := s.Confirm(); err != nil {
		t.Fatal(err)
	}
	// History resolves pattern instances too.
	if err := s.StageFromHistory(e.ID, "hostname.em0", false); err != nil {
		t.Fatal(err)
	}
}

func TestPatternDiscardAll(t *testing.T) {
	s, _, _ := newPatternStore(t)
	stage(t, s, "hostname.em0", "up\n")
	stage(t, s, "ntpd", "servers x\n")
	if err := s.DiscardAll(); err != nil {
		t.Fatal(err)
	}
	if got := staged(t, s); got != nil {
		t.Fatalf("still staged: %v", got)
	}
}

func TestPatternValidation(t *testing.T) {
	for _, f := range []File{
		{Name: "hostname.*", Path: "/etc/hostname", Match: `x`},
		{Name: "a*b*", Path: "/etc/a*", Match: `x`},
		{Name: "hostname.*", Path: "/etc/hostname.*"},
		{Name: "hostname.*", Path: "/etc/hostname.*", Match: `(`},
		{Name: "hostname.*", Path: "/etc/hostname.*", Match: `x`, Confirm: true, Apply: []string{"{}"}},
	} {
		if _, err := New(Options{StateDir: t.TempDir(), Files: []File{f}}); err == nil {
			t.Errorf("New accepted %+v", f)
		}
	}
}

func TestFileLog(t *testing.T) {
	root := t.TempDir()
	var buf bytes.Buffer
	s, err := New(Options{
		Root: root, StateDir: t.TempDir(), Files: testFiles, Runner: &fakeRunner{},
		ConfirmTimeout: 50 * time.Millisecond, FileLog: log.New(&buf, "", 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	writeLive(t, root, "/etc/pf.conf", "pass\n")

	stage(t, s, "pf", "block\n")
	stage(t, s, "rc", "ntpd_flags=\n")
	stage(t, s, "ntpd", "servers x\n")
	stage(t, s, "ntpd", "") // same as the (missing) live file: unstaged
	if _, err := s.Commit(context.Background(), CommitInfo{}); err != nil {
		t.Fatal(err)
	}
	if err := s.Confirm(); err != nil {
		t.Fatal(err)
	}
	// A second commit that isn't confirmed: rc.conf.local is restored.
	stage(t, s, "rc", "sshd_flags=NO\n")
	stage(t, s, "pf", "pass\n")
	if _, err := s.Commit(context.Background(), CommitInfo{}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for s.Pending() != nil && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	got := buf.String()
	cand := func(p string) string { return filepath.Join(s.dir, "candidate", p) }
	live := func(p string) string { return filepath.Join(root, p) }
	op := func(name string) string { return fmt.Sprintf("file: %-8s ", name) }
	for _, want := range []string{
		op("stage") + "/etc/pf.conf -> " + cand("/etc/pf.conf") + "\n",
		op("stage") + "/etc/rc.conf.local -> " + cand("/etc/rc.conf.local") + " (new file)\n",
		op("unstage") + "/etc/ntpd.conf -> " + cand("/etc/ntpd.conf") + " (same as the live file)\n",
		op("install") + "/etc/rc.conf.local -> " + live("/etc/rc.conf.local") + " (commit ",
		", new file, mode 0644)\n",
		op("install") + "/etc/pf.conf -> " + live("/etc/pf.conf") + " (confirmed commit ",
		op("restore") + "/etc/rc.conf.local -> " + live("/etc/rc.conf.local") + " (reverting commit ",
		// bookkeeping
		op("index") + filepath.Join(s.dir, "candidate", "base.json") + " (staging index, 1 staged)\n",
		op("snapshot") + "/etc/pf.conf -> " + filepath.Join(s.dir, "history"),
		"/old/etc/pf.conf (restore point before commit ",
		"/new/etc/rc.conf.local (contents of commit ",
		op("record") + filepath.Join(s.dir, "history"),
		"/manifest.json (commit ",
		", applying)\n",
		", confirmed)\n",
		", reverted)\n",
		op("clear") + "/etc/rc.conf.local -> " + cand("/etc/rc.conf.local") + " (used by commit ",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("file log missing %q:\n%s", want, got)
		}
	}
	// Clearing the candidate after a commit isn't reported as unstaging.
	if n := strings.Count(got, "unstage"); n != 1 {
		t.Errorf("%d unstage lines, want 1:\n%s", n, got)
	}
}

func TestFileLogCheck(t *testing.T) {
	var buf bytes.Buffer
	s, err := New(Options{StateDir: t.TempDir(), Files: testFiles, Runner: &fakeRunner{}, FileLog: log.New(&buf, "", 0)})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.CheckContent(context.Background(), "pf", []byte("pass\n")); err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("file: %-8s /etc/pf.conf -> %s", "check", filepath.Join(s.dir, "tmp", "pf."))
	if !strings.Contains(buf.String(), want) || !strings.Contains(buf.String(), "(temporary copy for the checker, removed after)") {
		t.Errorf("got %q, want %q…", buf.String(), want)
	}
}

// With a CheckRunner, validators run there and everything else on the
// Runner: -dry -checks validates for real and applies nothing.
func TestCheckRunner(t *testing.T) {
	root := t.TempDir()
	applies, checks := &fakeRunner{}, &fakeRunner{fail: []string{"pfctl -n"}}
	s, err := New(Options{Root: root, StateDir: t.TempDir(), Files: testFiles, Runner: applies, CheckRunner: checks, ConfirmTimeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	writeLive(t, root, "/etc/pf.conf", "pass\n")
	stage(t, s, "pf", "garbage\n")
	var ce *CheckError
	if _, err := s.Commit(context.Background(), CommitInfo{}); !errors.As(err, &ce) {
		t.Fatalf("err = %v", err)
	}
	if !checks.ran("pfctl -n -f") || len(applies.commands()) != 0 {
		t.Errorf("checks ran %q, applies ran %q", checks.commands(), applies.commands())
	}
}

// A service is told once per commit, and a file with ReloadWith that
// changed alone uses it instead of reloading the whole service.
func TestServiceToldOnce(t *testing.T) {
	files := []File{
		{Name: "zone", Path: "/var/db/zone", Service: "dns", ServiceAction: "reload", ReloadWith: []string{"dns-control", "reload-zone", "{}"}, Mode: 0644},
		{Name: "dns.conf", Path: "/etc/dns.conf", Service: "dns", ServiceAction: "reload", Mode: 0644},
	}
	setup := func(t *testing.T, running bool) (*Store, *fakeRunner, string) {
		root := t.TempDir()
		r := &fakeRunner{}
		if !running {
			r.fail = []string{"rcctl check"}
		}
		s, err := New(Options{Root: root, StateDir: t.TempDir(), Files: files, Runner: r, ConfirmTimeout: time.Minute})
		if err != nil {
			t.Fatal(err)
		}
		writeLive(t, root, "/var/db/zone", "a\n")
		writeLive(t, root, "/etc/dns.conf", "x\n")
		return s, r, root
	}
	count := func(r *fakeRunner, prefix string) int {
		n := 0
		for _, c := range r.commands() {
			if strings.HasPrefix(c, prefix) {
				n++
			}
		}
		return n
	}

	// Both files: one reload, which takes them both.
	s, r, _ := setup(t, true)
	stage(t, s, "zone", "b\n")
	stage(t, s, "dns.conf", "y\n")
	if _, err := s.Commit(context.Background(), CommitInfo{}); err != nil {
		t.Fatal(err)
	}
	if count(r, "rcctl reload dns") != 1 || count(r, "dns-control") != 0 {
		t.Errorf("both changed: %q", r.commands())
	}

	// The zone alone: just the zone, for the commit and its revert.
	s, r, root := setup(t, true)
	stage(t, s, "zone", "b\n")
	e, err := s.Commit(context.Background(), CommitInfo{})
	if err != nil {
		t.Fatal(err)
	}
	want := "dns-control reload-zone " + filepath.Join(root, "var/db/zone")
	if count(r, "rcctl reload") != 0 || count(r, want) != 1 {
		t.Errorf("zone alone: %q", r.commands())
	}
	if err := s.revertEntry(context.Background(), e, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if count(r, "rcctl reload") != 0 || count(r, want) != 2 || readLive(t, root, "/var/db/zone") != "a\n" {
		t.Errorf("revert of the zone alone: %q", r.commands())
	}

	// A service that isn't running is left alone.
	s, r, _ = setup(t, false)
	stage(t, s, "zone", "b\n")
	stage(t, s, "dns.conf", "y\n")
	if _, err := s.Commit(context.Background(), CommitInfo{}); err != nil {
		t.Fatal(err)
	}
	if count(r, "rcctl reload") != 0 || count(r, "dns-control") != 0 {
		t.Errorf("not running: %q", r.commands())
	}
}

// Removing a file with ReloadWith reloads the whole service: the zone
// alone can't be told it's gone.
func TestRemovalReloadsWholeService(t *testing.T) {
	files := []File{
		{Name: "zone", Path: "/var/db/zone", Service: "dns", ServiceAction: "reload", ReloadWith: []string{"dns-control", "reload-zone", "{}"}, Mode: 0644},
	}
	root := t.TempDir()
	r := &fakeRunner{}
	s, err := New(Options{Root: root, StateDir: t.TempDir(), Files: files, Runner: r, ConfirmTimeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	writeLive(t, root, "/var/db/zone", "a\n")
	if err := s.StageRemoval("zone"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Commit(context.Background(), CommitInfo{}); err != nil {
		t.Fatal(err)
	}
	if !r.ran("rcctl reload dns") || r.ran("dns-control") {
		t.Errorf("removal: %q", r.commands())
	}
}
