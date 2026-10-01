package appliance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dantecatalfamo/OPF/internal/config"
	"github.com/dantecatalfamo/OPF/internal/pf"
)

// runner records commands and succeeds unless one contains one of fail.
type runner struct {
	mu   sync.Mutex
	fail []string
	cmds []string
}

func (r *runner) commands() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.cmds)
}

func (r *runner) Run(ctx context.Context, argv ...string) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	line := strings.Join(argv, " ")
	r.cmds = append(r.cmds, line)
	for _, f := range r.fail {
		if strings.Contains(line, f) {
			return []byte("syntax error\n"), errors.New("exit status 1")
		}
	}
	return nil, nil
}

func sample(t *testing.T) *pf.Model {
	t.Helper()
	data, err := os.ReadFile("../../ui/src/model/sample-model.json")
	if err != nil {
		t.Fatal(err)
	}
	m, err := decodeModel(data)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

type env struct {
	t     *testing.T
	root  string
	state string
	m     *Manager
	run   *runner
}

// newEnv is a system whose files are what the sample model generates.
func newEnv(t *testing.T, timeout time.Duration) *env {
	t.Helper()
	root := t.TempDir()
	model := sample(t)
	write := func(path string, data []byte) {
		p := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range pf.GenerateFiles(model) {
		write(f.Path, config.Normalize([]byte(f.Content)))
	}
	data, err := EncodeModel(model)
	if err != nil {
		t.Fatal(err)
	}
	write(config.ModelPath, data)
	// A system that has run a while: the URL alias's list downloaded and
	// unbound's trust anchor made.
	for _, a := range model.Firewall.Aliases {
		if a.Type == pf.AliasURL {
			write(pf.TablePath(a.Name), []byte("# Downloaded by OPF from "+a.URL+" at 2026-01-01T00:00:00Z\n192.0.2.0/24\n"))
		}
	}
	write(pf.RootKeyPath, []byte(". IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D\n"))

	r := &runner{}
	state := t.TempDir()
	store, err := config.New(config.Options{Root: root, StateDir: state, Files: config.DefaultFiles(), Runner: r, ConfirmTimeout: timeout})
	if err != nil {
		t.Fatal(err)
	}
	m, err := New(store)
	if err != nil {
		t.Fatal(err)
	}
	m.Runner = r // nothing runs for real
	return &env{t: t, root: root, state: state, m: m, run: r}
}

func (e *env) live() *Config {
	e.t.Helper()
	c, err := e.m.Live()
	if err != nil {
		e.t.Fatal(err)
	}
	return c
}

func (e *env) read(path string) string {
	e.t.Helper()
	data, err := os.ReadFile(filepath.Join(e.root, path))
	if errors.Is(err, os.ErrNotExist) {
		return "<missing>"
	}
	if err != nil {
		e.t.Fatal(err)
	}
	return string(data)
}

func code(err error) Code {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

// disableLANRule turns off "Allow LAN to anywhere" (pf.conf only).
func disableLANRule(m *pf.Model) {
	for i := range m.Firewall.Rules {
		if m.Firewall.Rules[i].ID == "r3" {
			m.Firewall.Rules[i].Enabled = false
		}
	}
}

func TestStageCommitConfirm(t *testing.T) {
	e := newEnv(t, time.Minute)
	live := e.live()
	model := live.Model
	disableLANRule(model)
	model.System.NTPServers = []string{"time.example.org"}

	staged, err := e.m.Stage(StageRequest{Base: live.Version, Model: model})
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, c := range staged.Changes {
		paths = append(paths, c.Path)
		if c.Path == "/etc/pf.conf" && !c.NeedsConfirm {
			t.Error("pf.conf should need confirmation")
		}
	}
	if strings.Join(paths, " ") != "/var/opf/config.json /etc/pf.conf /etc/ntpd.conf" {
		t.Fatalf("changes %v", paths)
	}
	if st, _ := e.m.Status(); st.Staged != staged.Version || st.Live != live.Version {
		t.Fatalf("status %+v", st)
	}

	c, err := e.m.Commit(CommitRequest{Staged: staged.Version, Message: "Tighten LAN", Changes: []config.ChangeNote{{Area: "firewall", Summary: "Disabled rule"}}})
	if err != nil {
		t.Fatal(err)
	}
	if c.Status != StatusPending || c.Deadline == nil || c.Message != "Tighten LAN" || len(c.Changes) != 1 {
		t.Fatalf("commit %+v", c)
	}
	if !strings.Contains(e.read("/etc/ntpd.conf"), "time.example.org") {
		t.Error("ntpd.conf not installed")
	}
	if strings.Contains(e.read("/etc/pf.conf"), "Allow LAN") == false {
		t.Error("pf.conf written before confirmation")
	}
	if _, err := e.m.Stage(StageRequest{Base: e.live().Version, Model: model}); code(err) != CodePending {
		t.Errorf("stage while pending: %v", err)
	}

	if _, err := e.m.Confirm(c.ID); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(e.read("/etc/pf.conf"), "Allow LAN to anywhere") {
		t.Error("pf.conf not installed after confirmation")
	}
	after := e.live()
	if after.Version != staged.Version {
		t.Errorf("live version %s, staged was %s", after.Version, staged.Version)
	}
	list, _ := e.m.Commits()
	if len(list) != 1 || list[0].Status != StatusConfirmed || list[0].Message != "Tighten LAN" {
		t.Fatalf("history %+v", list)
	}
	d, err := e.m.GetCommit(c.ID)
	if err != nil || len(d.Diffs) != 3 {
		t.Fatalf("detail %+v, %v", d, err)
	}
}

func TestStageRejects(t *testing.T) {
	e := newEnv(t, time.Minute)
	live := e.live()

	if _, err := e.m.Stage(StageRequest{Base: "stale", Model: live.Model}); code(err) != CodeConflict {
		t.Errorf("stale base: %v", err)
	}

	bad := sample(t)
	bad.Firewall.Rules[0].Description = "x\npass all"
	_, err := e.m.Stage(StageRequest{Base: live.Version, Model: bad})
	var ae *Error
	if !errors.As(err, &ae) || ae.Code != CodeInvalid || ae.Details[0].Path != "firewall.rules[0].description" {
		t.Errorf("invalid model: %+v", err)
	}

	gone := sample(t)
	gone.Interfaces = gone.Interfaces[:2] // drops vlan20 and wg0
	gone.DHCP = gone.DHCP[:1]
	var fw []pf.Rule
	for _, r := range gone.Firewall.Rules {
		if len(r.Interfaces) == 0 || r.Interfaces[0] == "wan" || r.Interfaces[0] == "lan" {
			fw = append(fw, r)
		}
	}
	gone.Firewall.Rules = fw
	gone.Routing.Gateways = gone.Routing.Gateways[:1]
	gone.Routing.Routes = nil
	for i := range gone.Firewall.Rules {
		gone.Firewall.Rules[i].Gateway = ""
	}
	// Removing interfaces stages removing their files.
	st, err := e.m.Stage(StageRequest{Base: live.Version, Model: gone})
	if err != nil {
		t.Fatalf("removing interfaces: %v", err)
	}
	var removedFiles []string
	for _, c := range st.Changes {
		if c.Status == "removed" {
			removedFiles = append(removedFiles, c.Path)
		}
	}
	if strings.Join(removedFiles, " ") != "/etc/hostname.vlan20 /etc/hostname.wg0 /etc/hostname.wg1" {
		t.Errorf("removed %v", removedFiles)
	}

	same, err := e.m.Stage(StageRequest{Base: live.Version, Model: live.Model})
	if err != nil || len(same.Changes) != 0 {
		t.Errorf("identical model: %+v, %v", same, err)
	}
	if st, _ := e.m.Status(); st.Staged != "" {
		t.Errorf("identical model left something staged: %+v", st)
	}
	if _, err := e.m.Staged(); code(err) != CodeNothingStaged {
		t.Errorf("staged after identical: %v", err)
	}
}

func TestModifiedOutside(t *testing.T) {
	e := newEnv(t, time.Minute)
	live := e.live()
	if err := os.WriteFile(filepath.Join(e.root, "/etc/ntpd.conf"), []byte("servers by.hand\n"), 0644); err != nil {
		t.Fatal(err)
	}
	model := sample(t)
	disableLANRule(model)

	_, err := e.m.Stage(StageRequest{Base: live.Version, Model: model})
	var ae *Error
	if !errors.As(err, &ae) || ae.Code != CodeModifiedOutside || ae.Details[0].Path != "/etc/ntpd.conf" {
		t.Fatalf("hand edit not caught: %+v", err)
	}
	if _, err := e.m.Stage(StageRequest{Base: live.Version, Model: model, Overwrite: []string{"/etc/ntpd.conf"}}); err != nil {
		t.Fatalf("overwrite: %v", err)
	}

	// Repair: re-staging the live model over a hand edit.
	if err := e.m.Discard(); err != nil {
		t.Fatal(err)
	}
	staged, err := e.m.Stage(StageRequest{Base: live.Version, Model: live.Model, Overwrite: []string{"/etc/ntpd.conf"}})
	if err != nil || staged.Version != live.Version || len(staged.Changes) != 1 {
		t.Fatalf("repair stage: %+v, %v", staged, err)
	}
	if _, err := e.m.Commit(CommitRequest{Staged: staged.Version, Message: "Undo hand edit"}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(e.read("/etc/ntpd.conf"), "by.hand") {
		t.Error("hand edit not replaced")
	}

	// Edited after staging: the commit is refused.
	model2 := sample(t)
	model2.System.NTPServers = []string{"a.example"}
	staged, err = e.m.Stage(StageRequest{Base: e.live().Version, Model: model2})
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(e.root, "/etc/ntpd.conf"), []byte("servers late.edit\n"), 0644)
	if _, err := e.m.Commit(CommitRequest{Staged: staged.Version}); code(err) != CodeModifiedOutside {
		t.Errorf("drift after staging: %v", err)
	}
}

func TestCommitRejects(t *testing.T) {
	e := newEnv(t, time.Minute)
	if _, err := e.m.Commit(CommitRequest{Staged: "x"}); code(err) != CodeNothingStaged {
		t.Errorf("nothing staged: %v", err)
	}
	model := sample(t)
	disableLANRule(model)
	staged, err := e.m.Stage(StageRequest{Base: e.live().Version, Model: model})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.m.Commit(CommitRequest{Staged: "other"}); code(err) != CodeConflict {
		t.Errorf("wrong staged version: %v", err)
	}
	if _, err := e.m.Commit(CommitRequest{Staged: staged.Version, Message: "a\nb"}); code(err) != CodeInvalid {
		t.Errorf("message with a newline: %v", err)
	}

	e.run.fail = []string{"pfctl -n"}
	_, err = e.m.Commit(CommitRequest{Staged: staged.Version})
	var ae *Error
	if !errors.As(err, &ae) || ae.Code != CodeCheckFailed || ae.Details[0].Path != "/etc/pf.conf" || !strings.Contains(ae.Details[0].Output, "syntax error") {
		t.Errorf("check failure: %+v", err)
	}
	if list, _ := e.m.Commits(); len(list) != 0 {
		t.Errorf("history after a rejected commit: %+v", list)
	}

	e.run.fail = []string{"pfctl -f"}
	c, err := e.m.Commit(CommitRequest{Staged: staged.Version})
	if err != nil || c.Status != StatusFailed {
		t.Errorf("apply failure: %+v, %v", c, err)
	}
	if st, _ := e.m.Status(); st.Staged != staged.Version {
		t.Errorf("failed commit should leave its changes staged: %+v", st)
	}
}

func TestPendingCommit(t *testing.T) {
	e := newEnv(t, 80*time.Millisecond)
	live := e.live()
	model := sample(t)
	disableLANRule(model)
	staged, _ := e.m.Stage(StageRequest{Base: live.Version, Model: model})
	c, err := e.m.Commit(CommitRequest{Staged: staged.Version})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.m.Confirm("20000101-000000.000"); code(err) != CodeNotFound {
		t.Errorf("unknown commit: %v", err)
	}
	if _, err := e.m.Confirm("../../x"); code(err) != CodeNotFound {
		t.Errorf("malformed id: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		st, _ := e.m.Status()
		if st.Pending == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("never reverted")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := e.m.Confirm(c.ID); code(err) != CodeNotPending {
		t.Errorf("confirm after timeout: %v", err)
	}
	got, _ := e.m.GetCommit(c.ID)
	if got.Status != StatusReverted {
		t.Errorf("status %s", got.Status)
	}
	if e.live().Version != live.Version {
		t.Error("live model changed by a reverted commit")
	}
	if st, _ := e.m.Status(); st.Staged != staged.Version {
		t.Errorf("reverted changes should be staged again: %+v", st)
	}

	// Revert explicitly.
	c2, err := e.m.Commit(CommitRequest{Staged: staged.Version})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.m.Revert(c.ID); code(err) != CodeNotPending {
		t.Errorf("revert of an old commit: %v", err)
	}
	r, err := e.m.Revert(c2.ID)
	if err != nil || r.Status != StatusReverted {
		t.Errorf("revert: %+v, %v", r, err)
	}
}

func TestRestore(t *testing.T) {
	e := newEnv(t, time.Minute)
	orig := e.live()
	model := sample(t)
	model.System.NTPServers = []string{"b.example"}
	staged, _ := e.m.Stage(StageRequest{Base: orig.Version, Model: model})
	c, err := e.m.Commit(CommitRequest{Staged: staged.Version, Message: "ntp"})
	if err != nil || c.Status != StatusApplied {
		t.Fatalf("%+v, %v", c, err)
	}
	if _, err := e.m.CommitConfig(c.ID, "sideways"); code(err) != CodeInvalid {
		t.Errorf("bad which: %v", err)
	}
	if _, err := e.m.CommitConfig("20000101-000000.000", Before); code(err) != CodeNotFound {
		t.Errorf("unknown commit: %v", err)
	}
	back, err := e.m.CommitConfig(c.ID, Before)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(back.Model)
	b, _ := json.Marshal(orig.Model)
	if string(a) != string(b) || back.Version != orig.Version {
		t.Error("the model before the commit differs from the one that was live")
	}
	if after, err := e.m.CommitConfig(c.ID, After); err != nil || after.Version != e.live().Version {
		t.Errorf("after: %+v, %v", after, err)
	}
	if _, err := e.m.Staged(); code(err) != CodeNothingStaged {
		t.Errorf("reading a commit's configuration staged something: %v", err)
	}

	// Restoring is staging it.
	st, err := e.m.Stage(StageRequest{Base: e.live().Version, Model: back.Model})
	if err != nil || st.Version != orig.Version {
		t.Fatalf("stage the old model: %+v, %v", st, err)
	}
}

func TestOnChange(t *testing.T) {
	e := newEnv(t, time.Minute)
	n := 0
	// It runs without the lock held, so it may call back in.
	e.m.OnChange(func() {
		n++
		e.m.Discard() // takes the lock
	})
	model := sample(t)
	model.System.NTPServers = []string{"c.example"}
	st, err := e.m.Stage(StageRequest{Base: e.live().Version, Model: model})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.m.Commit(CommitRequest{Staged: st.Version, Message: "ntp"}); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("called %d times after a commit", n)
	}
}

// The daemons rc.conf.local is generated for are the ones the reconcile
// after installing it manages.
func TestRcServicesMatchGenerator(t *testing.T) {
	got := pf.GenerateRcConfLocal(sample(t))
	var names []string
	for _, line := range strings.Split(got, "\n") {
		if name, _, ok := strings.Cut(line, "_flags="); ok && !strings.HasPrefix(line, "#") {
			names = append(names, name)
		}
	}
	if strings.Join(names, " ") != strings.Join(config.RcServices, " ") {
		t.Errorf("rc.conf.local sets %v, but the reconcile manages %v", names, config.RcServices)
	}
}

// Committing a model without an interface removes its hostname.if and
// destroys the device; reverting puts both back.
func TestRemoveInterface(t *testing.T) {
	e := newEnv(t, time.Minute)
	live := e.live()
	m := sample(t)
	// Drop the site-to-site tunnel and what refers to it.
	m.Interfaces = slices.DeleteFunc(m.Interfaces, func(i pf.Iface) bool { return i.ID == "wg1" })
	m.Firewall.Rules = slices.DeleteFunc(m.Firewall.Rules, func(r pf.Rule) bool { return slices.Contains(r.Interfaces, "wg1") })
	m.Routing.Gateways = slices.DeleteFunc(m.Routing.Gateways, func(g pf.Gateway) bool { return g.Iface == "wg1" })
	m.Routing.Routes = nil
	for i := range m.Firewall.Rules {
		if m.Firewall.Rules[i].Gateway == "gw_wh" {
			m.Firewall.Rules[i].Gateway = ""
		}
	}
	st, err := e.m.Stage(StageRequest{Base: live.Version, Model: m})
	if err != nil {
		t.Fatalf("%v %+v", err, AsError(err).Details)
	}
	c, err := e.m.Commit(CommitRequest{Staged: st.Version, Message: "remove the site tunnel"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(e.root, "/etc/hostname.wg1")); !os.IsNotExist(err) {
		t.Errorf("hostname.wg1 is still there: %v", err)
	}
	if cmds := strings.Join(e.run.commands(), "\n"); !strings.Contains(cmds, "destroy") || !strings.Contains(cmds, "sh wg1") {
		t.Errorf("wg1 wasn't destroyed: %s", cmds)
	}
	removed := false
	for _, f := range c.Files {
		removed = removed || (f.Path == "/etc/hostname.wg1" && f.Removed)
	}
	if !removed {
		t.Errorf("the commit doesn't record the removal: %+v", c.Files)
	}
	if c.Status == StatusPending {
		if _, err := e.m.Revert(c.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(e.root, "/etc/hostname.wg1")); err != nil {
			t.Errorf("reverting didn't restore hostname.wg1: %v", err)
		}
	}
}

// rc.conf.local is shared: staging and committing keep its lines that
// aren't OPF's (pkg_scripts, other daemons' flags), and only a hand
// change to one of OPF's own lines counts as a change outside OPF.
func TestRcConfLocalKeepsOtherLines(t *testing.T) {
	e := newEnv(t, time.Minute)
	path := filepath.Join(e.root, pf.RcPath)
	ours := pf.GenerateRcConfLocal(sample(t)) // what OPF wrote for the live model
	other := "pkg_scripts=\"postgresql\"\npostgresql_flags=\"-D /var/postgresql/data\"\n"
	if err := os.WriteFile(path, []byte(other+"\n"+ours), 0644); err != nil {
		t.Fatal(err)
	}
	// An admin enables another package with rcctl: not OPF's business.
	if err := os.WriteFile(path, []byte(strings.Replace(other, `"postgresql"`, `"postgresql nginx"`, 1)+"\n"+ours), 0644); err != nil {
		t.Fatal(err)
	}

	live := e.live()
	m := live.Model
	for i := range m.DHCP {
		if m.DHCP[i].Iface == "iot" {
			m.DHCP[i].Enabled = false
		}
	}
	st, err := e.m.Stage(StageRequest{Base: live.Version, Model: m})
	if err != nil {
		t.Fatalf("stage: %v %+v", err, AsError(err).Details)
	}
	c, err := e.m.Commit(CommitRequest{Staged: st.Version, Message: "no DHCP on IoT"})
	if err != nil {
		t.Fatal(err)
	}
	if c.Status == StatusPending {
		e.m.Confirm(c.ID)
	}
	got, _ := os.ReadFile(path)
	for _, want := range []string{`pkg_scripts="postgresql nginx"`, `postgresql_flags="-D /var/postgresql/data"`, `dhcpd_flags="em1"`} {
		if !strings.Contains(string(got), want) {
			t.Errorf("missing %q in rc.conf.local:\n%s", want, got)
		}
	}

	// Someone disables dhcpd by hand: that is OPF's line, so it's a
	// change outside OPF.
	os.WriteFile(path, []byte(strings.Replace(string(got), `dhcpd_flags="em1"`, `dhcpd_flags=NO`, 1)), 0644)
	live = e.live()
	m = live.Model
	m.System.NTPServers = []string{"other.example"}
	_, err = e.m.Stage(StageRequest{Base: live.Version, Model: m})
	if code(err) != CodeModifiedOutside || !strings.Contains(fmt.Sprint(AsError(err).Details), pf.RcPath) {
		t.Errorf("hand-disabled dhcpd: %v", err)
	}
}

// A commit reverted because nobody confirmed it reports the change, so
// the lease watcher puts DHCP names back in the reloaded resolver.
func TestTimeoutRevertReportsChange(t *testing.T) {
	e := newEnv(t, 50*time.Millisecond)
	changed := make(chan struct{}, 4)
	e.m.OnChange(func() { changed <- struct{}{} })
	m := e.live().Model
	m.Firewall.Rules[0].Description += " (edited)"
	st, err := e.m.Stage(StageRequest{Base: e.live().Version, Model: m})
	if err != nil {
		t.Fatal(err)
	}
	c, err := e.m.Commit(CommitRequest{Staged: st.Version})
	if err != nil || c.Status != "pending" {
		t.Fatalf("%+v %v", c, err)
	}
	<-changed // the commit's
	select {
	case <-changed:
	case <-time.After(5 * time.Second):
		t.Fatal("no change reported after the confirm timeout")
	}
	if e.m.store.Pending() != nil {
		t.Error("still pending")
	}
}
