package appliance

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dantecatalfamo/OPF/internal/config"
	"github.com/dantecatalfamo/OPF/internal/pf"
)

// pfctlRunner answers pfctl -nvf with what pfctl printed on OpenBSD 7.9
// for the router fixture's pf.conf and OPF's in its place
// (internal/pf/testdata/import), and records everything else.
type pfctlRunner struct {
	runner
	root, machine, opf string
}

func (r *pfctlRunner) Run(ctx context.Context, argv ...string) ([]byte, error) {
	if len(argv) == 3 && argv[0] == "pfctl" && argv[1] == "-nvf" {
		if argv[2] == filepath.Join(r.root, "/etc/pf.conf") {
			return []byte(r.machine), nil
		}
		return []byte(r.opf), nil
	}
	if strings.Join(argv, " ") == "ifconfig egress" {
		return []byte("em0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n\tgroups: egress\n"), nil
	}
	return r.runner.Run(ctx, argv...)
}

// newHandEnv is the router fixture's machine, configured by hand: OPF
// has no configuration of its own for it.
func newHandEnv(t *testing.T) (*Manager, string) {
	t.Helper()
	root := t.TempDir()
	fixture := filepath.Join("..", "pf", "testdata", "import")
	err := filepath.WalkDir(filepath.Join(fixture, "router"), func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(filepath.Join(fixture, "router"), p)
		dst := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
			return err
		}
		return os.WriteFile(dst, data, 0644)
	})
	if err != nil {
		t.Fatal(err)
	}
	read := func(name string) string {
		data, err := os.ReadFile(filepath.Join(fixture, name))
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	r := &pfctlRunner{root: root, machine: read("router-pfctl-orig.txt"), opf: read("router-pfctl-gen.txt")}
	store, err := config.New(config.Options{Root: root, StateDir: t.TempDir(), Files: config.DefaultFiles(), Runner: r, ConfirmTimeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	m, err := New(store)
	if err != nil {
		t.Fatal(err)
	}
	m.Runner = r
	return m, root
}

func TestImportReport(t *testing.T) {
	m, _ := newHandEnv(t)
	rep, err := m.Import(ImportRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Problems) > 0 || rep.Ruleset == nil || !rep.Ruleset.Same || rep.Fingerprint == "" {
		t.Fatalf("report: problems %v, ruleset %+v, error %q", rep.Problems, rep.Ruleset, rep.RulesetError)
	}
	status := map[string]string{}
	for _, f := range rep.Files {
		status[f.Path] = f.Status
	}
	// The hand-made resolver is left alone, so its file isn't written.
	if _, ok := status[pf.UnboundConfPath]; ok {
		t.Errorf("unbound.conf is planned: %v", status)
	}
	if status["/etc/pf.conf"] != "changed" || status["/etc/myname"] != "same" || status[pf.HostsPath] != "added" {
		t.Errorf("files %v", status)
	}
	// The same machine, the same report; another choice, another.
	again, _ := m.Import(ImportRequest{})
	if again.Fingerprint != rep.Fingerprint {
		t.Error("the fingerprint isn't stable")
	}
	managed, _ := m.Import(ImportRequest{Manage: map[string]bool{pf.AreaDNS: true}})
	if managed.Fingerprint == rep.Fingerprint {
		t.Error("managing the resolver didn't change the fingerprint")
	}
}

func TestTakeOver(t *testing.T) {
	m, root := newHandEnv(t)
	rep, err := m.Import(ImportRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.TakeOver(TakeOverRequest{Fingerprint: "stale"}); code(err) != CodeConflict {
		t.Errorf("a stale fingerprint: %v", err)
	}
	st, err := m.TakeOver(TakeOverRequest{Fingerprint: rep.Fingerprint})
	if err != nil || st.Staged == nil || st.Restarting {
		t.Fatalf("take over: %+v, %v", st, err)
	}
	// Reviewing stages it again, without being told again to replace
	// the files it was told to replace then.
	if _, err := m.Stage(StageRequest{Base: NoVersion, Model: st.Staged.Model}); err != nil {
		t.Fatalf("staging the import again: %v", err)
	}
	// But not a file changed since.
	hosts := filepath.Join(root, "/etc/dhcpd.conf")
	orig, _ := os.ReadFile(hosts)
	os.WriteFile(hosts, append(orig, []byte("# by hand\n")...), 0644)
	if _, err := m.Stage(StageRequest{Base: NoVersion, Model: st.Staged.Model}); code(err) != CodeModifiedOutside {
		t.Errorf("a file changed since: %v", err)
	}
	os.WriteFile(hosts, orig, 0644)
	staged, err := m.Stage(StageRequest{Base: NoVersion, Model: st.Staged.Model})
	if err != nil {
		t.Fatal(err)
	}

	unbound, _ := os.ReadFile(filepath.Join(root, pf.UnboundConfPath))
	c, err := m.Commit(CommitRequest{Staged: staged.Version, Message: "Take over"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Confirm(c.ID); err != nil {
		t.Fatal(err)
	}
	// The resolver left alone: its file, and the admin's line for it.
	if after, _ := os.ReadFile(filepath.Join(root, pf.UnboundConfPath)); string(after) != string(unbound) {
		t.Error("the hand-made unbound.conf was written")
	}
	rc, _ := os.ReadFile(filepath.Join(root, pf.RcPath))
	if !strings.Contains(string(rc), "unbound_flags=\n") || strings.Contains(string(rc), `unbound_flags=""`) || !strings.Contains(string(rc), `dhcpd_flags="em1 vlan20"`) {
		t.Errorf("rc.conf.local:\n%s", rc)
	}
	if !strings.Contains(string(rc), "pkg_scripts=node_exporter") {
		t.Error("the admin's rc.conf.local lines went")
	}
	// Managed now: nothing more to import.
	if _, err := m.Import(ImportRequest{}); code(err) != CodeConflict {
		t.Errorf("import once managed: %v", err)
	}
}

// Read-only, the import is saved and OPF starts again; started again,
// it stages it.
func TestTakeOverReadOnly(t *testing.T) {
	m, _ := newHandEnv(t)
	m.SetReadOnly(true)
	rep, err := m.Import(ImportRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.TakeOver(TakeOverRequest{Fingerprint: rep.Fingerprint}); code(err) != CodeUnsupported {
		t.Errorf("without a way to start again: %v", err)
	}
	started := make(chan struct{})
	m.OnTakeOver(func() { close(started) })
	res, err := m.TakeOver(TakeOverRequest{Fingerprint: rep.Fingerprint})
	if err != nil || !res.Restarting || res.Staged != nil {
		t.Fatalf("take over: %+v, %v", res, err)
	}
	<-started
	if st, _ := m.Status(); st.Staged != "" {
		t.Error("staged while read-only")
	}
	dir := filepath.Dir(m.store.StatePath(TakeOverFile))
	if !TakeOverPending(dir) {
		t.Fatal("the import wasn't saved")
	}

	// Started again, out of read-only mode.
	m.SetReadOnly(false)
	if err := m.ResumeTakeOver(); err != nil {
		t.Fatal(err)
	}
	if TakeOverPending(dir) {
		t.Error("the saved import is still there")
	}
	if st, _ := m.Status(); st.Staged == "" || st.Managed {
		t.Errorf("status %+v", st)
	}
}

// A ruleset that differs is taken over only when the admin accepts it.
func TestTakeOverDifferentRuleset(t *testing.T) {
	m, _ := newHandEnv(t)
	r := m.Runner.(*pfctlRunner)
	r.opf = strings.Replace(r.opf, "set limit states 50000", "set limit states 60000", 1)
	rep, err := m.Import(ImportRequest{})
	if err != nil || rep.Ruleset == nil || rep.Ruleset.Same {
		t.Fatalf("report %+v, %v", rep.Ruleset, err)
	}
	if _, err := m.TakeOver(TakeOverRequest{Fingerprint: rep.Fingerprint}); code(err) != CodeInvalid {
		t.Errorf("not accepted: %v", err)
	}
	if _, err := m.TakeOver(TakeOverRequest{Fingerprint: rep.Fingerprint, AcceptDifferences: true}); err != nil {
		t.Errorf("accepted: %v", err)
	}
}
