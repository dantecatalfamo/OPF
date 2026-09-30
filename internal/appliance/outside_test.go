package appliance

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// commitRuleToggle stages, commits and confirms disabling the sample's LAN rule,
// or enabling it again, and returns the commit.
func commitRuleToggle(t *testing.T, e *env, enable bool) *Commit {
	t.Helper()
	m := e.live().Model
	for i := range m.Firewall.Rules {
		if r := &m.Firewall.Rules[i]; r.Description == "Allow LAN to anywhere" {
			r.Enabled = enable
		}
	}
	st, err := e.m.Stage(StageRequest{Base: e.live().Version, Model: m})
	if err != nil {
		t.Fatal(err)
	}
	c, err := e.m.Commit(CommitRequest{Staged: st.Version})
	if err != nil {
		t.Fatal(err)
	}
	if c.Status == "pending" {
		if c, err = e.m.Confirm(c.ID); err != nil {
			t.Fatal(err)
		}
	}
	return c
}

// An OPF upgrade that changes what a generator writes mustn't make the
// files the old version wrote look hand-edited: they're judged against
// what OPF last wrote, not what it would write now.
func TestUpgradeIsNotAnOutsideChange(t *testing.T) {
	e := newEnv(t, time.Minute)
	c := commitRuleToggle(t, e, false)
	// As if an older OPF had written pf.conf with a different comment:
	// the file on disk and the commit's copy of it both say so.
	older := e.read("/etc/pf.conf") + "# written by an older OPF\n"
	for _, p := range []string{filepath.Join(e.root, "etc/pf.conf"), filepath.Join(e.state, "history", c.ID, "new", "etc/pf.conf")} {
		if err := os.WriteFile(p, []byte(older), 0600); err != nil {
			t.Fatal(err)
		}
	}
	commitRuleToggle(t, e, true) // stages without a complaint about pf.conf
	if e.read("/etc/pf.conf") == older {
		t.Error("pf.conf wasn't rewritten by the current generator")
	}
}

// A real edit is still one.
func TestHandEditAfterCommitIsOutside(t *testing.T) {
	e := newEnv(t, time.Minute)
	commitRuleToggle(t, e, false)
	p := filepath.Join(e.root, "etc/pf.conf")
	if err := os.WriteFile(p, []byte(e.read("/etc/pf.conf")+"pass in all\n"), 0600); err != nil {
		t.Fatal(err)
	}
	m := e.live().Model
	m.Firewall.Rules[0].Description += " (edited)"
	_, err := e.m.Stage(StageRequest{Base: e.live().Version, Model: m})
	if code(err) != CodeModifiedOutside {
		t.Fatalf("hand edit not noticed: %v", err)
	}
}

// After a revert, OPF last wrote the old copy back; the file matching it
// isn't an outside change, and an edit after it is.
func TestAfterRevert(t *testing.T) {
	e := newEnv(t, time.Minute)
	commitRuleToggle(t, e, false)
	m := e.live().Model
	m.Firewall.Rules[0].Description += " (to revert)"
	st, err := e.m.Stage(StageRequest{Base: e.live().Version, Model: m})
	if err != nil {
		t.Fatal(err)
	}
	c, err := e.m.Commit(CommitRequest{Staged: st.Version})
	if err != nil || c.Status != "pending" {
		t.Fatalf("commit: %+v %v", c, err)
	}
	if _, err := e.m.Revert(c.ID); err != nil {
		t.Fatal(err)
	}
	commitRuleToggle(t, e, true) // no complaint: pf.conf is what the revert put back

	p := filepath.Join(e.root, "etc/pf.conf")
	if err := os.WriteFile(p, []byte(e.read("/etc/pf.conf")+"pass in all\n"), 0600); err != nil {
		t.Fatal(err)
	}
	m = e.live().Model
	m.Firewall.Rules[0].Description += " (again)"
	if _, err := e.m.Stage(StageRequest{Base: e.live().Version, Model: m}); code(err) != CodeModifiedOutside {
		t.Errorf("edit after a revert not noticed: %v", err)
	}
}
