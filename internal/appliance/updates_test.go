package appliance

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func waitChecked(t *testing.T, m *Manager) *UpdatesStatus {
	t.Helper()
	for range 200 {
		if u, _ := m.Updates(); u.CheckedAt != nil && !u.Checking {
			return u
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("no check finished")
	return nil
}

func TestUpdateChecker(t *testing.T) {
	e := newEnv(t, time.Minute)
	c := &captured{dir: "openbsd-other", files: map[string]string{"syspatch -c": "syspatch_-c.txt"}}
	e.m.Runner = c
	if u, _ := e.m.Updates(); !u.Checking || u.CheckedAt != nil {
		t.Errorf("before any check: %+v", u)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go e.m.RunUpdateChecker(ctx)
	u := waitChecked(t, e.m)
	cancel()
	if len(u.Patches) != 16 || u.Patches[0] != "015_smtpd" || c.calls.Load() != 1 {
		t.Fatalf("checked: %+v, %d runs", u, c.calls.Load())
	}
	// "Check again" right after a check does nothing.
	e.m.CheckUpdates()
	if c.calls.Load() != 1 {
		t.Error("checked again within a minute")
	}

	// A restart shows the saved answer at once, and doesn't check again
	// while it's fresh.
	m2, _ := New(e.m.store)
	c2 := &captured{dir: "openbsd-other", files: map[string]string{"syspatch -c": "syspatch_-c.txt"}}
	m2.Runner = c2
	ctx2, cancel2 := context.WithCancel(context.Background())
	go m2.RunUpdateChecker(ctx2)
	time.Sleep(100 * time.Millisecond)
	cancel2()
	if u, _ := m2.Updates(); len(u.Patches) != 16 || u.Checking || c2.calls.Load() != 0 {
		t.Errorf("after a restart: %+v, %d runs", u, c2.calls.Load())
	}

	// A saved file that's been tampered with: only patch names survive.
	path := e.m.store.StatePath(updatesFile)
	data, _ := os.ReadFile(path)
	os.WriteFile(path, []byte(strings.Replace(string(data), `"015_smtpd"`, `"<script>","../x","015_smtpd"`, 1)), 0600)
	m3, _ := New(e.m.store)
	m3.loadUpdates()
	if u, _ := m3.Updates(); len(u.Patches) != 16 || u.Patches[0] != "015_smtpd" {
		t.Errorf("tampered: %v", u.Patches)
	}
}

func TestUpdatesDue(t *testing.T) {
	now := time.Now()
	old := now.Add(-3 * time.Hour)
	recent := now.Add(-20 * time.Minute)
	for _, c := range []struct {
		u    *UpdatesStatus
		want bool
	}{
		{nil, true},
		{&UpdatesStatus{CheckedAt: &recent}, false},
		{&UpdatesStatus{CheckedAt: &old}, true},
		{&UpdatesStatus{CheckedAt: &recent, Error: "no network"}, true}, // retried sooner
	} {
		if got := updatesDue(c.u); got != c.want {
			t.Errorf("%+v: %v", c.u, got)
		}
	}
}
