package appliance

import (
	"testing"
	"time"
)

// Everything is listed whatever answers: OPF's own records from its
// files, the rest when the commands do.
func TestStorage(t *testing.T) {
	e := newEnv(t, time.Minute)
	m := e.live().Model
	m.System.NTPServers = []string{"other.example"}
	if err := stageCommit(t, e, m); err != nil {
		t.Fatal(err)
	}
	s, err := e.m.Storage()
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]StorageItem{}
	for _, it := range s.Items {
		by[it.ID] = it
	}
	for _, id := range []string{"graphs-firewall", "graphs-dns", "graphs-system", "graphs-interfaces", "graphs-rules", "events", "dns-activity", "history-entries", "history-bytes", "lists", "pf-states", "pf-tables", "pf-table-entries", "log-pflog", "log-daemon"} {
		if _, ok := by[id]; !ok {
			t.Errorf("no %s", id)
		}
	}
	if h := by["history-entries"]; h.Current == nil || *h.Current != 1 || h.Max != nil || h.Unbounded == "" {
		t.Errorf("history %+v", h)
	}
	if b := by["history-bytes"]; b.Current == nil || *b.Current == 0 {
		t.Errorf("history on disk %+v", b)
	}
	if d := by["dns-activity"]; !d.Off {
		t.Errorf("DNS activity isn't on in the sample: %+v", d)
	}
	// The firewall's and DNS's history each have their own row; fixed
	// ones say so, capped ones say where the cap is.
	for _, id := range []string{"graphs-firewall", "graphs-dns"} {
		if g := by[id]; g.Current == nil || g.Max != nil || g.Fixed == "" || len(g.Settings) != 0 {
			t.Errorf("%s %+v", id, g)
		}
	}
	if g := by["graphs-interfaces"]; len(g.Settings) != 1 || g.Settings[0].To != "/system/general#graphs" {
		t.Errorf("interfaces' graphs %+v", g)
	}
	if p := by["pf-states"]; len(p.Settings) != 1 || p.Settings[0].To != "/firewall/settings#connections" {
		t.Errorf("pf states' setting %+v", p.Settings)
	}
	// The test's runner answers nothing: pf's limits can't be read, and
	// it says so rather than guess.
	if p := by["pf-states"]; p.Max != nil || p.Current != nil || len(s.Errors) == 0 {
		t.Errorf("pf %+v, errors %v", p, s.Errors)
	}
}
