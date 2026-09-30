package appliance

import (
	"strings"
	"testing"
	"time"

	"github.com/dantecatalfamo/OPF/internal/pf"
	"github.com/dantecatalfamo/OPF/internal/sysinfo"
)

func TestDNSStatsFromOutput(t *testing.T) {
	e := newEnv(t, time.Minute)
	c := &captured{files: map[string]string{
		"unbound-control -c /var/unbound/etc/unbound.conf stats_noreset": "unbound-control_stats_noreset.txt",
		"ps -A -o rss=,comm=": "ps_-A_-o_rss_comm.txt",
	}}
	e.m.Runner = c
	s, err := e.m.DNSStats()
	if err != nil {
		t.Fatal(err)
	}
	if !s.Enabled || len(s.Errors) != 0 || s.Stats == nil || s.Stats.Queries != 8 || s.Stats.Blocked() != 3 {
		t.Fatalf("got %+v", s)
	}
	// The same counters twice: none a second, not a made-up figure.
	if s.QueriesPerSec == nil || *s.QueriesPerSec != 0 || s.BlockedPerSec == nil || *s.BlockedPerSec != 0 {
		t.Errorf("rates %v %v", s.QueriesPerSec, s.BlockedPerSec)
	}
	if s.MemoryBytes != 782744*1024 {
		t.Errorf("memory %d", s.MemoryBytes)
	}

	// unbound not answering is said, not an error.
	e.m.Runner = &captured{}
	e.m.dnsCounters = rate[sysinfo.UnboundStats]{}
	if s, err := e.m.DNSStats(); err != nil || s.Stats != nil || len(s.Errors) != 1 {
		t.Errorf("not running: %+v %v", s, err)
	}

	// With the resolver off nothing is read.
	m := e.live().Model
	m.DNS.Enabled = false
	e.m.Runner = e.run
	if err := stageCommit(t, e, m); err != nil {
		t.Fatal(err)
	}
	c = &captured{}
	e.m.Runner = c
	if s, err := e.m.DNSStats(); err != nil || s.Enabled || len(s.Errors) != 0 || c.calls.Load() != 0 {
		t.Errorf("off: %+v %v, %d calls", s, err, c.calls.Load())
	}
}

func TestDNSBlockedTally(t *testing.T) {
	now := time.Date(2026, 9, 29, 17, 0, 0, 0, time.UTC)
	hit := func(zone, action, name string, min int) sysinfo.RPZHit {
		return sysinfo.RPZHit{Time: now.Add(time.Duration(min) * time.Minute), Zone: zone, Trigger: "*." + name, Action: action, Client: "192.0.2.1", Name: name, Type: "A"}
	}
	list := pf.DNSListLogName("ads")
	hits := []sysinfo.RPZHit{
		hit("someone-else", "rpz-nxdomain", "not.ours.example", 0), // not OPF's zone: not counted, not the start
		hit(list, "rpz-local-data", "a.example", 1),
		hit(list, "rpz-local-data", "b.example", 2),
		hit(list, "rpz-local-data", "a.example", 3),
		hit(pf.OwnLogName, "rpz-nxdomain", "a.example", 4),
		hit(pf.OwnLogName, "rpz-passthru", "ok.example", 5),
		// Anyone on the network can ask for anything: a name that isn't
		// one is counted but not offered.
		hit(list, "rpz-local-data", "bad name\x1b[31m.example", 6),
	}
	var res DNSBlocked
	res.ByList = map[string]int{}
	res.tally(hits, 1)
	if res.Since == nil || !res.Since.Equal(now.Add(time.Minute)) {
		t.Errorf("since %v", res.Since)
	}
	if res.Blocked != 5 || res.Own != 1 || res.ByList["ads"] != 4 || res.Allowed != 1 {
		t.Errorf("counts %+v", res)
	}
	if len(res.Names) != 1 {
		t.Fatalf("names %+v", res.Names)
	}
	n := res.Names[0]
	// Last blocked by your own entry, which has no list.
	if n.Name != "a.example" || n.Count != 3 || n.List != "" || !n.Last.Equal(now.Add(4*time.Minute)) {
		t.Errorf("top %+v", n)
	}
	for _, n := range res.Names {
		if strings.ContainsAny(n.Name, " \x1b") {
			t.Errorf("offered %q", n.Name)
		}
	}
}

func TestDNSBlockedFromLog(t *testing.T) {
	c := &captured{dir: "handwritten", files: map[string]string{"tail -n 20000 /var/log/daemon": "daemon_rpz.txt"}}
	m := &Manager{Runner: c}
	res, err := m.DNSBlocked()
	if err != nil || res.Error != "" {
		t.Fatal(err, res.Error)
	}
	// Six lines from OPF's zones blocked; one own name was let through;
	// the line with no zone name isn't OPF's.
	if res.Blocked != 6 || res.Allowed != 1 || res.Own != 1 || res.ByList["hagezi"] != 4 || res.ByList["oisd"] != 1 {
		t.Errorf("got %+v", res)
	}
	if len(res.Names) == 0 || res.Names[0].Name != "securepubads.g.doubleclick.net" || res.Names[0].Count != 3 || res.Names[0].List != "hagezi" || res.Names[0].Entry != "*.doubleclick.net" {
		t.Errorf("names %+v", res.Names)
	}
	if res, _ := (&Manager{Runner: &captured{}}).DNSBlocked(); res.Error == "" {
		t.Error("no error without the log")
	}
}

func TestCommitTimesResolverReload(t *testing.T) {
	e := newEnv(t, time.Minute)
	e.m.Fetcher = &fetch{body: "0.0.0.0 ads.example.com\n0.0.0.0 more.example.com\n"}
	if err := stageCommit(t, e, withDNSList(t, e, pf.BlockAnswerNull)); err != nil {
		t.Fatal(err)
	}
	var r *ResolverReload
	for i := 0; i < 100 && r == nil; i++ {
		time.Sleep(20 * time.Millisecond)
		r = e.m.lastReload()
	}
	// Two names from the list, one blocked and one allowed of your own.
	if r == nil || r.TimedOut || r.Names != 4 {
		t.Fatalf("reload %+v", r)
	}
	found := false
	for _, c := range e.run.commands() {
		found = found || c == "unbound-control -c /var/unbound/etc/unbound.conf status"
	}
	if !found {
		t.Errorf("didn't ask unbound: %q", e.run.commands())
	}
}
