package appliance

import (
	"context"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dantecatalfamo/OPF/internal/metrics"
	"github.com/dantecatalfamo/OPF/internal/pf"
)

func TestCollectorRate(t *testing.T) {
	c := &collector{prev: map[string]reading{}}
	t0 := time.Now()
	if _, ok := c.rate("x", 100, t0); ok {
		t.Error("a rate from one reading")
	}
	if r, ok := c.rate("x", 200, t0.Add(10*time.Second)); !ok || r != 10 {
		t.Errorf("growth: %v %v", r, ok)
	}
	// A counter that went backwards (a reload) starts over.
	if _, ok := c.rate("x", 50, t0.Add(20*time.Second)); ok {
		t.Error("a rate across a reset")
	}
	if r, ok := c.rate("x", 150, t0.Add(30*time.Second)); !ok || r != 10 {
		t.Errorf("after the reset: %v %v", r, ok)
	}
	// So does one after a long gap (OPF stopped a while).
	if _, ok := c.rate("x", 1e6, t0.Add(time.Hour)); ok {
		t.Error("a rate across a gap")
	}
}

// growing answers the collector's commands with captured output, the
// em0 byte counters and pf's blocked packets growing a fixed amount on
// each call.
type growing struct {
	mu     sync.Mutex
	calls  map[string]int
	cmds   []string
	failed bool
}

func (g *growing) Run(_ context.Context, argv ...string) ([]byte, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	cmd := strings.Join(argv, " ")
	g.cmds = append(g.cmds, cmd)
	g.calls[cmd]++
	n := uint64(g.calls[cmd])
	file := func(name string) string {
		b, err := os.ReadFile(filepath.Join("..", "sysinfo", "testdata", "openbsd-7.9", name))
		if err != nil {
			panic(err)
		}
		return string(b)
	}
	switch cmd {
	case "netstat -ibn":
		return fmt.Appendf(nil, "Name    Mtu   Network     Address               Ibytes     Obytes\nem0     1500  <Link>      52:54:00:12:34:56 %d %d\n", 1000*n, 500*n), nil
	case "netstat -in":
		return []byte("Name    Mtu   Network     Address              Ipkts Ifail    Opkts Ofail Colls\nem0     1500  <Link>      52:54:00:12:34:56    10     0       10     0     0\n"), nil
	case "sysctl kern.cp_time vm.loadavg hw.physmem":
		return []byte(file("sysctl_kern_cp_time.txt") + file("sysctl_vm_loadavg.txt") + file("sysctl_hw_physmem.txt")), nil
	case "vmstat -s":
		return []byte(file("vmstat_-s.txt")), nil
	case "pfctl -v -s info":
		return []byte(file("pfctl_-v_-s_info.txt")), nil
	case "pfctl -vv -s rules":
		b, err := os.ReadFile(filepath.Join("..", "sysinfo", "testdata", "handwritten", "pfctl_-vv_-s_rules.txt"))
		if err != nil {
			panic(err)
		}
		return b, nil
	case "unbound-control -c /var/unbound/etc/unbound.conf stats_noreset":
		return fmt.Appendf(nil, "total.num.queries=%d\ntotal.num.cachehits=%d\ntotal.num.cachemiss=%d\ntime.up=%d\nnum.rpz.action.rpz-local-data=%d\n", 100*n, 75*n, 25*n, 10*n, 5*n), nil
	}
	return []byte("not captured\n"), fmt.Errorf("exit status 1")
}

func lastPoint(t *testing.T, st *metrics.Store, key string) (float64, bool) {
	t.Helper()
	r, ok := st.Query(key, time.Now().Add(-time.Minute), time.Now().Add(time.Second), 0)
	if !ok {
		return 0, false
	}
	for i := len(r.Avg) - 1; i >= 0; i-- {
		if r.Avg[i] != nil {
			return *r.Avg[i], true
		}
	}
	return 0, false
}

func TestSample(t *testing.T) {
	e := newEnv(t, time.Minute)
	g := &growing{calls: map[string]int{}}
	e.m.Runner = g
	t0 := time.Now()
	e.m.sample(t0)
	st := e.m.metricsStore()
	// One reading: levels, but no rates yet.
	if v, ok := lastPoint(t, st, SeriesPfStates); !ok || v != 6 {
		t.Errorf("pf states %v %v", v, ok)
	}
	if v, ok := lastPoint(t, st, SeriesMemory); !ok || v <= 0 {
		t.Errorf("memory %v %v", v, ok)
	}
	if _, ok := lastPoint(t, st, ifaceSeries("em0", "rx")); ok {
		t.Error("a rate from one reading")
	}
	// The collector times readings as it makes them; wait for a second
	// so the rate is over a real interval.
	time.Sleep(1100 * time.Millisecond)
	e.m.sample(t0.Add(10 * time.Second))
	rx, ok := lastPoint(t, st, ifaceSeries("em0", "rx"))
	// 1000 bytes more over about a second: about 8000 bits a second.
	if !ok || rx < 6000 || rx > 8000 {
		t.Errorf("em0 rx %v %v", rx, ok)
	}
	q, ok := lastPoint(t, st, SeriesDNSQueries)
	hit, hok := lastPoint(t, st, SeriesDNSCacheHit)
	if !ok || q < 70 || q > 100 || !hok || math.Abs(hit-75) > 1e-9 {
		t.Errorf("dns %v %v, cache hit %v %v", q, ok, hit, hok)
	}
	if b, ok := lastPoint(t, st, SeriesDNSBlocked); !ok || b <= 0 {
		t.Errorf("dns blocked %v %v", b, ok)
	}

	// Rules' packets a second, by label, from the slower round.
	e.m.sampleSlow(e.m.collect)
	time.Sleep(1100 * time.Millisecond)
	e.m.sampleSlow(e.m.collect)
	if v, ok := lastPoint(t, st, "pf.builtin.anti-lockout"); !ok || v != 0 {
		t.Errorf("anti-lockout packets %v %v", v, ok)
	}
	// Every enabled DHCP network has a count of leases, none here.
	for _, s := range e.live().Model.DHCP {
		if v, ok := lastPoint(t, st, dhcpSeries(s.Iface)); s.Enabled && (!ok || v != 0) {
			t.Errorf("dhcp %s: %v %v", s.Iface, v, ok)
		}
	}

	// Metrics answers for what was asked, and lists what's kept.
	res, err := e.m.Metrics(MetricsRequest{Series: []string{SeriesPfStates, "if.nope.rx"}, Range: 3600})
	if err != nil || res.Series[SeriesPfStates] == nil || res.Series["if.nope.rx"] != nil || len(res.Known) < 5 {
		t.Errorf("metrics %+v %v", res, err)
	}
	for _, bad := range []MetricsRequest{
		{Series: []string{SeriesPfStates}, Range: 0},
		{Series: []string{SeriesPfStates}, Range: 100 * 24 * 3600},
		{Series: []string{"../etc"}, Range: 60},
		{Series: make([]string, MaxMetricsSeries+1), Range: 60},
		{Series: []string{SeriesPfStates}, Range: 60, Step: 120},
	} {
		if _, err := e.m.Metrics(bad); err == nil {
			t.Errorf("took %+v", bad)
		}
	}

	// Saved and read back when the collector starts again.
	if err := e.m.SaveMetrics(); err != nil {
		t.Fatal(err)
	}
	m2, err := New(e.m.store)
	if err != nil {
		t.Fatal(err)
	}
	m2.Runner = &growing{calls: map[string]int{}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m2.RunCollector(ctx); close(done) }()
	time.Sleep(200 * time.Millisecond)
	cancel()
	<-done
	if v, ok := lastPoint(t, m2.metricsStore(), ifaceSeries("em0", "rx")); !ok || v != rx {
		t.Errorf("after a restart: %v %v, want %v", v, ok, rx)
	}
}

func TestPseudoIface(t *testing.T) {
	for name, want := range map[string]bool{"lo0": true, "enc0": true, "pflog0": true, "pfsync0": true, "em0": false, "lo": false, "local0": false, "vlan20": false, "wg0": false} {
		if pseudoIface(name) != want {
			t.Errorf("%s: %v", name, !want)
		}
	}
}

func TestGraphLimits(t *testing.T) {
	e := newEnv(t, time.Minute)
	one := 1
	m := e.live().Model
	m.System.Graphs = &pf.GraphLimits{Rules: &one}
	if err := stageCommit(t, e, m); err != nil {
		t.Fatal(err)
	}
	e.m.Runner = &growing{calls: map[string]int{}}
	for range 2 {
		e.m.sample(time.Now())
		e.m.sampleSlow(e.m.collect)
		time.Sleep(1100 * time.Millisecond)
	}
	var rules, ifaces int
	for _, k := range e.m.metricsStore().Keys() {
		switch {
		case strings.HasPrefix(k, "if."):
			ifaces++
		case strings.HasPrefix(k, "pf.") && strings.Count(k, ".") == 2:
			rules++
		}
	}
	// The handwritten ruleset has several labelled rules; one is kept,
	// and the interfaces have their own room.
	if rules != 1 || ifaces != 2 {
		t.Errorf("%d rule series, %d interface series: %v", rules, ifaces, e.m.metricsStore().Keys())
	}
	res, err := e.m.Metrics(MetricsRequest{Range: 60})
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range res.Groups {
		if g.Name == GroupRules && (g.Max != 1 || g.Items != 1 || !g.Refused || g.Default != GraphDefaults[GroupRules] || g.ItemBytes <= 0) {
			t.Errorf("rules group %+v", g)
		}
		if g.Name == GroupInterfaces && (g.Items != 1 || g.Refused || g.ItemBytes != 2*g.SeriesBytes) {
			t.Errorf("interfaces group %+v", g)
		}
	}
	// Out of range is refused when staged.
	big := pf.MaxGraphItems + 1
	m.System.Graphs = &pf.GraphLimits{Interfaces: &big}
	if _, err := e.m.Stage(StageRequest{Base: e.live().Version, Model: m}); err == nil {
		t.Error("took a cap past the limit")
	}
}
