package appliance

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dantecatalfamo/OPF/internal/pf"
)

// captured answers commands with output captured on OpenBSD
// (internal/sysinfo/testdata), and fails the rest.
type captured struct {
	dir   string            // default openbsd-7.9
	files map[string]string // command line → fixture
	calls atomic.Int32
	mu    sync.Mutex
	ran   []string
}

func (c *captured) Run(_ context.Context, argv ...string) ([]byte, error) {
	c.calls.Add(1)
	cmd := strings.Join(argv, " ")
	c.mu.Lock()
	c.ran = append(c.ran, cmd)
	c.mu.Unlock()
	name, ok := c.files[cmd]
	if !ok {
		return []byte("not captured\n"), errors.New("exit status 1")
	}
	if name == "" {
		return nil, nil
	}
	dir := c.dir
	if dir == "" {
		dir = "openbsd-7.9"
	}
	return os.ReadFile(filepath.Join("..", "sysinfo", "testdata", dir, name))
}

func TestSystemFromCapturedOutput(t *testing.T) {
	c := &captured{files: map[string]string{
		"sysctl kern.cp_time": "sysctl_kern_cp_time.txt",
		"vmstat -s":           "vmstat_-s.txt",
		"swapctl -lk":         "swapctl_-lk.txt",
		"df -kPl":             "df_-kP.txt",
		"sysctl hw.sensors":   "sysctl_hw_sensors.txt",
	}}
	m := &Manager{Runner: c}
	s, err := m.System()
	if err != nil {
		t.Fatal(err)
	}
	// The first sysctl call isn't captured as one file, so its part is
	// missing and says so; the rest is there.
	if len(s.Errors) != 1 || !strings.Contains(s.Errors[0], "sysctl") {
		t.Errorf("errors = %q", s.Errors)
	}
	if s.Memory == nil || s.Memory.Free != 668420*4096 {
		t.Errorf("memory = %+v", s.Memory)
	}
	if s.Swap == nil || s.Swap.Total != 2342760*1024 || len(s.Disks) != 9 || len(s.Sensors) != 3 {
		t.Errorf("swap %+v, %d disks, %d sensors", s.Swap, len(s.Disks), len(s.Sensors))
	}
	// The same counters twice: no time passed, so no CPU figure rather
	// than a made-up one.
	if s.CPU != nil {
		t.Errorf("cpu = %+v from identical readings", s.CPU)
	}
}

func TestInterfacesFromCapturedOutput(t *testing.T) {
	c := &captured{files: map[string]string{
		"ifconfig -A":  "ifconfig_-A.txt",
		"netstat -ibn": "netstat_-ibn.txt",
		"netstat -in":  "netstat_-in.txt",
	}}
	m := &Manager{Runner: c}
	res, err := m.Interfaces()
	if err != nil || len(res.Errors) != 0 {
		t.Fatal(err, res.Errors)
	}
	var vio *InterfaceState
	for i := range res.Interfaces {
		if res.Interfaces[i].Name == "vio0" {
			vio = &res.Interfaces[i]
		}
	}
	if vio == nil || vio.Counters == nil || vio.Counters.RxBytes != 127363 || vio.RxBps == nil || *vio.RxBps != 0 {
		t.Errorf("vio0 = %+v", vio)
	}
}

func TestRateSharesRecentReadings(t *testing.T) {
	var r rate[int]
	n := 0
	read := func() (int, error) { n++; return n * 10, nil }
	then, now, dt, err := r.sample(read)
	if err != nil || then != 10 || now != 20 || dt < time.Second || n != 2 {
		t.Fatalf("first sample: %d %d %v %v, %d reads", then, now, dt, err, n)
	}
	// Straight away: the same pair, no new reading.
	then, now, _, _ = r.sample(read)
	if then != 10 || now != 20 || n != 2 {
		t.Errorf("second sample: %d %d, %d reads", then, now, n)
	}
}

func TestGatewayTarget(t *testing.T) {
	m := &pf.Model{Interfaces: []pf.Iface{{ID: "wan", Device: "em0"}}}
	routes := []RouteEntry{{Destination: "default", Gateway: "203.0.113.1", Iface: "em0"}}
	for _, tc := range []struct {
		g    pf.Gateway
		want string
	}{
		{pf.Gateway{Address: "10.0.0.1", Monitor: "9.9.9.9"}, "9.9.9.9"},
		{pf.Gateway{Address: "10.0.0.1"}, "10.0.0.1"},
		{pf.Gateway{Address: "dhcp", Iface: "wan"}, "203.0.113.1"},
		{pf.Gateway{Address: "dhcp", Iface: "other"}, "invalid IP"},
		// A monitor that isn't an address is never passed to ping.
		{pf.Gateway{Address: "dhcp", Iface: "other", Monitor: "-f"}, "invalid IP"},
	} {
		if got := gatewayTarget(tc.g, m, routes).String(); got != tc.want {
			t.Errorf("%+v: got %s, want %s", tc.g, got, tc.want)
		}
	}
}

func TestKillState(t *testing.T) {
	c := &captured{files: map[string]string{"pfctl -k id -k 6505b0d400000001/1c9d3f2a": ""}}
	m := &Manager{Runner: c}
	if err := m.KillState(KillStateRequest{ID: "6505b0d400000001", CreatorID: "1c9d3f2a"}); err != nil {
		t.Fatal(err)
	}
	// Anything else is refused before pfctl sees it.
	for _, bad := range []KillStateRequest{
		{ID: "6505b0d40000001", CreatorID: "1c9d3f2a"},
		{ID: "6505B0D400000001", CreatorID: "1c9d3f2a"},
		{ID: "6505b0d400000001", CreatorID: "1c9d3f2a/0"},
		{ID: "-f /etc/pf.co", CreatorID: "1c9d3f2a"},
		{ID: "6505b0d400000001", CreatorID: ""},
	} {
		if err := m.KillState(bad); code(err) != CodeInvalid {
			t.Errorf("%+v: %v", bad, err)
		}
	}
	if len(c.ran) != 1 {
		t.Errorf("ran %q", c.ran)
	}
}

func TestRuleCountersByLabel(t *testing.T) {
	c := &captured{dir: "handwritten", files: map[string]string{"pfctl -vv -s rules": "pfctl_-vv_-s_rules.txt"}}
	res, err := (&Manager{Runner: c}).RuleCounters()
	if err != nil || res.Error != "" {
		t.Fatal(err, res.Error)
	}
	// The anti-lockout rule was expanded into two, one per port.
	if got := res.Labels["opf:builtin:anti-lockout"]; got != (RuleCounter{Evaluations: 18320, Packets: 5021, Bytes: 612345, States: 2}) {
		t.Errorf("anti-lockout: %+v", got)
	}
	// Labels that aren't OPF's are left out.
	if _, ok := res.Labels["has no opf prefix"]; ok || len(res.Labels) != 6 {
		t.Errorf("labels: %v", res.Labels)
	}
}

func TestFirewallLogLabelsOnlySinceLastChange(t *testing.T) {
	e := newEnv(t, time.Minute)
	e.m.Runner = &captured{dir: "handwritten", files: map[string]string{
		"tcpdump -n -e -ttt -r /var/log/pflog": "tcpdump_pflog.txt",
		"pfctl -vv -s rules":                   "pfctl_-vv_-s_rules.txt",
	}}
	// No history: every entry is labelled from the loaded rules.
	log, err := e.m.FirewallLog()
	if err != nil || len(log.Entries) != 8 {
		t.Fatal(err, len(log.Entries))
	}
	byRule := func(l *FirewallLog, rule int) []string {
		var out []string
		for _, x := range l.Entries {
			if x.Rule == rule && x.Anchor == "" {
				out = append(out, x.Label)
			}
		}
		return out
	}
	if got := byRule(log, 5); len(got) != 1 || got[0] != "opf:builtin:block-bogons" {
		t.Errorf("rule 5: %q", got)
	}
	// The entry in an anchor is numbered in the anchor, not the main
	// ruleset, so it gets no label.
	for _, x := range log.Entries {
		if x.Anchor != "" && x.Label != "" {
			t.Errorf("anchored entry labelled %q", x.Label)
		}
	}
	// After a commit, the entries (from before it) have none.
	m := sample(t)
	disableLANRule(m)
	staged, err := e.m.Stage(StageRequest{Base: e.live().Version, Model: m})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.m.Commit(CommitRequest{Staged: staged.Version, Message: "Tighten LAN"}); err != nil {
		t.Fatal(err)
	}
	log, _ = e.m.FirewallLog()
	for _, x := range log.Entries {
		if x.Label != "" {
			t.Errorf("entry from %v, before the commit, labelled %q", x.Time, x.Label)
		}
	}
	if log.RulesSince == nil {
		t.Error("no rulesSince")
	}
}

// Ending a connection changes the system, so it goes through Actions
// (the dry runner under -dry), not the runner that reads state.
func TestKillStateUsesActions(t *testing.T) {
	reads := &captured{files: map[string]string{}}
	acts := &captured{files: map[string]string{"pfctl -k id -k 6505b0d400000001/1c9d3f2a": ""}}
	m := &Manager{Runner: reads, Actions: acts}
	if err := m.KillState(KillStateRequest{ID: "6505b0d400000001", CreatorID: "1c9d3f2a"}); err != nil {
		t.Fatal(err)
	}
	if len(reads.ran) != 0 || len(acts.ran) != 1 {
		t.Errorf("reads ran %q, actions ran %q", reads.ran, acts.ran)
	}
}
