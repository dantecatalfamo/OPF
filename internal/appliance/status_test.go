package appliance

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dantecatalfamo/OPF/internal/pf"
)

// captured answers commands with output captured on OpenBSD
// (internal/sysinfo/testdata), and fails the rest.
type captured struct {
	files map[string]string // command line → fixture
	calls atomic.Int32
}

func (c *captured) Run(_ context.Context, argv ...string) ([]byte, error) {
	c.calls.Add(1)
	name, ok := c.files[strings.Join(argv, " ")]
	if !ok {
		return []byte("not captured\n"), errors.New("exit status 1")
	}
	return os.ReadFile(filepath.Join("..", "sysinfo", "testdata", "openbsd-7.9", name))
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
