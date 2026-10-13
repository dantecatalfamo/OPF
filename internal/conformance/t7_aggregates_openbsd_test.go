package conformance

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/dantecatalfamo/OPF/internal/pf"
)

// TestAggregates applies the hostname.if files OPF writes for aggr(4)
// and trunk(4) with the release's netstart, as a commit does, on ports
// of their own (the models' spare ports are in use by then): the ports
// join, one dropped from the model leaves, LACP's settings change both
// ways, and a port moving from an aggr to a trunk is let go by the
// first. It relies on ifconfig's "trunk: trunkdev" line on a port and
// its "<port> port <flags>" lines on an aggregate.
func TestAggregates(t *testing.T) {
	owns(t)
	const aggr, trunk = "aggr7", "trunk7"
	ports := []string{"vether8", "vether9"}
	cleanup := func() {
		for _, dev := range append([]string{"vlan67", aggr, trunk}, ports...) {
			run("ifconfig", dev, "destroy")
			os.Remove("/etc/hostname." + dev)
		}
	}
	cleanup()
	t.Cleanup(cleanup)

	m := pf.EmptyModel()
	iface := func(dev string, a *pf.AggregateConfig, addr string) *pf.Iface {
		return &pf.Iface{ID: dev, Name: "Bond " + dev, Device: dev, Role: pf.RoleOPT, Enabled: true,
			IPv4: static(addr, 24), IPv6: pf.IPv6None, Aggregate: a}
	}
	apply := func(files map[string]string, devs ...string) {
		t.Helper()
		for dev, content := range files {
			if err := os.WriteFile("/etc/hostname."+dev, []byte(content), 0640); err != nil {
				t.Fatal(err)
			}
		}
		// As HostnameApply does: netstart, one interface at a time, in
		// netstart's order.
		for _, dev := range devs {
			if out, code := run("sh", "/etc/netstart", dev); code != 0 || strings.Contains(out, "ifconfig:") {
				t.Errorf("netstart %s: exit %d:\n%s\n--- the file:\n%s", dev, code, out, numbered(files[dev]))
			}
		}
	}
	portsOf := func(dev string) []string {
		var out []string
		for _, l := range strings.Split(mustT(&recorder{T: t}, "ifconfig", dev), "\n") {
			if f := strings.Fields(l); len(f) >= 2 && f[1] == "port" {
				out = append(out, f[0])
			}
		}
		slices.Sort(out)
		return out
	}
	trunkdev := func(port string) string {
		for _, l := range strings.Split(mustT(&recorder{T: t}, "ifconfig", port), "\n") {
			if f := strings.Fields(l); len(f) == 3 && f[0] == "trunk:" && f[1] == "trunkdev" {
				return f[2]
			}
		}
		return ""
	}
	filesFor := func(i *pf.Iface) map[string]string {
		m.Interfaces = []pf.Iface{*i}
		files := map[string]string{i.Device: pf.GenerateHostnameIf(i, m)}
		for _, p := range pf.AggregatePorts(m) {
			files[p.Device] = pf.GenerateAggregatePort(p)
		}
		return files
	}

	// An aggr of both ports, passive and fast, with a VLAN on it.
	a := iface(aggr, &pf.AggregateConfig{Ports: ports, LACPPassive: true, LACPFast: true}, "172.16.67.1")
	files := filesFor(a)
	vlan := pf.Iface{ID: "v67", Name: "VLAN 67", Device: "vlan67", Role: pf.RoleOPT, Enabled: true, IPv4: static("172.16.68.1", 24), IPv6: pf.IPv6None,
		VLAN: &pf.VLANConfig{Parent: aggr, Tag: 67}}
	files["vlan67"] = pf.GenerateHostnameIf(&vlan, m)
	apply(files, append(slices.Clone(ports), aggr, "vlan67")...)
	if got := portsOf(aggr); !slices.Equal(got, ports) {
		t.Errorf("%s's ports: %v, want %v", aggr, got, ports)
	}
	for _, p := range ports {
		if d := trunkdev(p); d != aggr {
			t.Errorf("%s's trunkdev: %q", p, d)
		}
	}
	out := mustT(&recorder{T: t}, "ifconfig", aggr)
	if !strings.Contains(out, "trunkproto lacp") || !strings.Contains(out, "172.16.67.1") {
		t.Errorf("ifconfig %s:\n%s", aggr, out)
	}
	if out := mustT(&recorder{T: t}, "ifconfig", "vlan67"); !strings.Contains(out, "encap: vnetid 67 parent "+aggr) {
		t.Errorf("ifconfig vlan67:\n%s", out)
	}

	// The second port dropped, and LACP back to its defaults: it leaves
	// when only the aggr is applied again, and isn't a port of anything.
	a.Aggregate = &pf.AggregateConfig{Ports: ports[:1]}
	files = filesFor(a)
	apply(map[string]string{aggr: files[aggr]}, aggr)
	if got := portsOf(aggr); !slices.Equal(got, ports[:1]) {
		t.Errorf("%s's ports after dropping %s: %v", aggr, ports[1], got)
	}
	if d := trunkdev(ports[1]); d != "" {
		t.Errorf("%s still in %s", ports[1], d)
	}

	// A failover trunk of both: the port still in the aggr moves.
	tr := iface(trunk, &pf.AggregateConfig{Ports: ports, Proto: pf.TrunkFailover}, "172.16.69.1")
	files = filesFor(tr)
	apply(files, trunk)
	if got := portsOf(trunk); !slices.Equal(got, ports) {
		t.Errorf("%s's ports: %v, want %v", trunk, got, ports)
	}
	if got := portsOf(aggr); len(got) != 0 {
		t.Errorf("%s kept %v", aggr, got)
	}
	out = mustT(&recorder{T: t}, "ifconfig", trunk)
	if !strings.Contains(out, "trunkproto failover") || !strings.Contains(out, ports[0]+" port master") {
		t.Errorf("ifconfig %s:\n%s", trunk, out)
	}
	save(t, "ifconfig_trunk.txt", out)
}
