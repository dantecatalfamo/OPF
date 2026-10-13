package pf

import (
	"slices"
	"strings"
	"testing"
)

// aggregateLAN is the sample model with its LAN on aggr0, made of em1
// and em2, and the IoT VLAN carried on the aggregate.
func aggregateLAN(t *testing.T) *Model {
	t.Helper()
	m, _ := loadSampleModel(t)
	m.Interfaces[1].Device = "aggr0"
	m.Interfaces[1].Aggregate = &AggregateConfig{Ports: []string{"em1", "em2"}}
	m.Interfaces[2].VLAN.Parent = "aggr0"
	if errs := Validate(m); len(errs) > 0 {
		t.Fatal(errs)
	}
	return m
}

// An aggregate's ports are Ethernet ports that are nothing else; its
// settings are its driver's.
func TestAggregateValidation(t *testing.T) {
	for name, tc := range map[string]struct {
		edit func(m *Model)
		path string // "": valid
	}{
		"aggr":                  {func(m *Model) {}, ""},
		"passive, fast":         {func(m *Model) { a := m.Interfaces[1].Aggregate; a.LACPPassive, a.LACPFast = true, true }, ""},
		"no ports":              {func(m *Model) { m.Interfaces[1].Aggregate.Ports = nil }, "interfaces[1].aggregate.ports"},
		"a port twice":          {func(m *Model) { m.Interfaces[1].Aggregate.Ports = []string{"em1", "em1"} }, "interfaces[1].aggregate.ports[1]"},
		"a port that's the WAN": {func(m *Model) { m.Interfaces[1].Aggregate.Ports = []string{"em0", "em1"} }, "interfaces[1].aggregate.ports[0]"},
		"a tunnel as a port":    {func(m *Model) { m.Interfaces[1].Aggregate.Ports = []string{"em1", "wg5"} }, "interfaces[1].aggregate.ports[1]"},
		"a VLAN's parent as a port": {func(m *Model) {
			m.Interfaces[2].VLAN.Parent = "em2"
		}, "interfaces[1].aggregate.ports[1]"},
		"trunkproto on aggr": {func(m *Model) { m.Interfaces[1].Aggregate.Proto = TrunkFailover }, "interfaces[1].aggregate.proto"},
		"failover trunk": {func(m *Model) {
			m.Interfaces[1].Device, m.Interfaces[2].VLAN.Parent = "trunk0", "trunk0"
			m.Interfaces[1].Aggregate.Proto = TrunkFailover
		}, ""},
		"trunk without a proto": {func(m *Model) { m.Interfaces[1].Device, m.Interfaces[2].VLAN.Parent = "trunk0", "trunk0" }, "interfaces[1].aggregate.proto"},
		"trunk doing lacp": {func(m *Model) {
			m.Interfaces[1].Device, m.Interfaces[2].VLAN.Parent = "trunk0", "trunk0"
			m.Interfaces[1].Aggregate.Proto = "lacp"
		}, "interfaces[1].aggregate.proto"},
		"trunk with LACP settings": {func(m *Model) {
			m.Interfaces[1].Device, m.Interfaces[2].VLAN.Parent = "trunk0", "trunk0"
			m.Interfaces[1].Aggregate.Proto, m.Interfaces[1].Aggregate.LACPFast = TrunkFailover, true
		}, "interfaces[1].aggregate"},
		"trunk with an MTU": {func(m *Model) {
			m.Interfaces[1].Device, m.Interfaces[2].VLAN.Parent = "trunk0", "trunk0"
			m.Interfaces[1].Aggregate.Proto, m.Interfaces[1].MTU = TrunkFailover, ptrTo(9000)
		}, "interfaces[1].mtu"},
		"aggr with an MTU":           {func(m *Model) { m.Interfaces[1].MTU = ptrTo(9000) }, ""},
		"a port in two aggregates":   {func(m *Model) { addAggregate(m, "aggr1", "em2") }, "interfaces[5].aggregate.ports[0]"},
		"aggr0 without its settings": {func(m *Model) { m.Interfaces[1].Aggregate = nil }, "interfaces[1].aggregate"},
		"ports on a port":            {func(m *Model) { m.Interfaces[1].Device = "em3" }, "interfaces[1].device"},
		"a VLAN on an aggregate OPF doesn't have": {func(m *Model) {
			m.Interfaces[2].VLAN.Parent = "aggr7"
		}, "interfaces[2].vlan.parent"},
	} {
		m := aggregateLAN(t)
		tc.edit(m)
		errs := Validate(m)
		has := slices.ContainsFunc(errs, func(e FieldError) bool { return e.Path == tc.path })
		if tc.path == "" && len(errs) > 0 || tc.path != "" && !has {
			t.Errorf("%s: %v", name, errs)
		}
	}
}

func addAggregate(m *Model, dev string, ports ...string) {
	m.Interfaces = append(m.Interfaces, Iface{
		ID: dev, Name: dev, Device: dev, Role: RoleOPT, Enabled: true,
		IPv4: IPv4Config{Mode: IPv4None}, IPv6: IPv6None,
		Aggregate: &AggregateConfig{Ports: ports},
	})
}

// An aggregate's file sets its driver up and adds its ports, after
// taking out ones it no longer has; each port's file only brings it up.
func TestAggregateFiles(t *testing.T) {
	m := aggregateLAN(t)
	got, _ := genFile(m, "/etc/hostname.aggr0")
	for _, want := range []string{
		"lacpmode active\nlacptimeout slow\n",
		`!for p in $(ifconfig $if | awk '$2 == "port" { print $1 }'); do case " em1 em2 " in *" $p "*) ;; *) ifconfig $if -trunkport $p ;; esac; done` + "\n",
		"trunkport em1\ntrunkport em2\ndescription \"LAN\"\n",
		"inet 192.168.1.1/24\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("hostname.aggr0 lacks %q:\n%s", want, got)
		}
	}
	// netstart reads lines with read, without -r.
	if strings.Contains(got, `\`) {
		t.Errorf("hostname.aggr0 has a backslash:\n%s", got)
	}
	for _, port := range []string{"em1", "em2"} {
		if got, _ := genFile(m, "/etc/hostname."+port); !strings.HasSuffix(got, "description \"Port of LAN\"\nup\n") || strings.Contains(got, "inet") {
			t.Errorf("hostname.%s:\n%s", port, got)
		}
	}
	if got, _ := genFile(m, "/etc/hostname.vlan20"); !strings.Contains(got, "vnetid 20 parent aggr0\n") {
		t.Errorf("hostname.vlan20:\n%s", got)
	}
	// pf names the aggregate, never its ports.
	if conf := GeneratePfConf(m); !strings.Contains(conf, `lan = "aggr0"`) || strings.Contains(conf, "em1") || strings.Contains(conf, "em2") {
		t.Errorf("pf.conf:\n%s", conf)
	}

	m.Interfaces[1].Device, m.Interfaces[2].VLAN.Parent = "trunk0", "trunk0"
	m.Interfaces[1].Aggregate.Proto = TrunkFailover
	got, _ = genFile(m, "/etc/hostname.trunk0")
	if !strings.Contains(got, "trunkproto failover\n!for") || strings.Contains(got, "lacp") {
		t.Errorf("hostname.trunk0:\n%s", got)
	}
}

// Taking over a machine reads its aggregates, their ports written by
// OPF from then on; one OPF can't write as it is stays as it is, ports
// and all.
func TestImportAggregates(t *testing.T) {
	src := ImportSources{Files: map[string]string{
		"/etc/hostname.em0":    "inet autoconf\nup\n",
		"/etc/hostname.em1":    "up\n",
		"/etc/hostname.em2":    "description \"to the switch\"\nup\n",
		"/etc/hostname.aggr0":  "trunkport em1\ntrunkport em2\nlacptimeout fast\ninet 192.168.1.1/24\nup\n",
		"/etc/hostname.vlan20": "vnetid 20 parent aggr0\ninet 192.168.20.1/24\nup\n",
		"/etc/hostname.em3":    "up\n",
		"/etc/hostname.em4":    "up\n",
		"/etc/hostname.trunk0": "trunkproto failover trunkport em3 trunkport em4\ninet 10.0.0.1/24\nup\n",
		"/etc/hostname.em5":    "inet 10.5.0.1/24\nup\n",
		"/etc/hostname.trunk1": "trunkproto lacp trunkport em5\nup\n",
	}, Egress: []string{"em0"}}
	res := Import(src, ImportOptions{})
	m := res.Model
	byDev := map[string]Iface{}
	for _, i := range m.Interfaces {
		byDev[i.Device] = i
	}
	if a := byDev["aggr0"].Aggregate; a == nil || !slices.Equal(a.Ports, []string{"em1", "em2"}) || !a.LACPFast || a.LACPPassive || a.Proto != "" {
		t.Errorf("aggr0: %+v", a)
	}
	if a := byDev["trunk0"].Aggregate; a == nil || !slices.Equal(a.Ports, []string{"em3", "em4"}) || a.Proto != TrunkFailover {
		t.Errorf("trunk0: %+v", a)
	}
	for _, dev := range []string{"em1", "em2", "em3", "em4", "trunk1", "em5"} {
		if _, ok := byDev[dev]; ok {
			t.Errorf("%s is an interface of its own", dev)
		}
	}
	if byDev["vlan20"].VLAN.Parent != "aggr0" {
		t.Errorf("vlan20: %+v", byDev["vlan20"].VLAN)
	}
	left := map[string]bool{}
	for _, n := range res.Notes {
		if n.Kind == NoteLeft {
			left[n.File] = true
		}
	}
	if !left["/etc/hostname.trunk1"] || !left["/etc/hostname.em5"] || left["/etc/hostname.aggr0"] || left["/etc/hostname.em1"] {
		t.Errorf("left: %v", left)
	}
	for _, e := range Validate(m) {
		t.Errorf("invalid: %v", e)
	}
	// The trunk's own file says what it did.
	if got, _ := genFile(m, "/etc/hostname.trunk0"); !strings.Contains(got, "trunkproto failover\n") || !strings.Contains(got, "trunkport em3\ntrunkport em4\n") {
		t.Errorf("hostname.trunk0:\n%s", got)
	}
}

// Ports of a trunk without trunkproto use trunk(4)'s default, which
// OPF writes out.
func TestImportTrunkDefault(t *testing.T) {
	src := ImportSources{Files: map[string]string{
		"/etc/hostname.trunk0": "trunkport em1 trunkport em2\ninet 10.0.0.1/24\nup\n",
	}}
	m := Import(src, ImportOptions{}).Model
	if len(m.Interfaces) != 1 || m.Interfaces[0].Aggregate == nil || m.Interfaces[0].Aggregate.Proto != TrunkRoundRobin {
		t.Errorf("%+v", m.Interfaces)
	}
	for _, e := range Validate(m) {
		t.Errorf("invalid: %v", e)
	}
}

// A port two aggregates both list leaves both as they are.
func TestImportSharedPort(t *testing.T) {
	src := ImportSources{Files: map[string]string{
		"/etc/hostname.aggr0":  "trunkport em1\nup\n",
		"/etc/hostname.trunk0": "trunkproto failover trunkport em1\nup\n",
		"/etc/hostname.em1":    "up\n",
	}}
	m := Import(src, ImportOptions{}).Model
	if len(m.Interfaces) != 0 {
		t.Errorf("%+v", m.Interfaces)
	}
}
