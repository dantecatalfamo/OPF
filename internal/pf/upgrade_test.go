package pf

import (
	"strings"
	"testing"
)

// An older model's interface gateway moves to Routing: into the
// interface's DHCP gateway, or a new one, never over a fixed one.
func TestUpgradeMovesInterfaceGateway(t *testing.T) {
	prefix := 24
	static := func(m *Model) *Iface {
		f := &m.Interfaces[0]
		f.IPv4 = IPv4Config{Mode: IPv4Static, Address: "203.0.113.10", Prefix: &prefix, Gateway: "203.0.113.1"}
		return f
	}
	defaultGW := func(m *Model) Gateway {
		for _, g := range m.Routing.Gateways {
			if g.ID == m.Routing.DefaultGateway {
				return g
			}
		}
		t.Fatal("no default gateway")
		return Gateway{}
	}

	// Into the interface's DHCP gateway, renamed.
	m, _ := loadSampleModel(t)
	f := static(m)
	for i := range m.Routing.Gateways {
		if m.Routing.Gateways[i].ID == m.Routing.DefaultGateway {
			m.Routing.Gateways[i] = Gateway{ID: "gw_wan", Name: "WAN_DHCP", Iface: f.ID, Address: "dhcp"}
			m.Routing.DefaultGateway = "gw_wan"
		}
	}
	n := len(m.Routing.Gateways)
	Upgrade(m)
	if g := defaultGW(m); g.Address != "203.0.113.1" || g.Name != "WAN_GW" || len(m.Routing.Gateways) != n {
		t.Errorf("moved into %+v (%d gateways)", g, len(m.Routing.Gateways))
	}
	if f.IPv4.Gateway != "" {
		t.Error("the interface still has it")
	}
	if errs := Validate(m); len(errs) > 0 {
		t.Errorf("invalid after: %v", errs)
	}
	if c, _ := genFile(m, "/etc/mygate"); c != "203.0.113.1\n" {
		t.Errorf("mygate = %q", c)
	}

	// Routing's fixed address wins.
	m, _ = loadSampleModel(t)
	f = static(m)
	m.Routing.Gateways = []Gateway{{ID: "gw_wan", Name: "ISP", Iface: f.ID, Address: "203.0.113.254"}}
	m.Routing.DefaultGateway = "gw_wan"
	m.Routing.Routes = nil
	Upgrade(m)
	if g := defaultGW(m); g.Address != "203.0.113.254" || g.Name != "ISP" {
		t.Errorf("replaced a fixed gateway: %+v", g)
	}

	// None on the interface: a new one, the default if there's none.
	m, _ = loadSampleModel(t)
	f = static(m)
	var others []Gateway
	for _, g := range m.Routing.Gateways {
		if g.Iface != f.ID {
			others = append(others, g)
		}
	}
	m.Routing.Gateways = others
	m.Routing.DefaultGateway = ""
	Upgrade(m)
	if g := defaultGW(m); g.ID != "gw_"+f.ID || g.Address != "203.0.113.1" || g.Iface != f.ID {
		t.Errorf("added %+v", g)
	}
	if errs := Validate(m); len(errs) > 0 {
		t.Errorf("invalid after: %v", errs)
	}

	// Left on, it's refused.
	m, _ = loadSampleModel(t)
	static(m)
	bad := false
	for _, e := range Validate(m) {
		bad = bad || e.Path == "interfaces[0].ipv4.gateway"
	}
	if !bad {
		t.Error("an interface gateway was accepted")
	}
}

func TestUpgradeDropsTableEntries(t *testing.T) {
	m := &Model{Firewall: Firewall{Aliases: []Alias{
		{Name: "bruteforce", Type: AliasTable, Entries: []string{"192.0.2.1"}},
		{Name: "internal", Type: AliasNetworks, Entries: []string{"10.0.0.0/8"}},
	}}}
	Upgrade(m)
	if len(m.Firewall.Aliases[0].Entries) != 0 || len(m.Firewall.Aliases[1].Entries) != 1 {
		t.Errorf("aliases %+v", m.Firewall.Aliases)
	}
	m.Firewall.Aliases[0].Entries = []string{"192.0.2.1"}
	if errs := Validate(m); !slicesContainsPath(errs, "firewall.aliases[0].entries[0]") {
		t.Errorf("a table's entry validated: %v", errs)
	}
}

func slicesContainsPath(errs []FieldError, path string) bool {
	for _, e := range errs {
		if e.Path == path {
			return true
		}
	}
	return false
}

// Routing table numbers OPF no longer sets: a form rule with one is
// raw afterwards, written exactly as it was; a daemon's and ntpd's go.
func TestUpgradeRoutingTables(t *testing.T) {
	m, _ := loadSampleModel(t)
	r := &m.Firewall.Rules[0]
	r.RTable = ptrTo(3)
	before := GenerateRule(r, m)
	m.System.Services = []ServiceSetting{{Name: "ntpd", Enabled: true, RTable: ptrTo(2)}}
	m.System.NTP = &NTPSettings{Listen: []NTPListen{{Address: "*", RTable: 4}}}
	if errs := Validate(m); len(errs) != 3 {
		t.Errorf("before: %v", errs)
	}
	Upgrade(m)
	r = &m.Firewall.Rules[0]
	if !r.IsRaw() || r.Text != before || !strings.Contains(before, "rtable 3") || r.RTable != nil {
		t.Errorf("rule: %+v\nwas %s", r, before)
	}
	if m.System.Services[0].RTable != nil || m.System.NTP.Listen[0].RTable != 0 {
		t.Errorf("services %+v, listen %+v", m.System.Services, m.System.NTP.Listen)
	}
	for _, e := range Validate(m) {
		t.Errorf("after: %v", e)
	}
}

// A pf rule with rtable is imported raw, as written.
func TestParseRTableRaw(t *testing.T) {
	m, _ := loadSampleModel(t)
	r, err := ParseRule("pass in on em1 from any to any rtable 2", m)
	if err != nil || !r.IsRaw() || !strings.Contains(r.Text, "rtable 2") {
		t.Errorf("%+v %v", r, err)
	}
}
