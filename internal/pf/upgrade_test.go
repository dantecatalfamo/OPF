package pf

import "testing"

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
