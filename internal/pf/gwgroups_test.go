package pf

import (
	"slices"
	"strconv"
	"strings"
	"testing"
)

// twoWANs is the sample model with a second, fixed WAN gateway, a
// group of both and an IPv4 rule sending the LAN's web traffic
// through it.
func twoWANs(t *testing.T) *Model {
	t.Helper()
	m, _ := loadSampleModel(t)
	m.Interfaces = append(m.Interfaces, Iface{ID: "wan2", Name: "WAN2", Device: "em2", Role: RoleWAN, Enabled: true,
		IPv4: IPv4Config{Mode: IPv4Static, Address: "198.51.100.2", Prefix: ptrTo(24)}, IPv6: IPv6None})
	m.Routing.Gateways = append(m.Routing.Gateways, Gateway{ID: "gw_wan2", Name: "WAN2_GW", Iface: "wan2", Address: "198.51.100.1"})
	m.Routing.Groups = []GatewayGroup{{ID: "both", Name: "Both", Members: []GroupMember{{Gateway: "gw_wan2", Tier: 1}, {Gateway: "gw_wan", Tier: 2}}}}
	m.Firewall.Rules = append(m.Firewall.Rules, Rule{ID: "web", Kind: "form", Enabled: true, Interfaces: []string{"lan"},
		Action: ActionPass, Direction: DirectionIn, Family: FamilyInet, Protocol: ProtoTCP, Port: "443",
		Source: Endpoint{Type: EndpointIface, Iface: "lan", Part: PartNetwork}, Destination: Endpoint{Type: EndpointAny}, Log: LogOff, Gateway: "both"})
	if errs := Validate(m); len(errs) > 0 {
		t.Fatal(errs)
	}
	return m
}

// A rule sends through a group's table, which pf.conf declares empty
// for OPF to fill; a DHCP gateway goes the same way, a fixed one by its
// address.
func TestGroupRuleset(t *testing.T) {
	m := twoWANs(t)
	conf := GeneratePfConf(m)
	for _, want := range []string{
		"table <opf_gw_both> persist\t# OPF puts in the group's gateways in use",
		"route-to <opf_gw_both> round-robin",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("pf.conf lacks %q:\n%s", want, conf)
		}
	}
	m.Routing.Groups[0].Sticky = true
	if conf := GeneratePfConf(m); !strings.Contains(conf, "route-to <opf_gw_both> round-robin sticky-address") {
		t.Errorf("sticky:\n%s", conf)
	}
	// The sample's WAN gateway is DHCP's: a table too.
	m.Firewall.Rules[len(m.Firewall.Rules)-1].Gateway = "gw_wan"
	conf = GeneratePfConf(m)
	if !strings.Contains(conf, "route-to <opf_gw_gw_wan> round-robin") || !strings.Contains(conf, "table <opf_gw_gw_wan> persist") || strings.Contains(conf, "opf_gw_both") {
		t.Errorf("DHCP gateway:\n%s", conf)
	}
	m.Firewall.Rules[len(m.Firewall.Rules)-1].Gateway = "gw_wan2"
	if conf := GeneratePfConf(m); !strings.Contains(conf, "route-to 198.51.100.1") || strings.Contains(conf, "opf_gw_") {
		t.Errorf("fixed gateway:\n%s", conf)
	}
	if got := GatewayTables(m); len(got) != 0 {
		t.Errorf("tables %v", got)
	}
}

func TestGroupValidation(t *testing.T) {
	for name, tc := range map[string]struct {
		edit func(m *Model)
		path string
	}{
		"no members":         {func(m *Model) { m.Routing.Groups[0].Members = nil }, "routing.groups[0].members"},
		"a gateway twice":    {func(m *Model) { m.Routing.Groups[0].Members[1].Gateway = "gw_wan2" }, "routing.groups[0].members[1].gateway"},
		"no such gateway":    {func(m *Model) { m.Routing.Groups[0].Members[1].Gateway = "gw_x" }, "routing.groups[0].members[1].gateway"},
		"tier 0":             {func(m *Model) { m.Routing.Groups[0].Members[0].Tier = 0 }, "routing.groups[0].members[0].tier"},
		"tier 6":             {func(m *Model) { m.Routing.Groups[0].Members[0].Tier = 6 }, "routing.groups[0].members[0].tier"},
		"a gateway's id":     {func(m *Model) { m.Routing.Groups[0].ID = "gw_wan2" }, "routing.groups[0].id"},
		"too long for pf":    {func(m *Model) { m.Routing.Groups[0].ID = strings.Repeat("g", 25) }, "routing.groups[0].id"},
		"a dash":             {func(m *Model) { m.Routing.Groups[0].ID = "a-b" }, "routing.groups[0].id"},
		"an IPv6 gateway":    {func(m *Model) { m.Routing.Gateways[len(m.Routing.Gateways)-1].Address = "2001:db8::1" }, "routing.groups[0].members[0].gateway"},
		"an any-family rule": {func(m *Model) { m.Firewall.Rules[len(m.Firewall.Rules)-1].Family = FamilyAny }, "firewall.rules[" + "LAST" + "].gateway"},
		"a static route": {func(m *Model) {
			m.Routing.Routes = []StaticRoute{{ID: "r", Enabled: true, Network: "10.5.0.0/16", Gateway: "both"}}
		}, "routing.routes[0].gateway"},
		"the default gateway": {func(m *Model) { m.Routing.DefaultGateway = "both" }, "routing.defaultGateway"},
		"reply-to a group":    {func(m *Model) { m.Firewall.Rules[len(m.Firewall.Rules)-1].ReplyTo = "both" }, ""},
	} {
		m := twoWANs(t)
		tc.edit(m)
		path := strings.ReplaceAll(tc.path, "LAST", strconv.Itoa(len(m.Firewall.Rules)-1))
		errs := Validate(m)
		if has := slices.ContainsFunc(errs, func(e FieldError) bool { return e.Path == path }); path == "" && len(errs) > 0 || path != "" && !has {
			t.Errorf("%s: %v", name, errs)
		}
	}
}

// The first tier with a gateway that answers is used, all of its that
// answer; with none, the first tier.
func TestGroupInUse(t *testing.T) {
	g := GatewayGroup{Members: []GroupMember{{Gateway: "a", Tier: 1}, {Gateway: "b", Tier: 1}, {Gateway: "c", Tier: 2}, {Gateway: "d", Tier: 3}}}
	for _, tc := range []struct {
		up   []string
		want []string
	}{
		{[]string{"a", "b", "c", "d"}, []string{"a", "b"}},
		{[]string{"b", "c"}, []string{"b"}},
		{[]string{"c", "d"}, []string{"c"}},
		{[]string{"d"}, []string{"d"}},
		{nil, []string{"a", "b"}},
	} {
		if got := GroupInUse(g, func(id string) bool { return slices.Contains(tc.up, id) }); !slices.Equal(got, tc.want) {
			t.Errorf("up %v: %v, want %v", tc.up, got, tc.want)
		}
	}
}
