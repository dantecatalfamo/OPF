package pf

import (
	"slices"
	"strings"
	"testing"
)

// addExit gives the sample model a way out through a VPN provider: wg2,
// which the IoT network leaves through.
func addExit(t *testing.T) (*Model, *Iface) {
	t.Helper()
	m, _ := loadSampleModel(t)
	prefix, ka := 32, 25
	m.Interfaces = append(m.Interfaces, Iface{
		ID: "vpnout", Name: "Provider", Device: "wg2", Role: RoleVPN, Enabled: true,
		IPv4: IPv4Config{Mode: IPv4Static, Address: "10.64.1.2", Prefix: &prefix}, IPv6: IPv6None,
		WireGuard: &WireGuard{PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", Peers: []Peer{}, Exit: &Exit{
			PublicKey: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=", Endpoint: "vpn.example.net:51820", Keepalive: &ka,
			From: []string{"iot"}, DNS: []string{"10.64.0.1"},
		}},
	})
	return m, &m.Interfaces[len(m.Interfaces)-1]
}

func TestExitTunnel(t *testing.T) {
	m, exit := addExit(t)
	if errs := Validate(m); len(errs) > 0 {
		t.Fatal(errs)
	}

	// The provider takes everything sent in; the main table gets no
	// route through it, the tunnel's own table its only one, and the
	// provider's resolver a host route.
	hif := GenerateHostnameIf(exit, m)
	for _, want := range []string{
		"wgpeer BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA= wgaip 0.0.0.0/0 wgendpoint vpn.example.net 51820 wgpka 25 wgdescr \"Provider\"",
		"inet 10.64.1.2/32",
		"!route -qT 202 delete -inet default >/dev/null 2>&1; route -qT 202 add -inet default -iface 10.64.1.2",
		"!route -q delete -inet -host 10.64.0.1 >/dev/null 2>&1; route -q add -inet -host 10.64.0.1 -iface 10.64.1.2",
	} {
		if !strings.Contains(hif, want) {
			t.Errorf("hostname.wg2 lacks %q:\n%s", want, hif)
		}
	}
	if strings.Contains(hif, "wgport") || strings.Contains(hif, "route -q add -net") || strings.Contains(hif, "route -q add -inet default") {
		t.Errorf("hostname.wg2:\n%s", hif)
	}

	if slices.Contains(LocalNetworks(m, true), "10.64.1.2/32") {
		t.Error("the way out's address counts as one of your networks")
	}
	conf := GeneratePfConf(m)
	for _, want := range []string{
		"table <opf_local> const {",
		`match in on $iot inet from ($iot:network) to ! <opf_local> rtable 202 scrub (max-mss 1380) label "opf:exit:vpnout"`,
		`match in on $iot to (self) rtable 0 label "opf:exit:vpnout"`,
		`block out log quick on $wan received-on $iot label "opf:exit:vpnout"`,
		`match out on $vpnout inet from ($iot:network) nat-to ($vpnout:0) label "opf:exit:vpnout"`,
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("pf.conf lacks %q:\n%s", want, conf)
		}
	}
	// The routing comes before every user rule.
	if strings.Index(conf, "rtable 202") > strings.Index(conf, "opf:rule:") {
		t.Error("the way out comes after user rules")
	}
	if strings.Contains(conf, "$lan inet from ($lan:network) to ! <opf_local> rtable") {
		t.Error("the LAN leaves through the provider too")
	}

	unbound := GenerateUnboundConf(m)
	if !strings.Contains(unbound, "forward-zone:\n\tname: \".\"\n\t# through Provider\n\tforward-addr: 10.64.0.1\n") || strings.Contains(unbound, "@853") {
		t.Errorf("unbound.conf:\n%s", unbound)
	}

	// Turned off, nothing of it at all.
	exit.Enabled = false
	if conf := GeneratePfConf(m); strings.Contains(conf, "opf:exit") {
		t.Errorf("disabled:\n%s", conf)
	}
	if strings.Contains(GenerateUnboundConf(m), "through Provider") {
		t.Error("a disabled way out still takes the resolver")
	}
}

func TestExitValidation(t *testing.T) {
	for name, tc := range map[string]struct {
		edit func(m *Model, e *Iface)
		path string
	}{
		"devices on it":         {func(m *Model, e *Iface) { e.WireGuard.Peers = wg(m, 3).Peers[:1] }, "wireguard.peers"},
		"reachable from":        {func(m *Model, e *Iface) { e.WireGuard.ReachableFrom = []string{"lan"} }, "reachableFrom"},
		"no port":               {func(m *Model, e *Iface) { e.WireGuard.Exit.Endpoint = "vpn.example.net" }, "exit.endpoint"},
		"bad key":               {func(m *Model, e *Iface) { e.WireGuard.Exit.PublicKey = "x" }, "exit.publicKey"},
		"the WAN leaves":        {func(m *Model, e *Iface) { e.WireGuard.Exit.From = []string{"wan"} }, "exit.from[0]"},
		"unknown network":       {func(m *Model, e *Iface) { e.WireGuard.Exit.From = []string{"nope"} }, "exit.from[0]"},
		"DNS not an address":    {func(m *Model, e *Iface) { e.WireGuard.Exit.DNS = []string{"dns.example"} }, "exit.dns[0]"},
		"device past table 255": {func(m *Model, e *Iface) { e.Device = "wg56" }, "device"},
		"no fixed address":      {func(m *Model, e *Iface) { e.IPv4 = IPv4Config{Mode: IPv4DHCP} }, "ipv4"},
	} {
		m, e := addExit(t)
		tc.edit(m, e)
		errs := Validate(m)
		found := false
		for _, err := range errs {
			found = found || strings.Contains(err.Path, tc.path)
		}
		if !found {
			t.Errorf("%s: %v", name, errs)
		}
	}
	// A network leaves through one way out only.
	m, _ := addExit(t)
	prefix := 32
	second := m.Interfaces[len(m.Interfaces)-1]
	second.ID, second.Name, second.Device = "vpnout2", "Second", "wg3"
	second.IPv4 = IPv4Config{Mode: IPv4Static, Address: "10.65.1.2", Prefix: &prefix}
	w := *second.WireGuard
	e := *w.Exit
	e.DNS = nil
	w.Exit, w.PublicKey = &e, "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA="
	second.WireGuard = &w
	m.Interfaces = append(m.Interfaces, second)
	if errs := Validate(m); len(errs) != 1 || !strings.Contains(errs[0].Message, "already leaves through") {
		t.Errorf("two ways out for one network: %v", errs)
	}
}
