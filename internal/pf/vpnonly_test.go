package pf

import (
	"strings"
	"testing"
)

// A device kept to its VPN reaches the tunnel's network, and of OPF only
// DNS there: blocks on its address before any user rule. Other devices
// on the same tunnel aren't touched, NAT stays, and the sites behind the
// tunnel's routers aren't part of it.
func TestVPNOnlyDevices(t *testing.T) {
	m, _ := loadSampleModel(t)
	remote := wg(m, 3) // Remote access: Priya phone (full), Sam laptop (split)
	remote.Peers[0].ClientRoutes = ClientRoutesVPN
	if errs := Validate(m); len(errs) > 0 {
		t.Fatal(errs)
	}
	conf := GeneratePfConf(m)
	addr := remote.Peers[0].Address
	for _, want := range []string{
		`block in log quick on $wg from ` + addr + ` to ! ($wg:network) label "opf:vpn-only:wg"`,
		`block in log quick on $wg proto { tcp udp } from ` + addr + ` to ($wg) port != 53 label "opf:vpn-only:wg"`,
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("missing %q in:\n%s", want, conf)
		}
	}
	for _, l := range strings.Split(conf, "\n") {
		if strings.Contains(l, "opf:vpn-only") && strings.Contains(l, remote.Peers[1].Address) {
			t.Errorf("the split device is kept to the VPN too: %s", l)
		}
	}
	if !strings.Contains(conf, `opf:split-tunnel:wg`) {
		t.Error("the split device lost its own limit")
	}
	nat := false
	for _, n := range AutomaticNAT(m) {
		nat = nat || n.Source.Iface == "wg"
	}
	if !nat {
		t.Error("the tunnel lost its NAT")
	}
	if kind, id, ok := ParseLabel("opf:vpn-only:wg"); !ok || kind != LabelIsolated || id != "wg" {
		t.Errorf("label: %s %s %v", kind, id, ok)
	}
}

// A tunnel reachable from a LAN: connections from the LAN's network to
// the tunnel's network go in as OPF's address there, whatever the
// outbound NAT mode. The sites behind its routers aren't included:
// they're routed with real addresses.
func TestReachableFrom(t *testing.T) {
	m, _ := loadSampleModel(t)
	sites := wg(m, 4)
	sites.ReachableFrom = []string{"lan"}
	m.Firewall.OutboundNAT.Mode = NATModeManual
	if errs := Validate(m); len(errs) > 0 {
		t.Fatal(errs)
	}
	conf := GeneratePfConf(m)
	want := `match out on $wg1 inet from ($lan:network) to ($wg1:network) nat-to ($wg1:0) label "opf:vpn-in:wg1"`
	if !strings.Contains(conf, want) {
		t.Errorf("missing %q in:\n%s", want, conf)
	}
	if strings.Count(conf, "opf:vpn-in") != 1 {
		t.Errorf("NAT into more than the tunnel:\n%s", conf)
	}
	m.Interfaces[1].Enabled = false
	if conf := GeneratePfConf(m); strings.Contains(conf, "opf:vpn-in") {
		t.Error("NAT in from a disabled interface")
	}
	m.Interfaces[1].Enabled = true

	for _, bad := range [][]string{{"nope"}, {"wan"}, {"wg"}, {"lan", "lan"}} {
		sites.ReachableFrom = bad
		if errs := Validate(m); len(errs) != 1 || !strings.Contains(errs[0].Path, "reachableFrom") {
			t.Errorf("%v: %v", bad, errs)
		}
	}
}
