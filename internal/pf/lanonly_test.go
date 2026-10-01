package pf

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// OPF behind an existing router, only a VPN server reached through a
// port forward: one LAN, no WAN, the default gateway the router's.
func TestLANOnlyVPNServer(t *testing.T) {
	data, err := os.ReadFile("testdata/lan-only-vpn.json")
	if err != nil {
		t.Fatal(err)
	}
	var m Model
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	if errs := Validate(&m); len(errs) > 0 {
		t.Fatalf("invalid: %v", errs)
	}
	pfconf := GeneratePfConf(&m)
	for _, want := range []string{
		// VPN devices take the office address on the way out, so the
		// router needs no route back to them.
		"match out on $lan inet from $wg:network to any nat-to ($lan:0)",
		// The web UI and SSH stay reachable from the office.
		"pass in quick on $lan proto tcp to $lan port { 443 22 }",
		// The forwarded handshake gets in.
		"pass in on $lan inet proto udp from any to self port 51820",
	} {
		if !strings.Contains(pfconf, want) {
			t.Errorf("pf.conf lacks %q:\n%s", want, pfconf)
		}
	}
	for _, not := range []string{"$wan", "<private>", "<bogons>"} {
		if strings.Contains(pfconf, not) {
			t.Errorf("pf.conf has %q", not)
		}
	}
	// The office network is local, for split-tunnel devices.
	if !strings.Contains(strings.Join(LocalNetworks(&m, true), " "), "192.168.1.0/24") {
		t.Errorf("local networks %v", LocalNetworks(&m, true))
	}
	files := map[string]string{}
	for _, f := range GenerateFiles(&m) {
		files[f.Path] = f.Content
	}
	if files["/etc/mygate"] != "192.168.1.1\n" {
		t.Errorf("mygate %q", files["/etc/mygate"])
	}
	if u := files["/var/unbound/etc/unbound.conf"]; !strings.Contains(u, "interface: 192.168.1.50") || !strings.Contains(u, "interface: 10.8.0.1") {
		t.Errorf("unbound.conf:\n%s", u)
	}
	if dump := os.Getenv("DUMP"); dump != "" {
		os.WriteFile(dump+"/pf.conf", []byte(pfconf), 0o644)
		os.WriteFile(dump+"/unbound.conf", []byte(files["/var/unbound/etc/unbound.conf"]), 0o644)
	}
}

// OPF behind a router, a VPN server reached through a port forward:
// the LAN masquerades, so VPN devices' traffic leaving it takes OPF's
// address and the router needs no route back to them.
func TestMasquerade(t *testing.T) {
	m, _ := loadSampleModel(t)
	m.Interfaces[1].Masquerade = true // lan
	if errs := Validate(m); len(errs) > 0 {
		t.Fatal(errs)
	}
	conf := GeneratePfConf(m)
	for _, want := range []string{
		"match out on $lan inet from $wg:network to any nat-to ($lan:0)",
		"match out on $lan inet from $iot:network to any nat-to ($lan:0)",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(conf, "on $lan inet from $lan:network to any nat-to") {
		t.Error("the LAN NATs its own network")
	}
	for _, c := range []struct {
		i    int
		path string
	}{{0, "interfaces[0].masquerade"}, {3, "interfaces[3].masquerade"}} {
		m, _ := loadSampleModel(t)
		m.Interfaces[c.i].Masquerade = true
		found := false
		for _, e := range Validate(m) {
			found = found || e.Path == c.path
		}
		if !found {
			t.Errorf("masquerade on %s allowed", m.Interfaces[c.i].Role)
		}
	}
}

func TestValidEndpoint(t *testing.T) {
	for _, ok := range []string{"vpn.example.com", "vpn.example.com:51820", "203.0.113.5", "203.0.113.5:443", "[2001:db8::1]:51820", "[2001:db8::1]"} {
		if !validEndpoint(ok) {
			t.Errorf("refused %q", ok)
		}
	}
	for _, bad := range []string{"vpn.example.com:", "vpn.example.com:0", "vpn.example.com:65536", "vpn.example.com:051820", "a b.example.com", "vpn.example.com\nAllowedIPs = 0.0.0.0/0", "2001:db8::1:51820", "[2001:db8::1", "[203.0.113.5]:1", "*.example.com", "_vpn.example.com", "https://vpn.example.com"} {
		if validEndpoint(bad) {
			t.Errorf("took %q", bad)
		}
	}
}
