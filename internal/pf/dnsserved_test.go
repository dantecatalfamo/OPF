package pf

import (
	"slices"
	"strings"
	"testing"
)

// The resolver answers on every inside interface with a fixed address
// unless told which; never on a WAN or a way out. One left out gets
// neither a listening address nor access, so it's refused.
func TestDNSAnswersOn(t *testing.T) {
	m, _ := addExit(t) // the sample, plus a way out
	ids := func() []string {
		var out []string
		for _, i := range DNSServed(m) {
			out = append(out, i.ID)
		}
		return out
	}
	if got := ids(); !slices.Equal(got, []string{"lan", "iot", "wg", "wg1"}) {
		t.Errorf("by default: %v", got)
	}
	conf := GenerateUnboundConf(m)
	if strings.Contains(conf, "interface: 10.64.1.2") || strings.Contains(conf, "10.64.1.2/32 allow") {
		t.Errorf("the way out is answered on:\n%s", conf)
	}

	m.DNS.Interfaces = []string{"lan", "wg"}
	// IoT's DHCP hands out OPF as its resolver, which wouldn't answer.
	errs := Validate(m)
	if len(errs) != 1 || !strings.HasSuffix(errs[0].Path, ".dns") || !strings.HasPrefix(errs[0].Path, "dhcp[") {
		t.Fatalf("IoT left out while its DHCP names OPF: %v", errs)
	}
	for i := range m.DHCP {
		if m.DHCP[i].Iface == "iot" {
			m.DHCP[i].DNS, m.DHCP[i].DNSServers = DNSModeCustom, []string{"9.9.9.9"}
		}
	}
	if errs := Validate(m); len(errs) > 0 {
		t.Fatal(errs)
	}
	conf = GenerateUnboundConf(m)
	for _, want := range []string{"\tinterface: 192.168.1.1\n", "\taccess-control: 192.168.1.0/24 allow\n", "\tinterface: 10.8.0.1\n", "\taccess-control: 10.8.0.0/24 allow\n"} {
		if !strings.Contains(conf, want) {
			t.Errorf("missing %q", want)
		}
	}
	// Listening and access only; their reverse names are still known.
	for _, not := range []string{"interface: 192.168.20.1", "192.168.20.0/24 allow", "interface: 10.9.0.1", "10.9.0.0/24 allow"} {
		if strings.Contains(conf, not) {
			t.Errorf("%s is still there:\n%s", not, conf)
		}
	}
	if d := Derive(m); !slices.Equal(d.DNSServed, []string{"lan", "wg"}) {
		t.Errorf("derived %v", d.DNSServed)
	}
	m.DNS.Enabled = false
	if d := Derive(m); len(d.DNSServed) != 0 {
		t.Errorf("resolver off, still serving %v", d.DNSServed)
	}
	m.DNS.Enabled = true

	for name, bad := range map[string]string{"a WAN": "wan", "a way out": "vpnout", "unknown": "nope"} {
		m.DNS.Interfaces = []string{"lan", bad}
		if errs := Validate(m); len(errs) != 1 || errs[0].Path != "dns.interfaces[1]" {
			t.Errorf("%s: %v", name, errs)
		}
	}
	m.DNS.Interfaces = []string{"lan", "lan"}
	if errs := Validate(m); len(errs) != 1 || errs[0].Path != "dns.interfaces[1]" {
		t.Errorf("twice: %v", errs)
	}
	// A DHCP-addressed inside interface can't be answered on yet.
	m.Interfaces[1].IPv4 = IPv4Config{Mode: IPv4DHCP}
	m.DNS.Interfaces = []string{"lan"}
	found := false
	for _, e := range Validate(m) {
		found = found || e.Path == "dns.interfaces[0]" && strings.Contains(e.Message, "DHCP")
	}
	if !found {
		t.Errorf("a DHCP-addressed interface: %v", Validate(m))
	}
}
