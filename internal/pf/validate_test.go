package pf

import (
	"strings"
	"testing"
)

func TestValidateSampleModel(t *testing.T) {
	m, _ := loadSampleModel(t)
	if errs := Validate(m); len(errs) > 0 {
		t.Fatalf("sample model has problems: %v", errs)
	}
}

// Each case breaks one thing in the sample model; Validate must report
// it at the given path. Most are attempts to change the meaning of a
// generated file through a value that's written into it.
func TestValidateCatchesProblems(t *testing.T) {
	for _, tt := range []struct {
		name   string
		path   string
		break_ func(m *Model)
	}{
		{"newline in a rule description (pf injection)", "firewall.rules[0].description", func(m *Model) {
			m.Firewall.Rules[0].Description = "x\"\npass all"
		}},
		{"backslash in a description", "firewall.rules[0].description", func(m *Model) { m.Firewall.Rules[0].Description = `a\ b` }},
		{"description ending in a backslash (continues the pf comment)", "firewall.rules[0].description", func(m *Model) { m.Firewall.Rules[0].Description = `note\` }},
		{"description over 200 bytes", "firewall.rules[0].description", func(m *Model) {
			m.Firewall.Rules[0].Description = strings.Repeat("é", 101)
		}},
		{"rule id too long for its label", "firewall.rules[0].id", func(m *Model) { m.Firewall.Rules[0].ID = strings.Repeat("r", 33) }},
		{"rule id with a quote (label)", "firewall.rules[0].id", func(m *Model) { m.Firewall.Rules[0].ID = `r1" pass` }},
		{"port forward id with $ (label macro)", "firewall.forwards[0].id", func(m *Model) { m.Firewall.Forwards[0].ID = "f$nr" }},
		{"NAT rule id with a colon", "firewall.outboundNat.rules[0].id", func(m *Model) { m.Firewall.OutboundNAT.Rules[0].ID = "n:1" }},
		{"quote in an interface name (hostname.if)", "interfaces[1].name", func(m *Model) { m.Interfaces[1].Name = `LAN" up` }},
		{"interface id is a pf keyword", "interfaces[1].id", func(m *Model) { m.Interfaces[1].ID = "block" }},
		{"interface id with a space", "interfaces[1].id", func(m *Model) { m.Interfaces[1].ID = "l an" }},
		{"device with a path", "interfaces[1].device", func(m *Model) { m.Interfaces[1].Device = "../../etc/passwd" }},
		{"duplicate device", "interfaces[1].device", func(m *Model) { m.Interfaces[1].Device = m.Interfaces[0].Device }},
		{"VLAN on a non-vlan device", "interfaces[2].device", func(m *Model) { m.Interfaces[2].Device = "em7" }},
		{"alias name that breaks a table", "firewall.aliases[0].name", func(m *Model) { m.Firewall.Aliases[0].Name = "bad> pass all <x" }},
		{"alias entry that isn't an address", "firewall.aliases[2].entries[0]", func(m *Model) {
			m.Firewall.Aliases[2].Entries[0] = "10.0.0.0/8 } pass all {"
		}},
		{"URL with a newline (pf comment)", "firewall.aliases[0].url", func(m *Model) { m.Firewall.Aliases[0].URL = "https://x/\npass all" }},
		{"URL that isn't https", "firewall.aliases[0].url", func(m *Model) { m.Firewall.Aliases[0].URL = "file:///etc/master.passwd" }},
		{"raw rule with two lines", "firewall.rules[1].text", func(m *Model) { m.Firewall.Rules[1].Text = "pass all\npass all" }},
		{"NUL in custom pf", "firewall.custom.afterFilter", func(m *Model) { m.Firewall.Custom.AfterFilter = "pass all\x00" }},
		{"reservation host name with a brace (dhcpd.conf)", "dhcp[0].reservations[0].hostname", func(m *Model) {
			m.DHCP[0].Reservations[0].Hostname = "files { }"
		}},
		{"reservation outside the network", "dhcp[0].reservations[0].ip", func(m *Model) { m.DHCP[0].Reservations[0].IP = "10.9.9.9" }},
		{"duplicate MAC", "dhcp[0].reservations[1].mac", func(m *Model) { m.DHCP[0].Reservations[1].MAC = m.DHCP[0].Reservations[0].MAC }},
		{"range backwards", "dhcp[0].rangeEnd", func(m *Model) { m.DHCP[0].RangeEnd = "192.168.1.50" }},
		{"override host with a quote (unbound.conf)", "dns.overrides[0].host", func(m *Model) { m.DNS.Overrides[0].Host = `files" IN A 1.2.3.4` }},
		{"domain with a space (myname)", "system.domain", func(m *Model) { m.System.Domain = "office .arpa" }},
		{"hostname with a shell character (myname)", "system.hostname", func(m *Model) { m.System.Hostname = "gw$(id)" }},
		{"route description with a newline (!route)", "routing.routes[0].description", func(m *Model) {
			m.Routing.Routes[0].Description = "x\n!rm -rf /"
		}},
		{"peer name with a quote (wgdescr)", "wireguard.peers[0].name", func(m *Model) { m.WireGuard.Peers[0].Name = `Priya" wgpeer x` }},
		{"peer key that isn't a key", "wireguard.peers[0].publicKey", func(m *Model) { m.WireGuard.Peers[0].PublicKey = "x wgaip 0.0.0.0/0" }},
		{"peer endpoint with extra words", "wireguard.peers[2].endpoint", func(m *Model) { m.WireGuard.Peers[2].Endpoint = "a.example:51820 wgpka 1" }},
		{"rule on a missing interface", "firewall.rules[2].interfaces[0]", func(m *Model) { m.Firewall.Rules[2].Interfaces = []string{"nope"} }},
		{"rule using a missing alias", "firewall.rules[4].source.alias", func(m *Model) { m.Firewall.Rules[4].Source.Alias = "nope" }},
		{"port that isn't a port", "firewall.rules[2].port", func(m *Model) { m.Firewall.Rules[2].Port = "51820 } pass all {" }},
		{"port on a protocol without ports", "firewall.rules[2].port", func(m *Model) { m.Firewall.Rules[2].Protocol = ProtoICMP }},
		{"tag with a space", "firewall.rules[2].tag", func(m *Model) { m.Firewall.Rules[2].Tag = "a b" }},
		{"forward target that isn't an address", "firewall.forwards[0].target", func(m *Model) { m.Firewall.Forwards[0].Target = "1.2.3.4 port 1" }},
		{"unknown enum", "firewall.options.blockPolicy", func(m *Model) { m.Firewall.Options.BlockPolicy = "maybe" }},
		{"static route via a DHCP gateway", "routing.routes[0].gateway", func(m *Model) { m.Routing.Routes[0].Gateway = "gw_wan" }},
		{"not any", "firewall.rules[2].source.not", func(m *Model) { m.Firewall.Rules[2].Source.Not = true }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			m, _ := loadSampleModel(t)
			tt.break_(m)
			errs := Validate(m)
			for _, e := range errs {
				if e.Path == tt.path {
					return
				}
			}
			t.Errorf("no error at %s; got %v", tt.path, errs)
		})
	}
}

func TestValidPortExpr(t *testing.T) {
	for _, ok := range []string{"22", "8000:8080", "8000-8080", "80,443", "> 1023", "!= 22", "1024 >< 2048", "www", "netbios-ssn"} {
		if !validPortExpr(ok) {
			t.Errorf("rejected %q", ok)
		}
	}
	for _, bad := range []string{"0", "65536", "22 23", "a:b", "80,>1", "{ 22 }", "22;", "-1", "080"} {
		if validPortExpr(bad) {
			t.Errorf("accepted %q", bad)
		}
	}
}
