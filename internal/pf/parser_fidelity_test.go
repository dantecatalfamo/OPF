package pf

import (
	"reflect"
	"testing"
)

// The parser must never produce a guided rule that means something
// different from its input. Whatever it can't represent exactly stays a
// raw rule, which keeps the original text.

func fidelityModel() *Model {
	return &Model{
		Interfaces: []Iface{
			{ID: "wan", Name: "WAN", Device: "em0"},
			{ID: "lan", Name: "LAN", Device: "em1"},
		},
		Routing: Routing{Gateways: []Gateway{
			{ID: "gw_wh", Name: "WAREHOUSE", Iface: "wg", Address: "10.8.0.10"},
		}},
		Firewall: Firewall{Aliases: []Alias{
			{ID: "a1", Name: "bruteforce", Type: AliasTable},
			{ID: "a2", Name: "servers", Type: AliasHosts, Entries: []string{"192.168.1.20"}},
		}},
	}
}

// Each of these used to parse as a guided rule with part of the input
// silently discarded or changed.
func TestParseRule_KeepsUnmodelledAsRaw(t *testing.T) {
	m := fidelityModel()
	for _, in := range []string{
		// routing
		"pass in on $lan from any to any route-to 192.0.2.1", // no such gateway
		"pass in on $lan from any to any route-to (em0 10.0.0.1)",
		"pass in on $lan from any to any reply-to { 10.8.0.10 10.8.0.11 }",
		"pass out on $wan from any to any dup-to 10.8.0.10",
		// logging
		"pass in log (user) all",
		"pass in log (to pflog1) all",
		"pass in log (all, to pflog1) all",
		// hosts
		"pass in from servers to any", // bare word: hostname, not a table
		"pass in from $lan to any",    // bare macro
		"pass in from $lan:broadcast to any",
		"pass in from ($wan:0) to any",
		"pass in from (em0) to any",
		"pass in from { 10.0.0.1 10.0.0.2 } to any",
		"pass in from no-route to any",
		"pass in from 10.0.0.1 - 10.0.0.9 to any",
		"pass in from any to urpf-failed",
		// interfaces
		"pass in on em9 all",     // not in the model
		"pass out on egress all", // interface group
		"pass in on ! em0 all",
		// options
		"block drop in all",
		"pass in all user root",
		"pass in all max-pkt-rate 100/10",
		"pass in all label nolabelquote",
		"pass in all tag",
		"pass in all set prio (3, 5)",
		"pass in all set tos lowdelay",
		"pass in all set prio 9",
		"pass in all probability 12.5%",
		"pass in all rtable x",
		"pass in all tag A tag B",
		"pass in all os",
		// state
		"pass in proto tcp all keep state (source-track rule)",
		"pass in proto tcp all keep state (max-src-nodes 10)",
		"pass in proto tcp all keep state (tcp.established 60)",
		"pass in proto tcp all keep state (overload <bruteforce> flush)",
		"pass in proto tcp all keep state (max-src-conn-rate 3)",
		"pass in proto tcp all keep state (max 10",
		"block in proto tcp all keep state",
		"pass in all no",
		// protocol-dependent options the generator only writes for
		// matching protocols
		"pass in to port 22",
		"pass in from ($wan) to ! <servers> port netbios-ssn",
		"pass in proto icmp all flags S/SA",
		"pass in proto tcp all icmp-type echoreq",
		"pass in proto icmp all icmp6-type echoreq",
		"pass in proto tcp all flags S",
		// actions
		"block return-icmp (port-unr, port-unr) in all",
		"block return-rst ttl in all",
		"pass return-rst in all",
		// order: filter options come after the hosts in pf.conf(5)
		"pass in tagged VOIP all",
		// found by FuzzParseRuleRoundTrip
		"pass on {}",
		"pass in proto tcp to port {}",
		"pass from ! any",
		"pass from any os \"\x9b\"", // invalid UTF-8
		`pass in all label "a\\ b"`, // backslash can't be written back
		`pass in all label "back\\slash"`,
	} {
		rule, err := ParseRule(in, m)
		if err != nil {
			t.Errorf("ParseRule(%q): %v", in, err)
			continue
		}
		if rule == nil || rule.Kind != "raw" {
			t.Errorf("ParseRule(%q) = %+v, want a raw rule", in, rule)
			continue
		}
		if rule.Text == "" {
			t.Errorf("ParseRule(%q): raw rule has no text", in)
		}
	}
}

// Rules the form can represent, with the fields that must come out.
func TestParseRule_ModelledFields(t *testing.T) {
	m := fidelityModel()
	ten := 10
	tests := []struct {
		in    string
		check func(r *Rule) bool
	}{
		{"pass in on em0 proto tcp to port 22", func(r *Rule) bool {
			return reflect.DeepEqual(r.Interfaces, []string{"wan"}) && r.Port == "22"
		}},
		{"pass in on { $wan em1 } all", func(r *Rule) bool {
			return reflect.DeepEqual(r.Interfaces, []string{"wan", "lan"})
		}},
		{"pass in on $lan from $lan:network to any route-to 10.8.0.10", func(r *Rule) bool {
			return r.Gateway == "gw_wh" && r.Source.Type == EndpointNet && r.Source.Iface == "lan"
		}},
		{"pass in on $lan all reply-to 10.8.0.10", func(r *Rule) bool { return r.ReplyTo == "gw_wh" }},
		{"pass in proto tcp from ($wan) to ! <servers> port netbios-ssn", func(r *Rule) bool {
			return r.Source.Type == EndpointIfaddr && r.Destination.Type == EndpointAlias && r.Destination.Not && r.Port == "netbios-ssn"
		}},
		{"pass in proto tcp all flags /SA", func(r *Rule) bool { return r.TCPFlags == "/SA" }},
		{"pass in proto tcp all flags any", func(r *Rule) bool { return r.TCPFlags == "any" }},
		{"pass in proto tcp all keep state (max 10, max-src-conn-rate 3/30, overload <bruteforce> flush global)", func(r *Rule) bool {
			s := r.State
			return s != nil && *s.MaxStates == ten && s.MaxSrcConnRate.Count == 3 && s.MaxSrcConnRate.Seconds == 30 && s.Overload == "bruteforce" && s.FlushGlobal
		}},
		{"block return-icmp (port-unr) in all", func(r *Rule) bool {
			return r.BlockReturn == BlockReturnICMP && r.ReturnICMPCode == "port-unr"
		}},
		{"pass in all probability 20% set prio 6 tag VOIP label \"desk phone\"", func(r *Rule) bool {
			return *r.Probability == 20 && *r.Prio == 6 && r.Tag == "VOIP" && r.Description == "desk phone"
		}},
	}
	for _, tt := range tests {
		rule, err := ParseRule(tt.in, m)
		if err != nil {
			t.Errorf("ParseRule(%q): %v", tt.in, err)
			continue
		}
		if rule.Kind != "form" || !tt.check(rule) {
			t.Errorf("ParseRule(%q) = %+v", tt.in, rule)
		}
	}
}

// Parsing a guided rule, generating it and parsing that again must give
// the same rule: nothing the parser records may be lost or changed by
// the generator.
func roundTrips(t *testing.T, in string, m *Model) {
	t.Helper()
	first, err := ParseRule(in, m)
	if err != nil || first == nil || first.Kind != "form" {
		return
	}
	text := GenerateRule(first, m)
	second, err := ParseRule(text, m)
	if err != nil {
		t.Fatalf("%q generated %q, which doesn't parse: %v", in, text, err)
	}
	if second.Kind != "form" || !reflect.DeepEqual(first, second) {
		t.Fatalf("%q round-tripped through %q:\nfirst  %+v\nsecond %+v", in, text, first, second)
	}
}

func TestParseRule_RoundTrip(t *testing.T) {
	m := fidelityModel()
	for _, in := range []string{
		"pass in all",
		"block return in quick on $wan inet proto tcp from any to ($wan) port 22",
		"pass in log (all) quick on { $wan em1 } inet6 proto udp from ! 10.0.0.0/8 port > 1023 to self port 53",
		"pass in proto tcp from ($wan) to ! <servers> port netbios-ssn",
		"pass in proto tcp from any to any port 8000:8080 flags /SA modulate state (max 10, sloppy, if-bound)",
		"pass in on $lan from $lan:network to any route-to 10.8.0.10 reply-to 10.8.0.10 rtable 2",
		"block return-rst ttl 5 in proto tcp all",
		"block return-icmp6 (port-unr) in inet6 all",
		"pass in proto icmp all icmp-type echoreq",
		"pass in proto icmp6 all icmp6-type neighbrsol",
		"pass in from any os \"Windows\" to any probability 20% once set prio 6 tag A tagged B label \"x\"",
		"pass in proto tcp all synproxy state (max-src-conn 10, max-src-conn-rate 3/30, overload <bruteforce> flush global)",
		"pass in proto tcp all no state",
		"match out on $wan proto { tcp udp } from any to any port { 80 443 }",
	} {
		roundTrips(t, in, m)
	}
}

func FuzzParseRuleRoundTrip(f *testing.F) {
	for _, s := range []string{
		"pass in all",
		"pass in on em0 proto tcp to port 22",
		"pass in log (all) quick on { $wan em1 } inet proto udp from ! 10.0.0.0/8 port > 1023 to self port 53",
		"pass in proto tcp all keep state (max 10, max-src-conn-rate 3/30, overload <bruteforce> flush global)",
		"pass in on $lan from $lan:network to any route-to 10.8.0.10",
		"block return-icmp (port-unr) in all",
		"pass in from any os \"Windows\" to any probability 20% once set prio 6 tag A tagged B label \"x\"",
	} {
		f.Add(s)
	}
	m := fidelityModel()
	f.Fuzz(func(t *testing.T, in string) {
		roundTrips(t, in, m)
	})
}

// pf keywords are case-sensitive.
func TestTokenize_KeywordsCaseSensitive(t *testing.T) {
	toks := Tokenize("pass from Any to Self")
	if toks[0].Type != TokenKeyword || toks[2].Type != TokenIdent || toks[4].Type != TokenIdent {
		t.Fatalf("tokens = %+v", toks)
	}
	if rule, err := ParseRule("pAss all", nil); err != nil || rule != nil {
		t.Errorf("ParseRule(\"pAss all\") = %+v, %v; want no rule", rule, err)
	}
}

// Plain "keep state" is the default for pass rules and is stored as no
// state options, so it round-trips.
func TestParseRule_PlainKeepState(t *testing.T) {
	rule, err := ParseRule("pass in proto tcp all keep state", nil)
	if err != nil || rule.Kind != "form" || rule.State != nil {
		t.Fatalf("got %+v, %v", rule, err)
	}
}

// Quotes are escaped the way pf reads them, and read back the same.
func TestQuoteRoundTrip(t *testing.T) {
	for _, v := range []string{`say "hi"`, "café ☕", "plain"} {
		toks := Tokenize("label " + quote(v))
		if toks[1].Type != TokenString || toks[1].Value != v {
			t.Errorf("quote(%q) = %s, read back as %+v", v, quote(v), toks[1])
		}
	}
}
