package pf

import (
	"slices"
	"strings"
	"testing"
)

func intP(n int) *int { return &n }

func TestGenerateRule_Simple(t *testing.T) {
	tests := []struct {
		name     string
		rule     Rule
		expected string
	}{
		{
			name: "pass in all",
			rule: Rule{
				Kind:        "form",
				Action:      ActionPass,
				Direction:   DirectionIn,
				Family:      FamilyAny,
				Protocol:    ProtoAny,
				Source:      Endpoint{Type: EndpointAny},
				Destination: Endpoint{Type: EndpointAny},
				Log:         LogOff,
			},
			expected: "pass in all",
		},
		{
			name: "block out all",
			rule: Rule{
				Kind:        "form",
				Action:      ActionBlock,
				Direction:   DirectionOut,
				Family:      FamilyAny,
				Protocol:    ProtoAny,
				Source:      Endpoint{Type: EndpointAny},
				Destination: Endpoint{Type: EndpointAny},
				Log:         LogOff,
			},
			expected: "block out all",
		},
		{
			name: "match all",
			rule: Rule{
				Kind:        "form",
				Action:      ActionMatch,
				Direction:   DirectionAny,
				Family:      FamilyAny,
				Protocol:    ProtoAny,
				Source:      Endpoint{Type: EndpointAny},
				Destination: Endpoint{Type: EndpointAny},
				Log:         LogOff,
			},
			expected: "match all",
		},
		{
			name: "block return",
			rule: Rule{
				Kind:        "form",
				Action:      ActionReject,
				Direction:   DirectionIn,
				Family:      FamilyAny,
				Protocol:    ProtoAny,
				Source:      Endpoint{Type: EndpointAny},
				Destination: Endpoint{Type: EndpointAny},
				Log:         LogOff,
			},
			expected: "block return in all",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GenerateRule(&tt.rule, nil)
			if got != tt.expected {
				t.Errorf("GenerateRule() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestGenerateRule_WithInterfaces(t *testing.T) {
	rule := Rule{
		Kind:        "form",
		Action:      ActionPass,
		Direction:   DirectionIn,
		Interfaces:  []string{"wan"},
		Protocol:    ProtoTCP,
		Source:      Endpoint{Type: EndpointAny},
		Destination: Endpoint{Type: EndpointAny},
		Port:        "22",
		Log:         LogOff,
	}

	got := GenerateRule(&rule, nil)
	if !strings.Contains(got, "on $wan") {
		t.Errorf("Expected 'on $wan' in output: %q", got)
	}
	if !strings.Contains(got, "port 22") {
		t.Errorf("Expected 'port 22' in output: %q", got)
	}
}

func TestGenerateRule_MultipleInterfaces(t *testing.T) {
	rule := Rule{
		Kind:        "form",
		Action:      ActionPass,
		Direction:   DirectionIn,
		Interfaces:  []string{"wan", "lan"},
		Protocol:    ProtoAny,
		Source:      Endpoint{Type: EndpointAny},
		Destination: Endpoint{Type: EndpointAny},
		Log:         LogOff,
	}

	got := GenerateRule(&rule, nil)
	if !strings.Contains(got, "on { $wan $lan }") {
		t.Errorf("Expected 'on { $wan $lan }' in output: %q", got)
	}
}

func TestGenerateRule_Endpoints(t *testing.T) {
	model := &Model{
		Firewall: Firewall{
			Aliases: []Alias{
				{Name: "blocklist", Type: AliasHosts},
			},
		},
	}

	fixed, dynamic := false, true
	tests := []struct {
		name     string
		endpoint Endpoint
		expected string
	}{
		{"any", Endpoint{Type: EndpointAny}, "any"},
		{"self", Endpoint{Type: EndpointSelf}, "self"},
		{"network", Endpoint{Type: EndpointIface, Iface: "lan", Part: PartNetwork, Dynamic: &fixed}, "$lan:network"},
		{"address, dynamic", Endpoint{Type: EndpointIface, Iface: "wan", Dynamic: &dynamic}, "($wan)"},
		{"broadcast", Endpoint{Type: EndpointIface, Iface: "lan", Part: PartBroadcast, Dynamic: &fixed}, "$lan:broadcast"},
		{"peer, no aliases", Endpoint{Type: EndpointIface, Iface: "wg", Part: PartPeer, NoAlias: true, Dynamic: &dynamic}, "($wg:peer:0)"},
		{"group", Endpoint{Type: EndpointIface, Group: "egress", Part: PartNetwork}, "(egress:network)"},
		{"group, fixed", Endpoint{Type: EndpointIface, Group: "egress", Dynamic: &fixed}, "egress"},
		{"unknown interface is dynamic", Endpoint{Type: EndpointIface, Iface: "lan"}, "($lan)"},
		{"negated interface", Endpoint{Type: EndpointIface, Iface: "lan", Part: PartNetwork, Not: true, Dynamic: &fixed}, "! $lan:network"},
		{"host", Endpoint{Type: EndpointHost, Value: "192.168.1.1"}, "192.168.1.1"},
		{"network", Endpoint{Type: EndpointNetwork, Value: "10.0.0.0/8"}, "10.0.0.0/8"},
		{"alias", Endpoint{Type: EndpointAlias, Alias: "blocklist"}, "<blocklist>"},
		{"negated", Endpoint{Type: EndpointSelf, Not: true}, "! self"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := endpoint(tt.endpoint, model)
			if got != tt.expected {
				t.Errorf("endpoint() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestGenerateRule_StateOptions(t *testing.T) {
	tests := []struct {
		name     string
		state    *StateOptions
		contains []string
	}{
		{
			name:     "keep state",
			state:    &StateOptions{Mode: StateModeKeep},
			contains: []string{},
		},
		{
			name:     "modulate state",
			state:    &StateOptions{Mode: StateModeModulate},
			contains: []string{"modulate state"},
		},
		{
			name:     "synproxy state",
			state:    &StateOptions{Mode: StateModeSynproxy},
			contains: []string{"synproxy state"},
		},
		{
			name:     "no state",
			state:    &StateOptions{Mode: StateModeNone},
			contains: []string{"no state"},
		},
		{
			name:     "max states",
			state:    &StateOptions{Mode: StateModeKeep, MaxStates: intP(1000)},
			contains: []string{"keep state (max 1000)"},
		},
		{
			name:     "overload with flush",
			state:    &StateOptions{Mode: StateModeKeep, Overload: "bruteforce", FlushGlobal: true},
			contains: []string{"overload <bruteforce> flush global"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := Rule{
				Kind:        "form",
				Action:      ActionPass,
				Direction:   DirectionIn,
				Protocol:    ProtoTCP,
				Source:      Endpoint{Type: EndpointAny},
				Destination: Endpoint{Type: EndpointAny},
				State:       tt.state,
			}
			got := GenerateRule(&rule, nil)
			for _, substr := range tt.contains {
				if !strings.Contains(got, substr) {
					t.Errorf("Expected %q in output: %q", substr, got)
				}
			}
		})
	}
}

func TestGenerateRule_BlockReturn(t *testing.T) {
	tests := []struct {
		name        string
		blockReturn BlockReturn
		ttl         *int
		expected    string
	}{
		{"return-rst", BlockReturnRST, nil, "block return-rst"},
		{"return-rst with ttl", BlockReturnRST, intP(64), "block return-rst ttl 64"},
		{"return-icmp", BlockReturnICMP, nil, "block return-icmp"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := Rule{
				Kind:         "form",
				Action:       ActionBlock,
				Direction:    DirectionIn,
				BlockReturn:  tt.blockReturn,
				ReturnRstTTL: tt.ttl,
				Source:       Endpoint{Type: EndpointAny},
				Destination:  Endpoint{Type: EndpointAny},
			}
			got := GenerateRule(&rule, nil)
			if !strings.HasPrefix(got, tt.expected) {
				t.Errorf("Expected prefix %q in output: %q", tt.expected, got)
			}
		})
	}
}

func TestGenerateRule_LogOptions(t *testing.T) {
	tests := []struct {
		log      LogMode
		expected string
	}{
		{LogOff, "pass in all"},
		{LogOn, "pass in log all"},
		{LogAll, "pass in log (all) all"},
	}

	for _, tt := range tests {
		t.Run(string(tt.log), func(t *testing.T) {
			rule := Rule{
				Kind:        "form",
				Action:      ActionPass,
				Direction:   DirectionIn,
				Protocol:    ProtoAny,
				Source:      Endpoint{Type: EndpointAny},
				Destination: Endpoint{Type: EndpointAny},
				Log:         tt.log,
			}
			got := GenerateRule(&rule, nil)
			if got != tt.expected {
				t.Errorf("GenerateRule() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestGenerateRule_Quick(t *testing.T) {
	rule := Rule{
		Kind:        "form",
		Action:      ActionPass,
		Direction:   DirectionIn,
		Quick:       true,
		Source:      Endpoint{Type: EndpointAny},
		Destination: Endpoint{Type: EndpointAny},
	}
	got := GenerateRule(&rule, nil)
	if !strings.Contains(got, "quick") {
		t.Errorf("Expected 'quick' in output: %q", got)
	}
}

// A rule's label is its id; the description is a comment above it.
func TestGenerateRule_Label(t *testing.T) {
	rule := Rule{
		ID:          "r7",
		Kind:        "form",
		Action:      ActionPass,
		Direction:   DirectionIn,
		Source:      Endpoint{Type: EndpointAny},
		Destination: Endpoint{Type: EndpointAny},
		Description: "Allow SSH",
	}
	if got := GenerateRule(&rule, nil); got != `pass in all label "opf:rule:r7"` {
		t.Errorf("GenerateRule = %q", got)
	}
	// An id that can't be a label (possible before validation) gets none.
	rule.ID = `r7" pass all`
	if got := GenerateRule(&rule, nil); got != "pass in all" {
		t.Errorf("GenerateRule with a bad id = %q", got)
	}
}

func TestDescriptionsAreComments(t *testing.T) {
	prefix := 24
	m := &Model{
		Interfaces: []Iface{
			{ID: "wan", Name: "WAN", Device: "em0", Role: RoleWAN, Enabled: true, IPv4: IPv4Config{Mode: IPv4Static, Address: "203.0.113.2", Prefix: &prefix}},
			{ID: "lan", Name: "LAN", Device: "em1", Role: RoleLAN, Enabled: true, IPv4: IPv4Config{Mode: IPv4Static, Address: "192.168.1.1", Prefix: &prefix}},
		},
		Firewall: Firewall{
			Rules: []Rule{
				{ID: "r1", Kind: "form", Enabled: true, Interfaces: []string{"lan"}, Action: ActionPass, Direction: DirectionIn,
					Source: Endpoint{Type: EndpointAny}, Destination: Endpoint{Type: EndpointAny},
					Description: "Costs $5/month, see the \"ops\" wiki"},
				{ID: "r2", Kind: "raw", Enabled: true, Interfaces: []string{"lan"}, Text: `pass in on $lan proto udp to port 53 label "dns"`, Description: "Raw one\\"},
				{ID: "r3", Kind: "form", Enabled: true, Interfaces: []string{"lan"}, Action: ActionBlock, Direction: DirectionIn,
					Source: Endpoint{Type: EndpointAny}, Destination: Endpoint{Type: EndpointAny}},
			},
			Forwards: []PortForward{{ID: "f1", Enabled: true, Iface: "wan", Protocol: "tcp", Source: Endpoint{Type: EndpointAny},
				ExternalPort: "443", Target: "192.168.1.20", TargetPort: "443", Reflection: true, Description: "web"}},
			OutboundNAT: OutboundNAT{Mode: NATModeHybrid, Rules: []NATRule{{ID: "n1", Enabled: true, Iface: "wan",
				Source: Endpoint{Type: EndpointHost, Value: "192.168.1.9"}, Destination: Endpoint{Type: EndpointAny},
				Translation: Translation{Type: TranslationNone}, Description: "No NAT"}}},
		},
	}
	conf := GeneratePfConf(m)
	for _, want := range []string{
		"# Costs $5/month, see the \"ops\" wiki\npass in on $lan all label \"opf:rule:r1\"\n",
		// Raw rules keep their text, own label and all; a trailing
		// backslash would join the comment to the rule.
		"# Raw one\npass in on $lan proto udp to port 53 label \"dns\"\n",
		"\nblock in on $lan all label \"opf:rule:r3\"\n",
		"# web\npass in quick on $wan proto tcp from any to $wan port 443 rdr-to 192.168.1.20 port 443 label \"opf:forward:f1\"\n" +
			"pass in quick on $lan proto tcp from $lan:network to $wan port 443 rdr-to 192.168.1.20 port 443 label \"opf:forward:f1\"\n" +
			"match out on $lan proto tcp from $lan:network to 192.168.1.20 port 443 nat-to ($lan) label \"opf:forward:f1\"\n",
		"# No NAT\nmatch out on $wan inet from 192.168.1.9 to any tag opf_nonat label \"opf:nat:n1\"\n",
		"# Automatic: LAN to WAN\nmatch out on $wan inet from $lan:network to any ! tagged opf_nonat nat-to ($wan:0) label \"opf:auto-nat:lan\"\n",
		"block all label \"opf:builtin:default-block\"\n",
		"pass out inet label \"opf:builtin:self-out\"\n",
		"pass in quick on $lan proto tcp to $lan port { 443 22 } label \"opf:builtin:anti-lockout\"\n",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("missing %q in:\n%s", want, conf)
		}
	}
	if strings.Contains(conf, "label \"web\"") || strings.Contains(conf, "label \"No NAT\"") {
		t.Errorf("a description is still a label:\n%s", conf)
	}
}

func TestLabels(t *testing.T) {
	for _, l := range []string{"opf:rule:r1", "opf:forward:f_1", "opf:auto-nat:lan", "opf:builtin:anti-lockout", "opf:split-tunnel:wg1", "opf:nat:" + strings.Repeat("n", 32), "opf:split-tunnel:" + strings.Repeat("w", 32)} {
		kind, id, ok := ParseLabel(l)
		if !ok || Label(kind, id) != l {
			t.Errorf("ParseLabel(%q) = %q, %q, %v", l, kind, id, ok)
		}
		if len(l) > 63 {
			t.Errorf("%q is longer than PF_RULE_LABEL_SIZE allows", l)
		}
	}
	if len(Label(LabelAutoNAT, strings.Repeat("x", 32))) > 63 {
		t.Error("the longest label doesn't fit")
	}
	for _, l := range []string{"", "Allow SSH", "opf:", "opf:rule", "opf:rule:", "opf:thing:x", "opf:rule:a b", "opf:rule:$nr", "xopf:rule:r1", "opf:rule:" + strings.Repeat("r", 33)} {
		if _, _, ok := ParseLabel(l); ok {
			t.Errorf("ParseLabel(%q) accepted it", l)
		}
	}
}

func TestGenerateRule_Tags(t *testing.T) {
	rule := Rule{
		Kind:        "form",
		Action:      ActionPass,
		Direction:   DirectionIn,
		Source:      Endpoint{Type: EndpointAny},
		Destination: Endpoint{Type: EndpointAny},
		Tag:         "WEB",
		Tagged:      "VOIP",
	}
	got := GenerateRule(&rule, nil)
	if !strings.Contains(got, "tag WEB") {
		t.Errorf("Expected 'tag WEB' in output: %q", got)
	}
	if !strings.Contains(got, "tagged VOIP") {
		t.Errorf("Expected 'tagged VOIP' in output: %q", got)
	}
}

func TestGenerateRule_RawRule(t *testing.T) {
	rule := Rule{
		Kind: "raw",
		Text: "match out on egress nat-to (egress:0)",
	}
	got := GenerateRule(&rule, nil)
	if got != "match out on egress nat-to (egress:0)" {
		t.Errorf("GenerateRule() = %q, want raw text", got)
	}
}

func TestGenerateNATRule(t *testing.T) {
	rule := NATRule{
		Iface:       "wan",
		Source:      Endpoint{Type: EndpointIface, Iface: "lan", Part: PartNetwork},
		Destination: Endpoint{Type: EndpointAny},
		Translation: Translation{Type: TranslationIfaddr},
		Description: "LAN to WAN",
	}
	got := GenerateNATRule(&rule, nil)
	if !strings.Contains(got, "match out on $wan") {
		t.Errorf("Expected 'match out on $wan' in output: %q", got)
	}
	if !strings.Contains(got, "nat-to ($wan:0)") {
		t.Errorf("Expected 'nat-to ($wan:0)' in output: %q", got)
	}
}

func TestGenerateNATRule_Exception(t *testing.T) {
	rule := NATRule{
		Iface:       "wan",
		Source:      Endpoint{Type: EndpointHost, Value: "192.168.1.100"},
		Destination: Endpoint{Type: EndpointAny},
		Translation: Translation{Type: TranslationNone},
		Description: "No NAT for this host",
	}
	got := GenerateNATRule(&rule, nil)
	if got != "match out on $wan inet from 192.168.1.100 to any tag opf_nonat" {
		t.Errorf("GenerateNATRule = %q", got)
	}
}

// An exception tags its traffic, and every nat-to rule on the same
// interface leaves tagged traffic alone; rules on other interfaces, and
// all of them when there are no exceptions, aren't touched.
func TestNATExceptionsUseTags(t *testing.T) {
	m, _ := loadSampleModel(t)
	m.Firewall.OutboundNAT.Mode = NATModeHybrid
	m.Firewall.OutboundNAT.Rules = append(m.Firewall.OutboundNAT.Rules, NATRule{
		ID: "n9", Enabled: true, Iface: "wan", Source: Endpoint{Type: EndpointHost, Value: "192.168.1.9"},
		Destination: Endpoint{Type: EndpointNetwork, Value: "10.20.0.0/16"}, Translation: Translation{Type: TranslationNone}, Description: "Warehouse sees real addresses",
	})
	conf := GeneratePfConf(m)
	exception := strings.Index(conf, `match out on $wan inet from 192.168.1.9 to 10.20.0.0/16 tag opf_nonat label "opf:nat:n9"`)
	auto := strings.Index(conf, `match out on $wan inet from $lan:network to any ! tagged opf_nonat nat-to ($wan:0) label "opf:auto-nat:lan"`)
	manual := strings.Index(conf, `match out on $wan inet from 192.168.1.60 to any ! tagged opf_nonat nat-to ($wan:0) static-port label "opf:nat:n1"`)
	if exception < 0 || auto < 0 || manual < 0 {
		t.Fatalf("exception %d, auto %d, manual %d in:\n%s", exception, auto, manual, conf)
	}
	if exception > auto || exception > manual {
		t.Error("the exception must come before the nat-to rules")
	}
	// Reflection's nat-to is on the inside interface, not the exception's.
	if strings.Contains(conf, "nat-to ($lan) ! tagged") || strings.Contains(conf, "! tagged opf_nonat nat-to ($lan)") {
		t.Error("an exception on the WAN changed NAT on the LAN")
	}
	if strings.Contains(conf, "pass out quick") {
		t.Error("an exception still ends evaluation")
	}

	// In automatic mode manual exceptions don't apply at all.
	m.Firewall.OutboundNAT.Mode = NATModeAuto
	if conf := GeneratePfConf(m); strings.Contains(conf, "opf_nonat") {
		t.Errorf("automatic mode tagged something:\n%s", conf)
	}
}

func TestAutomaticNAT(t *testing.T) {
	prefix := 24
	model := &Model{
		Interfaces: []Iface{
			{ID: "wan", Name: "WAN", Role: RoleWAN, Enabled: true, IPv4: IPv4Config{Mode: IPv4DHCP}},
			{ID: "lan", Name: "LAN", Role: RoleLAN, Enabled: true, IPv4: IPv4Config{Mode: IPv4Static, Address: "192.168.1.1", Prefix: &prefix}},
		},
	}

	rules := AutomaticNAT(model)
	if len(rules) != 1 {
		t.Errorf("Expected 1 automatic NAT rule, got %d", len(rules))
	}
	if len(rules) > 0 && rules[0].Source.Iface != "lan" {
		t.Errorf("Expected source interface 'lan', got %q", rules[0].Source.Iface)
	}
}

func TestGeneratePfConf_SampleModel(t *testing.T) {
	prefix24 := 24
	model := &Model{
		System: SystemSettings{
			Hostname: "gw",
			Domain:   "example.com",
		},
		Interfaces: []Iface{
			{ID: "wan", Name: "WAN", Device: "em0", Role: RoleWAN, Enabled: true, IPv4: IPv4Config{Mode: IPv4DHCP}, BlockPrivate: true, BlockBogons: true},
			{ID: "lan", Name: "LAN", Device: "em1", Role: RoleLAN, Enabled: true, IPv4: IPv4Config{Mode: IPv4Static, Address: "192.168.1.1", Prefix: &prefix24}},
		},
		Routing: Routing{
			DefaultGateway: "gw_wan",
			Gateways: []Gateway{
				{ID: "gw_wan", Name: "WAN_DHCP", Iface: "wan", Address: "dhcp"},
			},
		},
		Firewall: Firewall{
			Rules: []Rule{
				{
					ID: "r1", Kind: "form", Enabled: true, Interfaces: []string{"wan"},
					Action: ActionPass, Direction: DirectionIn, Protocol: ProtoTCP,
					Source: Endpoint{Type: EndpointAny}, Destination: Endpoint{Type: EndpointSelf},
					Port: "22", Description: "Allow SSH",
				},
				{
					ID: "r2", Kind: "form", Enabled: true, Interfaces: []string{"lan"},
					Action: ActionPass, Direction: DirectionIn,
					Source: Endpoint{Type: EndpointIface, Iface: "lan", Part: PartNetwork}, Destination: Endpoint{Type: EndpointAny},
					Description: "Allow LAN",
				},
			},
			OutboundNAT: OutboundNAT{Mode: NATModeAuto},
			Aliases: []Alias{
				{Name: "bruteforce", Type: AliasTable},
			},
			Options: FirewallOptions{
				BlockPolicy:     BlockPolicyDrop,
				StatePolicy:     StatePolicyOptionFloating,
				Optimization:    OptNormal,
				MaxStates:       100000,
				Syncookies:      SyncookiesAdaptive,
				Scrub:           ScrubOptions{Enabled: true, RandomID: true, NoDf: true},
				LogDefaultBlock: true,
			},
		},
	}

	conf := GeneratePfConf(model)

	// Check for essential parts
	checks := []string{
		"# Generated by OPF",
		"wan = \"em0\"",
		"lan = \"em1\"",
		"table <bruteforce> persist",
		"table <bogons>",
		"table <private>",
		"set block-policy drop",
		"set syncookies adaptive",
		"block log all",
		"pass out inet label",
		"pass in quick on $lan proto tcp",
		"Allow SSH",
		"Allow LAN",
	}

	for _, check := range checks {
		if !strings.Contains(conf, check) {
			t.Errorf("Expected %q in generated config:\n%s", check, conf)
		}
	}
}

func TestGenerateHostnameIf(t *testing.T) {
	prefix := 24
	iface := &Iface{
		ID:      "lan",
		Name:    "LAN",
		Device:  "em1",
		Role:    RoleLAN,
		Enabled: true,
		IPv4:    IPv4Config{Mode: IPv4Static, Address: "192.168.1.1", Prefix: &prefix},
		IPv6:    IPv6None,
	}

	model := &Model{
		Routing: Routing{},
	}

	content := GenerateHostnameIf(iface, model)

	if !strings.Contains(content, "inet 192.168.1.1/24") {
		t.Errorf("Expected 'inet 192.168.1.1/24' in output: %q", content)
	}
	if !strings.Contains(content, "description \"LAN\"") {
		t.Errorf("Expected description in output: %q", content)
	}
	if !strings.Contains(content, "up") {
		t.Errorf("Expected 'up' in output: %q", content)
	}
}

func TestGenerateDHCPdConf(t *testing.T) {
	prefix := 24
	model := &Model{
		System: SystemSettings{Domain: "example.com"},
		Interfaces: []Iface{
			{ID: "lan", Name: "LAN", Role: RoleLAN, Enabled: true, IPv4: IPv4Config{Mode: IPv4Static, Address: "192.168.1.1", Prefix: &prefix}},
		},
		DHCP: []DHCPScope{
			{
				Iface:      "lan",
				Enabled:    true,
				RangeStart: "192.168.1.100",
				RangeEnd:   "192.168.1.200",
				LeaseHours: 24,
				DNS:        DNSModeSelf,
				Reservations: []Reservation{
					{Hostname: "server", MAC: "00:11:22:33:44:55", IP: "192.168.1.10"},
				},
			},
		},
	}

	content := GenerateDHCPdConf(model)

	checks := []string{
		"domain-name \"example.com\"",
		"subnet 192.168.1.0 netmask 255.255.255.0",
		"range 192.168.1.100 192.168.1.200",
		"host server",
		"hardware ethernet 00:11:22:33:44:55",
		"fixed-address 192.168.1.10",
	}

	for _, check := range checks {
		if !strings.Contains(content, check) {
			t.Errorf("Expected %q in output: %s", check, content)
		}
	}
}

func TestGenerateUnboundConf(t *testing.T) {
	prefix := 24
	model := &Model{
		System: SystemSettings{Domain: "example.com"},
		Interfaces: []Iface{
			{ID: "lan", Name: "LAN", Role: RoleLAN, Enabled: true, IPv4: IPv4Config{Mode: IPv4Static, Address: "192.168.1.1", Prefix: &prefix}},
		},
		DNS: DNS{
			Enabled: true,
			Mode:    ResolverModeRecursive,
			DNSSEC:  true,
			Overrides: []HostOverride{
				{Host: "www", Domain: "example.com", IP: "192.168.1.10"},
			},
		},
	}

	content := GenerateUnboundConf(model)

	checks := []string{
		"server:",
		"interface: 192.168.1.1",
		"access-control: 192.168.1.0/24 allow",
		"auto-trust-anchor-file",
		"local-zone: \"example.com.\" static",
		"local-data: \"www.example.com. IN A 192.168.1.10\"",
	}

	for _, check := range checks {
		if !strings.Contains(content, check) {
			t.Errorf("Expected %q in output: %s", check, content)
		}
	}
}

// Without an explicit choice, interfaces addressed by DHCP or SLAAC are
// written in parentheses so rules follow their address changes.
func TestIfaceDynamicDefault(t *testing.T) {
	prefix := 24
	m := &Model{Interfaces: []Iface{
		{ID: "wan", Device: "em0", IPv4: IPv4Config{Mode: IPv4DHCP}},
		{ID: "lan", Device: "em1", IPv4: IPv4Config{Mode: IPv4Static, Address: "192.168.1.1", Prefix: &prefix}},
		{ID: "v6", Device: "em2", IPv4: IPv4Config{Mode: IPv4Static, Address: "10.0.0.1", Prefix: &prefix}, IPv6: IPv6SLAAC},
	}}
	for iface, want := range map[string]string{
		"wan": "($wan:network)",
		"lan": "$lan:network",
		"v6":  "($v6:network)",
	} {
		got := endpoint(Endpoint{Type: EndpointIface, Iface: iface, Part: PartNetwork}, m)
		if got != want {
			t.Errorf("%s: got %q, want %q", iface, got, want)
		}
	}
}

// self follows address changes when any interface's address can change.
func TestSelfDynamicDefault(t *testing.T) {
	prefix := 24
	static := []Iface{{ID: "lan", Enabled: true, IPv4: IPv4Config{Mode: IPv4Static, Address: "192.168.1.1", Prefix: &prefix}}}
	withDHCP := append([]Iface{{ID: "wan", Enabled: true, IPv4: IPv4Config{Mode: IPv4DHCP}}}, static...)
	for _, tt := range []struct {
		m    *Model
		e    Endpoint
		want string
	}{
		{&Model{Interfaces: static}, Endpoint{Type: EndpointSelf}, "self"},
		{&Model{Interfaces: withDHCP}, Endpoint{Type: EndpointSelf}, "(self)"},
		{nil, Endpoint{Type: EndpointSelf}, "self"},
		{&Model{Interfaces: withDHCP}, Endpoint{Type: EndpointSelf, Part: PartNetwork, NoAlias: true}, "(self:network:0)"},
		{&Model{Interfaces: static}, Endpoint{Type: EndpointSelf, Part: PartBroadcast, Not: true}, "! self:broadcast"},
	} {
		if got := endpoint(tt.e, tt.m); got != tt.want {
			t.Errorf("endpoint(%+v) = %q, want %q", tt.e, got, tt.want)
		}
	}
}

// Built-in rules use the same interface references as user rules, so a
// DHCP-addressed interface is always in parentheses.
func TestBuiltinRulesFollowAddressing(t *testing.T) {
	prefix := 24
	m := &Model{
		Interfaces: []Iface{
			{ID: "wan", Device: "em0", Role: RoleWAN, Enabled: true, IPv4: IPv4Config{Mode: IPv4Static, Address: "203.0.113.2", Prefix: &prefix}},
			{ID: "lan", Device: "em1", Role: RoleLAN, Enabled: true, IPv4: IPv4Config{Mode: IPv4Static, Address: "192.168.1.1", Prefix: &prefix}},
			{ID: "lab", Device: "em2", Role: RoleOPT, Enabled: true, IPv4: IPv4Config{Mode: IPv4DHCP}},
		},
		Firewall: Firewall{Forwards: []PortForward{{
			ID: "f1", Enabled: true, Iface: "wan", Protocol: "tcp", Source: Endpoint{Type: EndpointAny},
			ExternalPort: "443", Target: "192.168.1.20", TargetPort: "443", Reflection: true, Description: "web",
		}}},
	}
	conf := GeneratePfConf(m)
	for _, want := range []string{
		`pass in quick on $lan proto tcp to $lan port { 443 22 } label "opf:builtin:anti-lockout"`,
		`pass in quick on $wan proto tcp from any to $wan port 443 rdr-to 192.168.1.20 port 443 label "opf:forward:f1"`,
		`pass in quick on $lan proto tcp from $lan:network to $wan port 443 rdr-to 192.168.1.20 port 443`,
		`match out on $lan proto tcp from $lan:network to 192.168.1.20 port 443 nat-to ($lan)`,
		// The DHCP-addressed lab network gets reflection too, in parentheses.
		`pass in quick on $lab proto tcp from ($lab:network) to $wan port 443 rdr-to 192.168.1.20 port 443`,
		`match out on $lab proto tcp from ($lab:network) to 192.168.1.20 port 443 nat-to ($lab)`,
		`match out on $wan inet from ($lab:network) to any nat-to ($wan:0)`,
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("missing %q in:\n%s", want, conf)
		}
	}

	m.Interfaces[0].IPv4 = IPv4Config{Mode: IPv4DHCP}
	conf = GeneratePfConf(m)
	for _, want := range []string{
		`from any to ($wan) port 443 rdr-to`,
		`from $lan:network to ($wan) port 443 rdr-to`,
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("DHCP WAN: missing %q in:\n%s", want, conf)
		}
	}
}

// Each tunnel's hostname.wgN has its own port and peers, and nothing of
// the others'.
func TestTunnelsAreSeparate(t *testing.T) {
	m, _ := loadSampleModel(t)
	files := map[string]string{}
	for _, f := range GenerateFiles(m) {
		files[f.Path] = f.Content
	}
	wg0, wg1 := files["/etc/hostname.wg0"], files["/etc/hostname.wg1"]
	for _, c := range []struct {
		file, text string
		want       bool
	}{
		{wg0, "wgport 51820", true},
		{wg0, `wgdescr "Priya phone"`, true},
		{wg0, `wgdescr "Warehouse router"`, false},
		{wg0, "inet 10.8.0.1/24", true},
		{wg1, "wgport 51821", true},
		{wg1, `wgdescr "Warehouse router"`, true},
		{wg1, "wgaip 10.9.0.2/32 wgaip 10.20.0.0/16 wgendpoint warehouse.example.net 51820", true},
		{wg1, `wgdescr "Priya phone"`, false},
		{wg1, "inet 10.9.0.1/24", true},
		{wg1, "!route -q add -net 10.20.0.0/16 10.9.0.2", true},
	} {
		if strings.Contains(c.file, c.text) != c.want {
			t.Errorf("contains %q = %v, want %v, in:\n%s", c.text, !c.want, c.want, c.file)
		}
	}
	if len(m.Tunnels()) != 2 {
		t.Errorf("Tunnels() = %d", len(m.Tunnels()))
	}
}

// A device told to send only local traffic through its tunnel is held
// to that by pf, ahead of any user rule that would let it out.
func TestSplitTunnelIsEnforced(t *testing.T) {
	m, _ := loadSampleModel(t)
	conf := GeneratePfConf(m)
	table := "table <opf_local> const { 192.168.1.0/24 192.168.20.0/24 10.8.0.0/24 10.9.0.0/24 10.20.0.0/16 }"
	block := `block in log quick on $wg inet from 10.8.0.3/32 to ! <opf_local> label "opf:split-tunnel:wg"`
	for _, want := range []string{table, "# Remote access: Sam laptop\n" + block} {
		if !strings.Contains(conf, want) {
			t.Errorf("missing %q in:\n%s", want, conf)
		}
	}
	// The sample's own rule lets the tunnel out to the internet; the
	// block has to come first.
	userPass := strings.Index(conf, `label "opf:rule:r13"`)
	if i := strings.Index(conf, block); i < 0 || userPass < 0 || i > userPass {
		t.Errorf("the split-tunnel block isn't before the tunnel's pass rule:\n%s", conf)
	}
	// Full-tunnel and site-to-site peers aren't limited.
	for _, addr := range []string{"10.8.0.2/32", "10.9.0.2/32"} {
		if strings.Contains(conf, "from "+addr+" to ! <opf_local>") {
			t.Errorf("%s is limited but isn't a split-tunnel peer", addr)
		}
	}

	// No split-tunnel peers, no table and no block.
	for _, tun := range m.Tunnels() {
		for i := range tun.WireGuard.Peers {
			tun.WireGuard.Peers[i].ClientRoutes = ClientRoutesFull
		}
	}
	if conf := GeneratePfConf(m); strings.Contains(conf, "opf_local") {
		t.Errorf("opf_local without split-tunnel peers:\n%s", conf)
	}

	// Several split peers in one tunnel share one rule; a DHCP-addressed
	// inside network is resolved by pf at load time.
	m, _ = loadSampleModel(t)
	tun := m.Tunnels()[0]
	for i := range tun.WireGuard.Peers {
		tun.WireGuard.Peers[i].ClientRoutes = ClientRoutesSplit
	}
	m.Interfaces[2].IPv4 = IPv4Config{Mode: IPv4DHCP}
	conf = GeneratePfConf(m)
	for _, want := range []string{"from { 10.8.0.2/32 10.8.0.3/32 } to ! <opf_local>", "$iot:network"} {
		if !strings.Contains(conf, want) {
			t.Errorf("missing %q in:\n%s", want, conf)
		}
	}
	if got := LocalNetworks(m, false); slices.Contains(got, "$iot:network") {
		t.Errorf("LocalNetworks(m, false) = %v, which a device configuration can't list", got)
	}
}

// Nothing OPF adds ahead of the user's rules may end evaluation for
// outbound traffic, or outbound user rules (blocks, match rules that set
// priorities or tags) would never be reached.
func TestNoQuickOutboundPassBeforeUserRules(t *testing.T) {
	m, _ := loadSampleModel(t)
	conf := GeneratePfConf(m)
	for _, line := range strings.Split(conf, "\n") {
		if strings.HasPrefix(line, "# Custom rules") || strings.Contains(line, `label "opf:rule:`) {
			break // the user's own rules and pf text start here
		}
		f := strings.Fields(line)
		if len(f) < 2 || f[0] != "pass" {
			continue
		}
		quick, out := false, false
		for _, w := range f {
			quick = quick || w == "quick"
			out = out || w == "out"
		}
		inOnly := strings.Contains(line, "pass in ")
		if quick && (out || !inOnly) {
			t.Errorf("%q ends evaluation for outbound traffic before the user's rules", line)
		}
	}
	for _, want := range []string{`pass out inet label "opf:builtin:self-out"`, `pass out inet6 label "opf:builtin:self-out"`} {
		if !strings.Contains(conf, want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestGenerateRcConfLocal(t *testing.T) {
	m, _ := loadSampleModel(t)
	got := GenerateRcConfLocal(m)
	// Only the devices with a DHCP scope: never the WAN.
	if !strings.Contains(got, "\ndhcpd_flags=\"em1 vlan20\"\n") || !strings.Contains(got, "\nunbound_flags=\"\"\n") {
		t.Errorf("sample:\n%s", got)
	}
	for i := range m.DHCP {
		m.DHCP[i].Enabled = false
	}
	m.DNS.Enabled = false
	if got := GenerateRcConfLocal(m); !strings.Contains(got, "dhcpd_flags=\"NO\"") || !strings.Contains(got, "unbound_flags=\"NO\"") {
		t.Errorf("all off:\n%s", got)
	}
	// A scope on a disabled interface isn't served.
	m, _ = loadSampleModel(t)
	m.Interfaces[2].Enabled = false // iot, vlan20
	if got := GenerateRcConfLocal(m); !strings.Contains(got, "dhcpd_flags=\"em1\"") {
		t.Errorf("iot off:\n%s", got)
	}
}

func TestPfOptions(t *testing.T) {
	m, _ := loadSampleModel(t)
	// The sample sets none of the optional ones: pf's defaults stand.
	conf := GeneratePfConf(m)
	for _, absent := range []string{"set timeout", "set state-defaults", "set reassemble", "set debug", "set hostid", "set fingerprints", "set ruleset-optimization", "antispoof"} {
		if strings.Contains(conf, absent) {
			t.Errorf("%q with nothing set", absent)
		}
	}
	for _, want := range []string{"set limit states 100000\n", "set skip on lo\n", "set loginterface $wan\n", `set syncookies adaptive (start 25%, end 12%)`} {
		if !strings.Contains(conf, want) {
			t.Errorf("missing %q", want)
		}
	}

	n := func(i int) *int { return &i }
	id := uint32(7)
	o := &m.Firewall.Options
	o.SyncookiesStart, o.SyncookiesEnd = n(40), n(20)
	o.Limits = Limits{SrcNodes: n(20000), TableEntries: n(500000), Anchors: n(1024)}
	o.Timeouts = map[string]int{"tcp.established": 3600, "adaptive.start": 60000, "adaptive.end": 120000}
	o.StateDefaults = []string{"no-sync", "pflow"}
	o.Reassemble, o.ReassembleNoDf = "yes", true
	o.RulesetOptimization = "basic"
	o.Debug = "notice"
	o.HostID = &id
	o.Fingerprints = "/etc/pf.os"
	o.LogInterface = "none"
	o.SkipOn = []string{"iot", "enc0"}
	o.Scrub = ScrubOptions{Enabled: true, MinTTL: n(64), ReassembleTCP: true}
	m.Interfaces[1].Antispoof = true // lan
	conf = GeneratePfConf(m)
	for _, want := range []string{
		"set ruleset-optimization basic\n",
		"set limit { states 100000, src-nodes 20000, table-entries 500000, anchors 1024 }\n",
		"set timeout { tcp.established 3600, adaptive.start 60000, adaptive.end 120000 }\n",
		"set syncookies adaptive (start 40%, end 20%)\n",
		"set state-defaults no-sync, pflow\n",
		"set reassemble yes no-df\n",
		"set debug notice\n",
		"set hostid 7\n",
		`set fingerprints "/etc/pf.os"`,
		"set skip on { lo $iot enc0 }\n",
		"set loginterface none\n",
		"match in all scrub (min-ttl 64 reassemble tcp)\n",
		`antispoof log quick for $lan inet label "opf:antispoof:lan"`,
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("missing %q in:\n%s", want, conf)
		}
	}
	// Every option line links to its setting by name.
	named := false
	for _, l := range GeneratePfRuleset(m) {
		named = named || (strings.HasPrefix(l.Text, "set limit") && l.Origin != nil && l.Origin.Label == "Firewall settings: Limits")
	}
	if !named {
		t.Error("option lines don't name their setting")
	}

	// Scrub with nothing selected writes no rule (pf needs at least one
	// option in the parentheses).
	o.Scrub = ScrubOptions{Enabled: true}
	if conf := GeneratePfConf(m); strings.Contains(conf, "scrub") {
		t.Errorf("empty scrub:\n%s", conf)
	}
}

func TestSafe(t *testing.T) {
	if _, err := Safe(func() int { var m *Model; return len(m.Interfaces) }); err == nil {
		t.Error("a panic wasn't turned into an error")
	}
	if v, err := Safe(func() int { return 3 }); v != 3 || err != nil {
		t.Errorf("Safe = %d, %v", v, err)
	}
}

// Derive gives the pages what they'd otherwise compute themselves.
func TestDerive(t *testing.T) {
	m, _ := loadSampleModel(t)
	d := Derive(m)
	if d.Rules["r6"] != GenerateRule(&m.Firewall.Rules[slices.IndexFunc(m.Firewall.Rules, func(r Rule) bool { return r.ID == "r6" })], m) {
		t.Errorf("rule text %q", d.Rules["r6"])
	}
	if len(d.AutomaticNAT) != len(AutomaticNAT(m)) || slices.Contains(d.LocalNetworks, "$lan:network") {
		t.Errorf("derived %+v", d)
	}
	if !d.DynamicIfaces["wan"] || d.DynamicIfaces["lan"] || !d.SelfDynamic {
		t.Errorf("dynamic %v, self %v", d.DynamicIfaces, d.SelfDynamic)
	}
	if d := Derive(&Model{}); d.AutomaticNAT == nil || d.LocalNetworks == nil || d.Rules == nil {
		t.Error("empty lists should be empty, not null in JSON")
	}
}
