package pf

import (
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

func TestGenerateRule_Label(t *testing.T) {
	rule := Rule{
		Kind:        "form",
		Action:      ActionPass,
		Direction:   DirectionIn,
		Source:      Endpoint{Type: EndpointAny},
		Destination: Endpoint{Type: EndpointAny},
		Description: "Allow SSH",
	}
	got := GenerateRule(&rule, nil)
	if !strings.Contains(got, `label "Allow SSH"`) {
		t.Errorf("Expected label in output: %q", got)
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
	if !strings.Contains(got, "pass out quick") {
		t.Errorf("Expected 'pass out quick' for NAT exception: %q", got)
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
		"pass out quick inet",
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
		`pass in quick on $lan proto tcp to $lan port { 443 22 } label "Anti-lockout"`,
		`pass in quick on $wan proto tcp from any to $wan port 443 rdr-to 192.168.1.20 port 443 label "web"`,
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
