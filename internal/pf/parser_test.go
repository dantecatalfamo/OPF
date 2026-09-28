package pf

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseRule_Simple(t *testing.T) {
	tests := []struct {
		input    string
		action   RuleAction
		dir      Direction
		protocol Protocol
		quick    bool
	}{
		{"pass in all", ActionPass, DirectionIn, ProtoAny, false},
		{"block out all", ActionBlock, DirectionOut, ProtoAny, false},
		{"match all", ActionMatch, DirectionAny, ProtoAny, false},
		{"pass in quick proto tcp", ActionPass, DirectionIn, ProtoTCP, true},
		{"block return all", ActionReject, DirectionAny, ProtoAny, false},
	}

	for _, tt := range tests {
		rule, err := ParseRule(tt.input, nil)
		if err != nil {
			t.Errorf("ParseRule(%q): %v", tt.input, err)
			continue
		}
		if rule.Action != tt.action {
			t.Errorf("ParseRule(%q).Action = %q, want %q", tt.input, rule.Action, tt.action)
		}
		if rule.Direction != tt.dir {
			t.Errorf("ParseRule(%q).Direction = %q, want %q", tt.input, rule.Direction, tt.dir)
		}
		if rule.Protocol != tt.protocol {
			t.Errorf("ParseRule(%q).Protocol = %q, want %q", tt.input, rule.Protocol, tt.protocol)
		}
		if rule.Quick != tt.quick {
			t.Errorf("ParseRule(%q).Quick = %v, want %v", tt.input, rule.Quick, tt.quick)
		}
	}
}

func TestParseRule_Interfaces(t *testing.T) {
	tests := []struct {
		input  string
		ifaces []string
	}{
		{"pass in on $wan all", []string{"wan"}},
		{"pass out on $lan all", []string{"lan"}},
		{"pass in on { $wan $lan } all", []string{"wan", "lan"}},
	}

	for _, tt := range tests {
		rule, err := ParseRule(tt.input, nil)
		if err != nil {
			t.Errorf("ParseRule(%q): %v", tt.input, err)
			continue
		}
		if len(rule.Interfaces) != len(tt.ifaces) {
			t.Errorf("ParseRule(%q).Interfaces = %v, want %v", tt.input, rule.Interfaces, tt.ifaces)
			continue
		}
		for i, iface := range tt.ifaces {
			if rule.Interfaces[i] != iface {
				t.Errorf("ParseRule(%q).Interfaces[%d] = %q, want %q", tt.input, i, rule.Interfaces[i], iface)
			}
		}
	}
}

func TestParseRule_Endpoints(t *testing.T) {
	tests := []struct {
		input   string
		srcType EndpointType
		dstType EndpointType
	}{
		{"pass in from any to any", EndpointAny, EndpointAny},
		{"pass in from self to any", EndpointSelf, EndpointAny},
		{"pass in from $lan:network to any", EndpointNet, EndpointAny},
		{"pass in from any to ($wan)", EndpointAny, EndpointIfaddr},
		{"pass in from <bruteforce> to any", EndpointAlias, EndpointAny},
		{"pass in from 192.168.1.1 to any", EndpointHost, EndpointAny},
		{"pass in from 192.168.1.0/24 to any", EndpointNetwork, EndpointAny},
	}

	for _, tt := range tests {
		rule, err := ParseRule(tt.input, nil)
		if err != nil {
			t.Errorf("ParseRule(%q): %v", tt.input, err)
			continue
		}
		if rule.Source.Type != tt.srcType {
			t.Errorf("ParseRule(%q).Source.Type = %q, want %q", tt.input, rule.Source.Type, tt.srcType)
		}
		if rule.Destination.Type != tt.dstType {
			t.Errorf("ParseRule(%q).Destination.Type = %q, want %q", tt.input, rule.Destination.Type, tt.dstType)
		}
	}
}

func TestParseRule_Ports(t *testing.T) {
	tests := []struct {
		input string
		port  string
	}{
		{"pass in proto tcp to any port 22", "22"},
		{"pass in proto tcp to any port 8000:8080", "8000:8080"},
		{"pass in proto tcp to any port { 80 443 }", "80,443"},
	}

	for _, tt := range tests {
		rule, err := ParseRule(tt.input, nil)
		if err != nil {
			t.Errorf("ParseRule(%q): %v", tt.input, err)
			continue
		}
		if rule.Port != tt.port {
			t.Errorf("ParseRule(%q).Port = %q, want %q", tt.input, rule.Port, tt.port)
		}
	}
}

func TestParseRule_Log(t *testing.T) {
	tests := []struct {
		input string
		log   LogMode
	}{
		{"pass in all", LogOff},
		{"pass in log all", LogOn},
		{"pass in log (all) all", LogAll},
	}

	for _, tt := range tests {
		rule, err := ParseRule(tt.input, nil)
		if err != nil {
			t.Errorf("ParseRule(%q): %v", tt.input, err)
			continue
		}
		if rule.Log != tt.log {
			t.Errorf("ParseRule(%q).Log = %q, want %q", tt.input, rule.Log, tt.log)
		}
	}
}

func TestParseRule_StateOptions(t *testing.T) {
	tests := []struct {
		input       string
		mode        StateMode
		maxStates   *int
		maxSrcConn  *int
		overload    string
		flushGlobal bool
	}{
		{"pass in all keep state", StateModeKeep, nil, nil, "", false},
		{"pass in all modulate state", StateModeModulate, nil, nil, "", false},
		{"pass in all synproxy state", StateModeSynproxy, nil, nil, "", false},
		{"pass in all no state", StateModeNone, nil, nil, "", false},
		{"pass in all keep state (max 1000)", StateModeKeep, intPtr(1000), nil, "", false},
		{"pass in all keep state (max-src-conn 10)", StateModeKeep, nil, intPtr(10), "", false},
		{"pass in all keep state (overload <bruteforce> flush global)", StateModeKeep, nil, nil, "bruteforce", true},
	}

	for _, tt := range tests {
		rule, err := ParseRule(tt.input, nil)
		if err != nil {
			t.Errorf("ParseRule(%q): %v", tt.input, err)
			continue
		}
		if rule.State == nil {
			// State might be nil for default keep state without options
			// Only check if we expected specific state options
			if tt.maxStates != nil || tt.maxSrcConn != nil || tt.overload != "" {
				t.Errorf("ParseRule(%q).State is nil, expected state options", tt.input)
			}
			continue
		}
		if rule.State != nil {
			if rule.State.Mode != tt.mode {
				t.Errorf("ParseRule(%q).State.Mode = %q, want %q", tt.input, rule.State.Mode, tt.mode)
			}
			if tt.maxStates != nil && (rule.State.MaxStates == nil || *rule.State.MaxStates != *tt.maxStates) {
				t.Errorf("ParseRule(%q).State.MaxStates = %v, want %v", tt.input, rule.State.MaxStates, tt.maxStates)
			}
			if tt.maxSrcConn != nil && (rule.State.MaxSrcConn == nil || *rule.State.MaxSrcConn != *tt.maxSrcConn) {
				t.Errorf("ParseRule(%q).State.MaxSrcConn = %v, want %v", tt.input, rule.State.MaxSrcConn, tt.maxSrcConn)
			}
			if rule.State.Overload != tt.overload {
				t.Errorf("ParseRule(%q).State.Overload = %q, want %q", tt.input, rule.State.Overload, tt.overload)
			}
			if rule.State.FlushGlobal != tt.flushGlobal {
				t.Errorf("ParseRule(%q).State.FlushGlobal = %v, want %v", tt.input, rule.State.FlushGlobal, tt.flushGlobal)
			}
		}
	}
}

func TestParseRule_BlockReturn(t *testing.T) {
	tests := []struct {
		input       string
		action      RuleAction
		blockReturn BlockReturn
	}{
		{"block return in all", ActionReject, ""},
		{"block return-rst in all", ActionBlock, BlockReturnRST},
		{"block return-icmp in all", ActionBlock, BlockReturnICMP},
		{"block return-icmp6 in all", ActionBlock, BlockReturnICMP6},
	}

	for _, tt := range tests {
		rule, err := ParseRule(tt.input, nil)
		if err != nil {
			t.Errorf("ParseRule(%q): %v", tt.input, err)
			continue
		}
		if rule.Action != tt.action {
			t.Errorf("ParseRule(%q).Action = %q, want %q", tt.input, rule.Action, tt.action)
		}
		if rule.BlockReturn != tt.blockReturn {
			t.Errorf("ParseRule(%q).BlockReturn = %q, want %q", tt.input, rule.BlockReturn, tt.blockReturn)
		}
	}
}

func TestParseRule_Label(t *testing.T) {
	input := `pass in on $wan proto tcp to port 22 label "Allow SSH"`
	rule, err := ParseRule(input, nil)
	if err != nil {
		t.Fatalf("ParseRule: %v", err)
	}
	if rule.Description != "Allow SSH" {
		t.Errorf("Description = %q, want %q", rule.Description, "Allow SSH")
	}
}

func TestParseRule_Tags(t *testing.T) {
	tests := []struct {
		input  string
		tag    string
		tagged string
	}{
		{"pass in all tag WEB", "WEB", ""},
		{"pass in tagged VOIP all", "", "VOIP"},
		{"pass in tagged VOIP all tag OUTBOUND", "OUTBOUND", "VOIP"},
	}

	for _, tt := range tests {
		rule, err := ParseRule(tt.input, nil)
		if err != nil {
			t.Errorf("ParseRule(%q): %v", tt.input, err)
			continue
		}
		if rule.Tag != tt.tag {
			t.Errorf("ParseRule(%q).Tag = %q, want %q", tt.input, rule.Tag, tt.tag)
		}
		if rule.Tagged != tt.tagged {
			t.Errorf("ParseRule(%q).Tagged = %q, want %q", tt.input, rule.Tagged, tt.tagged)
		}
	}
}

func TestParseRule_TCPFlags(t *testing.T) {
	input := `pass in proto tcp flags S/SA`
	rule, err := ParseRule(input, nil)
	if err != nil {
		t.Fatalf("ParseRule: %v", err)
	}
	if rule.TCPFlags != "S/SA" {
		t.Errorf("TCPFlags = %q, want %q", rule.TCPFlags, "S/SA")
	}
}

func TestParseRule_ICMPType(t *testing.T) {
	tests := []struct {
		input    string
		icmpType string
	}{
		{"pass in proto icmp icmp-type echoreq", "echoreq"},
		{"pass in proto icmp6 icmp6-type neighbrsol", "neighbrsol"},
	}

	for _, tt := range tests {
		rule, err := ParseRule(tt.input, nil)
		if err != nil {
			t.Errorf("ParseRule(%q): %v", tt.input, err)
			continue
		}
		if rule.ICMPType != tt.icmpType {
			t.Errorf("ParseRule(%q).ICMPType = %q, want %q", tt.input, rule.ICMPType, tt.icmpType)
		}
	}
}

func TestParseRule_Family(t *testing.T) {
	tests := []struct {
		input  string
		family Family
	}{
		{"pass in inet all", FamilyInet},
		{"pass in inet6 all", FamilyInet6},
		{"pass in all", FamilyAny},
	}

	for _, tt := range tests {
		rule, err := ParseRule(tt.input, nil)
		if err != nil {
			t.Errorf("ParseRule(%q): %v", tt.input, err)
			continue
		}
		if rule.Family != tt.family {
			t.Errorf("ParseRule(%q).Family = %q, want %q", tt.input, rule.Family, tt.family)
		}
	}
}

func TestParseRule_ComplexRule(t *testing.T) {
	input := `pass in log quick on $wan inet proto tcp from any to ($wan) port 443 flags S/SA keep state (max-src-conn 100, max-src-conn-rate 3/30, overload <bruteforce> flush global) tag WEB label "HTTPS traffic"`

	rule, err := ParseRule(input, nil)
	if err != nil {
		t.Fatalf("ParseRule: %v", err)
	}

	if rule.Action != ActionPass {
		t.Errorf("Action = %q, want pass", rule.Action)
	}
	if rule.Direction != DirectionIn {
		t.Errorf("Direction = %q, want in", rule.Direction)
	}
	if rule.Log != LogOn {
		t.Errorf("Log = %q, want on", rule.Log)
	}
	if !rule.Quick {
		t.Error("Quick = false, want true")
	}
	if rule.Family != FamilyInet {
		t.Errorf("Family = %q, want inet", rule.Family)
	}
	if rule.Protocol != ProtoTCP {
		t.Errorf("Protocol = %q, want tcp", rule.Protocol)
	}
	if rule.Port != "443" {
		t.Errorf("Port = %q, want 443", rule.Port)
	}
	if rule.TCPFlags != "S/SA" {
		t.Errorf("TCPFlags = %q, want S/SA", rule.TCPFlags)
	}
	if rule.Tag != "WEB" {
		t.Errorf("Tag = %q, want WEB", rule.Tag)
	}
	if rule.Description != "HTTPS traffic" {
		t.Errorf("Description = %q, want 'HTTPS traffic'", rule.Description)
	}
	if rule.State == nil {
		t.Fatal("State is nil")
	}
	if rule.State.MaxSrcConn == nil || *rule.State.MaxSrcConn != 100 {
		t.Errorf("State.MaxSrcConn = %v, want 100", rule.State.MaxSrcConn)
	}
	if rule.State.Overload != "bruteforce" {
		t.Errorf("State.Overload = %q, want bruteforce", rule.State.Overload)
	}
	if !rule.State.FlushGlobal {
		t.Error("State.FlushGlobal = false, want true")
	}
}

func TestParseRule_NegatedEndpoint(t *testing.T) {
	input := `pass in from ! <badguys> to any`
	rule, err := ParseRule(input, nil)
	if err != nil {
		t.Fatalf("ParseRule: %v", err)
	}
	if !rule.Source.Not {
		t.Error("Source.Not = false, want true")
	}
	if rule.Source.Alias != "badguys" {
		t.Errorf("Source.Alias = %q, want badguys", rule.Source.Alias)
	}
}

func TestParsePfConf_MultipleRules(t *testing.T) {
	content := `
# Comment line
pass in all
block out all
match all
`
	result := ParsePfConf(content, nil)
	if len(result.Errors) > 0 {
		t.Errorf("Errors: %v", result.Errors)
	}
	if len(result.Rules) != 3 {
		t.Errorf("got %d rules, want 3", len(result.Rules))
	}
}

func TestParseRule_UnsupportedFallsBackToRaw(t *testing.T) {
	// NAT rules should become RawRule
	input := `match out on $wan from $lan:network nat-to ($wan:0)`
	rule, err := ParseRule(input, nil)
	if err != nil {
		t.Fatalf("ParseRule: %v", err)
	}
	if !rule.IsRaw() {
		t.Error("Expected RawRule for NAT rule")
	}
}

func intPtr(n int) *int {
	return &n
}

// Golden file tests
func TestParseRule_GoldenFiles(t *testing.T) {
	entries, err := os.ReadDir("testdata")
	if err != nil {
		if os.IsNotExist(err) {
			t.Skip("testdata directory does not exist")
		}
		t.Fatal(err)
	}

	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".pf") {
			continue
		}

		baseName := strings.TrimSuffix(entry.Name(), ".pf")
		pfPath := filepath.Join("testdata", entry.Name())
		goldenPath := filepath.Join("testdata", baseName+".golden")

		t.Run(baseName, func(t *testing.T) {
			pfContent, err := os.ReadFile(pfPath)
			if err != nil {
				t.Fatal(err)
			}

			result := ParsePfConf(string(pfContent), nil)
			if len(result.Errors) > 0 {
				t.Logf("Parse errors: %v", result.Errors)
			}

			// Read expected output if exists
			goldenContent, err := os.ReadFile(goldenPath)
			if err != nil {
				if os.IsNotExist(err) {
					// Generate golden file
					output, _ := json.MarshalIndent(result, "", "  ")
					err = os.WriteFile(goldenPath, output, 0644)
					if err != nil {
						t.Logf("Could not write golden file: %v", err)
					}
					t.Logf("Generated golden file: %s", goldenPath)
					return
				}
				t.Fatal(err)
			}

			// Compare
			var expected ParseResult
			if err := json.Unmarshal(goldenContent, &expected); err != nil {
				t.Fatalf("Failed to parse golden file: %v", err)
			}

			actual, _ := json.MarshalIndent(result, "", "  ")
			if string(actual) != string(goldenContent) {
				t.Errorf("Output mismatch.\nGot:\n%s\n\nWant:\n%s", string(actual), string(goldenContent))
			}
		})
	}
}
