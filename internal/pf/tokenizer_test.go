package pf

import (
	"testing"
)

func TestTokenizer_SimpleRule(t *testing.T) {
	input := `pass in on em0 proto tcp to port 22`
	tokens := Tokenize(input)

	expected := []struct {
		typ TokenType
		val string
	}{
		{TokenKeyword, "pass"},
		{TokenKeyword, "in"},
		{TokenKeyword, "on"},
		{TokenIdent, "em0"},
		{TokenKeyword, "proto"},
		{TokenKeyword, "tcp"},
		{TokenKeyword, "to"},
		{TokenKeyword, "port"},
		{TokenNumber, "22"},
		{TokenEOF, ""},
	}

	if len(tokens) != len(expected) {
		t.Fatalf("expected %d tokens, got %d", len(expected), len(tokens))
	}

	for i, exp := range expected {
		if tokens[i].Type != exp.typ {
			t.Errorf("token %d: expected type %s, got %s", i, exp.typ, tokens[i].Type)
		}
		if tokens[i].Value != exp.val {
			t.Errorf("token %d: expected value %q, got %q", i, exp.val, tokens[i].Value)
		}
	}
}

func TestTokenizer_Macros(t *testing.T) {
	input := `pass in on $wan from $lan:network`
	tokens := Tokenize(input)

	var macros []string
	for _, tok := range tokens {
		if tok.Type == TokenMacro {
			macros = append(macros, tok.Value)
		}
	}

	if len(macros) != 2 || macros[0] != "wan" || macros[1] != "lan" {
		t.Errorf("expected macros [wan, lan], got %v", macros)
	}
}

func TestTokenizer_Tables(t *testing.T) {
	input := `block in from <bruteforce> to any`
	tokens := Tokenize(input)

	var tables []string
	for _, tok := range tokens {
		if tok.Type == TokenTable {
			tables = append(tables, tok.Value)
		}
	}

	if len(tables) != 1 || tables[0] != "bruteforce" {
		t.Errorf("expected tables [bruteforce], got %v", tables)
	}
}

func TestTokenizer_IPv4(t *testing.T) {
	input := `from 192.168.1.1 to 10.0.0.1`
	tokens := Tokenize(input)

	var ips []string
	for _, tok := range tokens {
		if tok.Type == TokenIPv4 {
			ips = append(ips, tok.Value)
		}
	}

	if len(ips) != 2 || ips[0] != "192.168.1.1" || ips[1] != "10.0.0.1" {
		t.Errorf("expected IPs [192.168.1.1, 10.0.0.1], got %v", ips)
	}
}

func TestTokenizer_CIDR(t *testing.T) {
	input := `from 192.168.1.0/24 to 10.0.0.0/8`
	tokens := Tokenize(input)

	var cidrs []string
	for _, tok := range tokens {
		if tok.Type == TokenCIDR {
			cidrs = append(cidrs, tok.Value)
		}
	}

	if len(cidrs) != 2 || cidrs[0] != "192.168.1.0/24" || cidrs[1] != "10.0.0.0/8" {
		t.Errorf("expected CIDRs [192.168.1.0/24, 10.0.0.0/8], got %v", cidrs)
	}
}

func TestTokenizer_PortRange(t *testing.T) {
	input := `port 8000:8080`
	tokens := Tokenize(input)

	found := false
	for _, tok := range tokens {
		if tok.Type == TokenNumber && tok.Value == "8000:8080" {
			found = true
			break
		}
	}

	if !found {
		t.Error("expected port range 8000:8080")
	}
}

func TestTokenizer_String(t *testing.T) {
	input := `label "Allow SSH from anywhere"`
	tokens := Tokenize(input)

	found := false
	for _, tok := range tokens {
		if tok.Type == TokenString && tok.Value == "Allow SSH from anywhere" {
			found = true
			break
		}
	}

	if !found {
		t.Error("expected string 'Allow SSH from anywhere'")
	}
}

func TestTokenizer_LineContinuation(t *testing.T) {
	input := "pass in \\\non em0"
	tokens := Tokenize(input)

	// Should not have a newline between "in" and "on"
	values := []string{}
	for _, tok := range tokens {
		if tok.Type != TokenEOF && tok.Type != TokenNewline {
			values = append(values, tok.Value)
		}
	}

	expected := []string{"pass", "in", "on", "em0"}
	if len(values) != len(expected) {
		t.Fatalf("expected %v, got %v", expected, values)
	}
	for i, v := range expected {
		if values[i] != v {
			t.Errorf("position %d: expected %q, got %q", i, v, values[i])
		}
	}
}

func TestTokenizer_Comment(t *testing.T) {
	input := `pass in # allow incoming
block out`
	tokens := Tokenize(input)

	// Comment should be skipped
	keywordCount := 0
	for _, tok := range tokens {
		if tok.Type == TokenKeyword {
			keywordCount++
		}
	}

	if keywordCount != 4 { // pass, in, block, out
		t.Errorf("expected 4 keywords, got %d", keywordCount)
	}
}

func TestTokenizer_Operators(t *testing.T) {
	tests := []struct {
		input string
		typ   TokenType
		val   string
	}{
		{"> 1023", TokenGT, ">"},
		{">= 80", TokenGTE, ">="},
		{"< 1024", TokenLT, "<"},
		{"<= 443", TokenLTE, "<="},
		{"!= 22", TokenNE, "!="},
		{">< 80", TokenRange, "><"},
		{"<> 22", TokenExclude, "<>"},
	}

	for _, tt := range tests {
		tokens := Tokenize(tt.input)
		found := false
		for _, tok := range tokens {
			if tok.Type == tt.typ && tok.Value == tt.val {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("input %q: expected %s %q", tt.input, tt.typ, tt.val)
		}
	}
}

func TestTokenizer_Braces(t *testing.T) {
	input := `proto { tcp udp }`
	tokens := Tokenize(input)

	braceCount := 0
	for _, tok := range tokens {
		if tok.Type == TokenLBrace || tok.Type == TokenRBrace {
			braceCount++
		}
	}

	if braceCount != 2 {
		t.Errorf("expected 2 braces, got %d", braceCount)
	}
}

func TestTokenizer_Parens(t *testing.T) {
	input := `to ($wan)`
	tokens := Tokenize(input)

	parenCount := 0
	for _, tok := range tokens {
		if tok.Type == TokenLParen || tok.Type == TokenRParen {
			parenCount++
		}
	}

	if parenCount != 2 {
		t.Errorf("expected 2 parens, got %d", parenCount)
	}
}

func TestTokenizer_StateOptions(t *testing.T) {
	input := `keep state (max 1000, max-src-conn 10, max-src-conn-rate 3/30, overload <bruteforce> flush global)`
	tokens := Tokenize(input)

	// Check for expected keywords
	expectedKeywords := []string{"keep", "state", "max", "max-src-conn", "max-src-conn-rate", "overload", "flush", "global"}
	keywordsFound := make(map[string]bool)
	for _, tok := range tokens {
		if tok.Type == TokenKeyword {
			keywordsFound[tok.Value] = true
		}
	}

	for _, kw := range expectedKeywords {
		if !keywordsFound[kw] {
			t.Errorf("expected keyword %q not found", kw)
		}
	}
}

func TestTokenizer_ComplexRule(t *testing.T) {
	input := `pass in log quick on $wan proto tcp from any to ($wan) port 443 flags S/SA keep state (max-src-conn 100) tag WEB label "HTTPS traffic"`
	tokens := Tokenize(input)

	// Just verify it doesn't error and produces tokens
	if len(tokens) < 20 {
		t.Errorf("expected many tokens, got %d", len(tokens))
	}

	// Verify no errors
	for _, tok := range tokens {
		if tok.Type == TokenError {
			t.Errorf("unexpected error token: %s", tok.Value)
		}
	}
}

func TestTokenizer_LineNumbers(t *testing.T) {
	input := `pass in
block out`
	tokens := Tokenize(input)

	// First token should be line 1
	if tokens[0].Line != 1 {
		t.Errorf("first token: expected line 1, got %d", tokens[0].Line)
	}

	// Find "block" - should be line 2
	for _, tok := range tokens {
		if tok.Value == "block" {
			if tok.Line != 2 {
				t.Errorf("block token: expected line 2, got %d", tok.Line)
			}
			break
		}
	}
}

func TestTokenizer_NATRule(t *testing.T) {
	input := `match out on $wan from $lan:network nat-to ($wan:0) round-robin`
	tokens := Tokenize(input)

	expectedKeywords := []string{"match", "out", "on", "from", "nat-to", "round-robin"}
	keywordsFound := make(map[string]bool)
	for _, tok := range tokens {
		if tok.Type == TokenKeyword {
			keywordsFound[tok.Value] = true
		}
	}

	for _, kw := range expectedKeywords {
		if !keywordsFound[kw] {
			t.Errorf("expected keyword %q not found", kw)
		}
	}
}

func TestTokenizer_BlockReturn(t *testing.T) {
	input := `block return-rst ttl 64 in on $wan`
	tokens := Tokenize(input)

	expectedKeywords := []string{"block", "return-rst", "ttl", "in", "on"}
	keywordsFound := make(map[string]bool)
	for _, tok := range tokens {
		if tok.Type == TokenKeyword {
			keywordsFound[tok.Value] = true
		}
	}

	for _, kw := range expectedKeywords {
		if !keywordsFound[kw] {
			t.Errorf("expected keyword %q not found", kw)
		}
	}
}

func TestTokenizer_IPv6(t *testing.T) {
	input := `from fe80::1 to 2001:db8::1`
	tokens := Tokenize(input)

	var ipv6s []string
	for _, tok := range tokens {
		if tok.Type == TokenIPv6 {
			ipv6s = append(ipv6s, tok.Value)
		}
	}

	if len(ipv6s) != 2 {
		t.Errorf("expected 2 IPv6 addresses, got %d: %v", len(ipv6s), ipv6s)
	}
}

func TestTokenizer_NetworkKeyword(t *testing.T) {
	input := `$lan:network`
	tokens := Tokenize(input)

	// Should have macro "lan", colon, and keyword "network"
	if len(tokens) < 3 {
		t.Fatalf("expected at least 3 tokens, got %d", len(tokens))
	}

	if tokens[0].Type != TokenMacro || tokens[0].Value != "lan" {
		t.Errorf("expected macro 'lan', got %s %q", tokens[0].Type, tokens[0].Value)
	}
	if tokens[1].Type != TokenColon {
		t.Errorf("expected colon, got %s", tokens[1].Type)
	}
	if tokens[2].Type != TokenKeyword || tokens[2].Value != "network" {
		t.Errorf("expected keyword 'network', got %s %q", tokens[2].Type, tokens[2].Value)
	}
}
