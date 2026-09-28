package pf

import (
	"strings"
	"testing"
	"time"
)

// finishes fails the test instead of hanging the suite if fn doesn't
// return promptly. The parser must terminate on every input.
func finishes(t *testing.T, name string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("%s did not terminate", name)
	}
}

// Inputs found by fuzzing that used to loop forever, plus close
// variants of each.
var hangInputs = []string{
	"pass in log (all) on { $wan \x00lan } from $lan:network to any",
	"pass in on { $wan 42 } all",
	"pass in on { $wan ( } all",
	"pass in proto { tcp \x00 } all",
	"pass in proto tcp to port { 22 ( } ",
	"pass in on { $wan",
	"\xf8\xb90\xb10\xa10X:0\xe4\x9a`I'ҕ\xce\xcb",
	"é:x",
	"a\xe4:b",
	"pass in on em0 label \"caf\xe9\"",
	"<\xe4>",
	"$\xe4",
	"pass in from (em0:0:network) to any",
	"pass in from 0:b to any",
}

func TestParserTerminates(t *testing.T) {
	for _, in := range hangInputs {
		finishes(t, "Tokenize "+strconvQuote(in), func() { Tokenize(in) })
		finishes(t, "ParseRule "+strconvQuote(in), func() { ParseRule(in, nil) })
		finishes(t, "ParsePfConf "+strconvQuote(in), func() { ParsePfConf(in, nil) })
	}
}

func strconvQuote(s string) string {
	return strings.ReplaceAll(strings.ToValidUTF8(s, "?"), "\x00", `\x00`)
}

// Every token must cover input the tokenizer actually consumed: the
// old rune/byte mix-up let identifiers rewind past their own start.
func TestTokenizerAdvances(t *testing.T) {
	for _, in := range hangInputs {
		tz := NewTokenizer(in)
		last := -1
		for i := 0; ; i++ {
			if i > len(in)+2 {
				t.Fatalf("%q: more tokens than bytes", in)
			}
			tok := tz.Next()
			if tz.pos <= last && tok.Type != TokenEOF {
				t.Fatalf("%q: tokenizer went from %d to %d", in, last, tz.pos)
			}
			last = tz.pos
			if tok.Type == TokenEOF {
				break
			}
		}
	}
}

// Rules the guided form can't represent exactly are kept as raw rules
// rather than parsed into something broader.
func TestParseRule_FallsBackToRaw(t *testing.T) {
	for _, in := range []string{
		"pass in on { $wan \x00lan } from $lan:network to any",
		"pass in proto { tcp udp icmp } all",
		"pass in proto 47 all",
		"pass in proto { tcp ( } all",
		"pass in proto tcp to port { 22 ( }",
	} {
		rule, err := ParseRule(in, nil)
		if err != nil {
			t.Errorf("ParseRule(%q): %v", in, err)
			continue
		}
		if rule == nil || rule.Kind != "raw" {
			t.Errorf("ParseRule(%q) = %+v, want a raw rule", in, rule)
		}
	}
}

// pf allows the host to be omitted before "port".
func TestParseRule_PortWithoutHost(t *testing.T) {
	for in, want := range map[string]string{
		"pass in proto tcp to port 22":              "22",
		"pass in proto tcp to port { 22 443 }":      "22,443",
		"pass in proto tcp from port > 1023":        "",
		"pass in proto tcp from any to any port 22": "22",
	} {
		rule, err := ParseRule(in, nil)
		if err != nil || rule.Kind != "form" {
			t.Errorf("ParseRule(%q) = %+v, %v; want a form rule", in, rule, err)
			continue
		}
		if rule.Port != want {
			t.Errorf("ParseRule(%q).Port = %q, want %q", in, rule.Port, want)
		}
	}
}

func TestParseRule_ProtocolLists(t *testing.T) {
	for in, want := range map[string]Protocol{
		"pass in proto { tcp udp } all":  ProtoTCPUDP,
		"pass in proto { udp, tcp } all": ProtoTCPUDP,
		"pass in proto { icmp } all":     ProtoICMP,
	} {
		rule, err := ParseRule(in, nil)
		if err != nil || rule.Kind != "form" || rule.Protocol != want {
			t.Errorf("ParseRule(%q) = %+v, %v; want form rule with %q", in, rule, err, want)
		}
	}
}

// A missing closing brace must not swallow the following lines.
func TestParsePfConf_UnclosedBrace(t *testing.T) {
	res := ParsePfConf("pass in on { $wan $lan\nblock in all\n", nil)
	if len(res.Rules) != 2 {
		t.Fatalf("got %d rules, want 2: %+v", len(res.Rules), res.Rules)
	}
	if res.Rules[1].Kind != "form" || res.Rules[1].Action != ActionBlock {
		t.Errorf("second rule = %+v, want the block rule", res.Rules[1])
	}
}

// Quoted strings are copied byte for byte, so UTF-8 labels survive.
func TestTokenize_StringBytes(t *testing.T) {
	toks := Tokenize(`label "café ☕"`)
	if len(toks) < 2 || toks[1].Type != TokenString || toks[1].Value != "café ☕" {
		t.Fatalf("tokens = %+v", toks)
	}
}
