package pf

import (
	"testing"
)

// FuzzParseRule tests that the parser never panics on arbitrary input.
func FuzzParseRule(f *testing.F) {
	// Add seed corpus
	seeds := []string{
		"pass in all",
		"block out all",
		"match all",
		"pass in on em0 proto tcp to port 22",
		"block return out proto tcp",
		"pass in quick on $wan from any to ($wan) port 443 flags S/SA keep state",
		"pass in log (all) on { $wan $lan } from $lan:network to any",
		"block in from <bruteforce> to any",
		"match out on $wan from $lan:network nat-to ($wan:0)",
		"pass in proto tcp keep state (max 1000, max-src-conn 10)",
		"pass in proto tcp keep state (overload <table> flush global)",
		"pass in tagged WEB all tag OUTBOUND label \"test rule\"",
		"",
		"   ",
		"\t\n",
		"pass",
		"block",
		"match",
		"pass in on",
		"{ } ( )",
		"$",
		"<>",
		"><",
		"!=",
		">=",
		"<=",
		"from to port",
		"pass in from 192.168.1.1/24 to 10.0.0.0/8",
		"pass in from fe80::1 to 2001:db8::1",
		"pass in proto { tcp udp icmp }",
		"pass in probability 50%",
		"pass in once",
		"set prio 7",
		"rtable 1",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		// Should never panic
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("ParseRule panicked on input %q: %v", input, r)
			}
		}()

		ParseRule(input, nil)
	})
}

// FuzzParsePfConf tests that parsing a full config never panics.
func FuzzParsePfConf(f *testing.F) {
	seeds := []string{
		"pass in all\nblock out all",
		"# comment\npass in all",
		"pass in \\\non em0",
		"table <bad> persist\nblock in from <bad>",
		"",
		"\n\n\n",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("ParsePfConf panicked on input %q: %v", input, r)
			}
		}()

		ParsePfConf(input, nil)
	})
}

// FuzzTokenize tests that the tokenizer never panics.
func FuzzTokenize(f *testing.F) {
	seeds := []string{
		"pass in all",
		"$macro <table> 192.168.1.1/24",
		"\"string with \\\" escape\"",
		"port 8000:8080",
		">= <= != <> ><",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Tokenize panicked on input %q: %v", input, r)
			}
		}()

		Tokenize(input)
	})
}
