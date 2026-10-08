package web

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
)

// fakeLookup answers from names; an address not there isn't found, and
// fail's fail. It counts the lookups it was asked for.
type fakeLookup struct {
	mu    sync.Mutex
	names map[string][]string
	fail  map[string]bool
	asked map[string]int
}

func (f *fakeLookup) lookup(_ context.Context, addr string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked[addr]++
	if f.fail[addr] {
		return nil, errors.New("connection refused")
	}
	if n, ok := f.names[addr]; ok {
		return n, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: addr, IsNotFound: true}
}

func TestReverseNames(t *testing.T) {
	f := &fakeLookup{
		names: map[string][]string{
			"192.168.1.112": {"priya-mbp.office.arpa."},
			"93.184.215.14": {"bad name!.example.", "example.com."}, // the first isn't a host name
			"198.51.100.9":  {"<script>.example."},
		},
		fail:  map[string]bool{"203.0.113.53": true},
		asked: map[string]int{},
	}
	s := newServer(t)
	s.SetReverseLookup(f.lookup)
	c := client{t, s}
	var out reverseResult
	c.do("POST", "/api/dns/reverse", `{"addresses":["192.168.1.112","93.184.215.14","198.51.100.9","10.0.0.9","203.0.113.53","::ffff:192.168.1.112"]}`, 200, &out)
	want := map[string]string{"192.168.1.112": "priya-mbp.office.arpa", "93.184.215.14": "example.com", "198.51.100.9": "", "10.0.0.9": ""}
	if len(out.Names) != len(want) {
		t.Errorf("names %v, want %v", out.Names, want)
	}
	for a, n := range want {
		if got, ok := out.Names[a]; !ok || got != n {
			t.Errorf("%s: %q, want %q", a, got, n)
		}
	}
	if len(out.Failed) != 1 || out.Failed[0] != "203.0.113.53" {
		t.Errorf("failed %v", out.Failed)
	}
	// Asked again: names and not-found are kept; the mapped address was
	// the same one, looked up once.
	c.do("POST", "/api/dns/reverse", `{"addresses":["192.168.1.112","10.0.0.9"]}`, 200, &out)
	if f.asked["192.168.1.112"] != 1 || f.asked["10.0.0.9"] != 1 {
		t.Errorf("looked up again: %v", f.asked)
	}

	// Not addresses, and too many.
	c.do("POST", "/api/dns/reverse", `{"addresses":["example.com"]}`, 400, nil)
	c.do("POST", "/api/dns/reverse", `{"addresses":["fe80::1%em0"]}`, 400, nil)
	many := make([]string, reverseMax+1)
	for i := range many {
		many[i] = `"10.0.0.1"`
	}
	c.do("POST", "/api/dns/reverse", `{"addresses":[`+strings.Join(many, ",")+`]}`, 400, nil)
}

func TestReverseNamesNeedsASession(t *testing.T) {
	b := &browser{t: t, s: newAuthServer(t)}
	b.do("POST", "/api/dns/reverse", `{"addresses":["192.0.2.1"]}`, 401)
	b.do("POST", "/api/session", `{"user":"viewer","password":"viewer-pass"}`, 200)
	b.s.SetReverseLookup((&fakeLookup{asked: map[string]int{}}).lookup)
	b.do("POST", "/api/dns/reverse", `{"addresses":["192.0.2.1"]}`, 200)
}

func TestHostName(t *testing.T) {
	for in, want := range map[string]string{
		"host.example.":                 "host.example",
		"a_b-c.example":                 "a_b-c.example",
		"":                              "",
		".":                             "",
		"a..b":                          "",
		"bad name.example":              "",
		"\x1b[31mred.example":           "",
		strings.Repeat("a", 64):         "",
		strings.Repeat("a.", 127):       strings.Repeat("a.", 126) + "a", // 253, the most
		strings.Repeat("a.", 127) + "a": "",                              // 255
		"xn--bcher-kva.example.":        "xn--bcher-kva.example",
		"bücher.example":                "",
		"semi;colon.example":            "",
		"quote\".example":               "",
		"lt<gt>.example":                "",
		"slash/.example":                "",
		"10.in-addr.arpa.":              "10.in-addr.arpa",
		strings.Repeat("a", 63):         strings.Repeat("a", 63),
		strings.Repeat("ab.", 84):       strings.Repeat("ab.", 83) + "ab",
		strings.Repeat("ab.", 85):       "",
		"trailing-dash-.example.":       "trailing-dash-.example",
		"UPPER.Example.":                "UPPER.Example",
		"tab\t.example":                 "",
		"null\x00.example":              "",
		"space .example":                "",
		"percent%.example":              "",
		"at@.example":                   "",
		"colon:.example":                "",
		"comma,.example":                "",
		"emoji\U0001F600.example":       "",
		"dot-at-end..":                  "",
		"a.b.c.d.e.f.g.h.i.j.k.l.m":     "a.b.c.d.e.f.g.h.i.j.k.l.m",
	} {
		if got := hostName(in); got != want {
			t.Errorf("hostName(%q) = %q, want %q", in, got, want)
		}
	}
}
