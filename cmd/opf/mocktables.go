package main

import (
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/dantecatalfamo/OPF/internal/pf"
)

// What the mock's pf tables hold: the dynamic tables a rule's overload
// fills (bruteforce starts with the scanners its firewall log shows),
// changed by pfctl -T add, delete, flush and expire as pf would, and a
// downloaded list's table, from the list mockList serves.

type mockTableEntry struct {
	addr    string
	negated bool
	added   time.Time
}

type mockTableStore struct {
	mu     sync.Mutex
	tables map[string][]mockTableEntry
}

func (t *mockTableStore) seed(now time.Time) {
	if t.tables != nil {
		return
	}
	t.tables = map[string][]mockTableEntry{
		"bruteforce": {
			{addr: "185.220.101.4", added: now.Add(-7 * time.Minute)},
			{addr: "162.142.125.9", added: now.Add(-48 * time.Minute)},
			{addr: "45.95.147.10", added: now.Add(-3*time.Hour - 12*time.Minute)},
			{addr: "198.51.100.23", added: now.Add(-26 * time.Hour)},
		},
	}
}

// handle answers pfctl -t <table> -T <op> [-v | addresses...] for a
// table or URL alias of m; ok is false for anything else.
func (t *mockTableStore) handle(m *pf.Model, argv []string, now time.Time) (out string, ok bool, err error) {
	if len(argv) < 5 || argv[0] != "pfctl" || argv[1] != "-t" || argv[3] != "-T" {
		return "", false, nil
	}
	name, op, rest := argv[2], argv[4], argv[5:]
	var alias *pf.Alias
	for i := range m.Firewall.Aliases {
		if a := &m.Firewall.Aliases[i]; a.Name == name && (a.Type == pf.AliasTable || a.Type == pf.AliasURL) {
			alias = a
		}
	}
	if alias == nil {
		return "", false, nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.seed(now)
	if alias.Type == pf.AliasURL {
		if op != "show" {
			return "", false, nil
		}
		var b strings.Builder
		for _, l := range strings.Split(mockList(alias.URL), "\n") {
			if f := strings.Fields(l); len(f) > 0 {
				if _, err := netip.ParsePrefix(f[0]); err == nil {
					fmt.Fprintf(&b, "   %s\n", f[0])
				}
			}
		}
		return b.String(), true, nil
	}
	entries := t.tables[name]
	switch op {
	case "show":
		var b strings.Builder
		for _, e := range entries {
			mark := " "
			if e.negated {
				mark = "!"
			}
			fmt.Fprintf(&b, "  %s%s\n", mark, e.addr)
			if len(rest) > 0 && rest[0] == "-v" {
				fmt.Fprintf(&b, "\tCleared:     %s\n", e.added.Format("Mon Jan _2 15:04:05 2006"))
			}
		}
		return b.String(), true, nil
	case "add":
		n := 0
		for _, a := range rest {
			if !hasEntry(entries, a) {
				entries = append(entries, mockTableEntry{addr: a, added: now})
				n++
			}
		}
		t.tables[name] = entries
		return fmt.Sprintf("%d/%d addresses added.\n", n, len(rest)), true, nil
	case "delete":
		n := 0
		for _, a := range rest {
			for i, e := range entries {
				if e.addr == a {
					entries = append(entries[:i], entries[i+1:]...)
					n++
					break
				}
			}
		}
		t.tables[name] = entries
		return fmt.Sprintf("%d/%d addresses deleted.\n", n, len(rest)), true, nil
	case "flush":
		t.tables[name] = nil
		return fmt.Sprintf("%d addresses deleted.\n", len(entries)), true, nil
	case "expire":
		var secs int
		fmt.Sscan(strings.Join(rest, ""), &secs)
		kept := entries[:0]
		for _, e := range entries {
			if now.Sub(e.added) <= time.Duration(secs)*time.Second {
				kept = append(kept, e)
			}
		}
		n := len(entries) - len(kept)
		t.tables[name] = kept
		return fmt.Sprintf("%d/%d addresses expired.\n", n, n), true, nil
	}
	return "", false, nil
}

func hasEntry(entries []mockTableEntry, a string) bool {
	for _, e := range entries {
		if e.addr == a {
			return true
		}
	}
	return false
}
