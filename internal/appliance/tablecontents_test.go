package appliance

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// pfctl -t opft -T show -v, from the test VM (7.9).
const tableShowV = `   192.0.2.0/24
	Cleared:     Thu Oct  8 00:45:58 2026
  !192.0.2.128/25
	Cleared:     Thu Oct  8 00:45:58 2026
   198.51.100.7
	Cleared:     Thu Oct  8 00:47:10 2026
`

func TestParseTableShow(t *testing.T) {
	es := parseTableShow(tableShowV, time.UTC)
	if len(es) != 3 {
		t.Fatalf("%d entries: %+v", len(es), es)
	}
	if es[1].Address != "192.0.2.128/25" || !es[1].Negated || es[0].Negated {
		t.Errorf("negated: %+v", es)
	}
	want := time.Date(2026, 10, 8, 0, 47, 10, 0, time.UTC)
	if es[2].Address != "198.51.100.7" || es[2].Added == nil || !es[2].Added.Equal(want) {
		t.Errorf("last entry %+v", es[2])
	}
	// Without -v: addresses only.
	if es := parseTableShow("   10.0.0.0/8\n   192.0.2.1\n", time.UTC); len(es) != 2 || es[0].Added != nil {
		t.Errorf("without -v: %+v", es)
	}
	if es := parseTableShow("", time.UTC); es == nil || len(es) != 0 {
		t.Errorf("empty: %#v", es)
	}
}

func TestBestEntry(t *testing.T) {
	es := parseTableShow(tableShowV, time.UTC)
	for addr, want := range map[string]string{
		"192.0.2.5":    "192.0.2.0/24", // in the network
		"192.0.2.200":  "",             // in the negated half
		"198.51.100.7": "198.51.100.7", // the address itself
		"198.51.100.8": "",             // not there
	} {
		e := bestEntry(es, netip.MustParseAddr(addr))
		got := ""
		if e != nil {
			got = e.Address
		}
		if got != want {
			t.Errorf("%s: %q, want %q", addr, got, want)
		}
	}
}

// tableRunner answers pfctl -T for the sample's tables: bruteforce
// holds two addresses, blocklist (a URL alias) one network; it records
// the changes it was asked for.
type tableRunner struct {
	mu      sync.Mutex
	changes []string
}

func (r *tableRunner) Run(_ context.Context, argv ...string) ([]byte, error) {
	cmd := strings.Join(argv, " ")
	switch {
	case cmd == "pfctl -t bruteforce -T show -v":
		return []byte("   203.0.113.9\n\tCleared:     Thu Oct  8 00:40:00 2026\n   198.51.100.23\n\tCleared:     Thu Oct  8 00:50:00 2026\n"), nil
	case cmd == "pfctl -t blocklist -T show":
		return []byte("   45.90.0.0/24\n   45.91.37.0/24\n"), nil
	case strings.HasPrefix(cmd, "pfctl -t") && strings.Contains(cmd, "-T show"):
		return []byte("pfctl: Table does not exist.\n"), errors.New("exit status 255")
	case strings.Contains(cmd, " -T add ") || strings.Contains(cmd, " -T delete ") || strings.HasSuffix(cmd, " -T flush"):
		r.mu.Lock()
		r.changes = append(r.changes, cmd)
		r.mu.Unlock()
		return []byte("1/1 addresses added.\n"), nil
	}
	return nil, nil
}

func TestTableContents(t *testing.T) {
	e := newEnv(t, time.Minute)
	r := &tableRunner{}
	e.m.Runner, e.m.Actions = r, r
	m := e.live().Model
	n := 60
	for i := range m.Firewall.Aliases {
		if m.Firewall.Aliases[i].Name == "bruteforce" {
			m.Firewall.Aliases[i].ExpireMinutes = &n
		}
	}
	if err := stageCommit(t, e, m); err != nil {
		t.Fatal(err)
	}

	got, err := e.m.TableEntries(TableEntriesRequest{Table: "bruteforce"})
	if err != nil {
		t.Fatal(err)
	}
	// Newest first, each with when it expires; the rule that fills it.
	if got.Kind != "dynamic" || !got.Loaded || got.Total != 2 || len(got.Entries) != 2 || got.Entries[0].Address != "198.51.100.23" {
		t.Fatalf("bruteforce: %+v", got)
	}
	if ex := got.Entries[0].Expires; ex == nil || ex.Sub(*got.Entries[0].Added) != time.Hour {
		t.Errorf("expires %v", ex)
	}
	if len(got.FilledBy) != 1 || got.FilledBy[0].ID != "r9" {
		t.Errorf("filled by %+v", got.FilledBy)
	}
	// Searched, and a page.
	if got, _ := e.m.TableEntries(TableEntriesRequest{Table: "bruteforce", Query: "203.0"}); got.Matching != 1 || got.Total != 2 || got.Entries[0].Address != "203.0.113.9" {
		t.Errorf("searched: %+v", got)
	}
	if got, _ := e.m.TableEntries(TableEntriesRequest{Table: "bruteforce", Offset: 1, Limit: 1}); len(got.Entries) != 1 || got.Entries[0].Address != "203.0.113.9" {
		t.Errorf("second page: %+v", got)
	}
	// A list: no dates. A fixed alias, or a table pf has nothing of, isn't
	// a table to read; one not yet loaded says so.
	if got, _ := e.m.TableEntries(TableEntriesRequest{Table: "blocklist"}); got.Kind != "list" || got.Total != 2 || got.Entries[0].Added != nil {
		t.Errorf("blocklist: %+v", got)
	}
	if _, err := e.m.TableEntries(TableEntriesRequest{Table: "internal"}); code(err) != CodeNotFound {
		t.Errorf("a fixed alias: %v", err)
	}
	if _, err := e.m.TableEntries(TableEntriesRequest{Table: "opf_hosts"}); code(err) != CodeNotFound {
		t.Errorf("OPF's own table: %v", err)
	}

	// Found across tables, with the rules that use each.
	f, err := e.m.TableFind("45.91.37.12")
	if err != nil || len(f.Tables) != 1 || f.Tables[0].Table != "blocklist" || f.Tables[0].Entry != "45.91.37.0/24" || len(f.Tables[0].UsedBy) == 0 {
		t.Errorf("find in the list: %+v %v", f, err)
	}
	if f, _ := e.m.TableFind("203.0.113.9"); len(f.Tables) != 1 || f.Tables[0].Table != "bruteforce" || f.Tables[0].Expires == nil {
		t.Errorf("find in bruteforce: %+v", f)
	}
	if _, err := e.m.TableFind("203.0.113.0/24"); code(err) != CodeInvalid {
		t.Errorf("a network to find: %v", err)
	}

	// Changes: a dynamic table's, recorded; never a list's, nor bad input.
	if err := e.m.TableChange(TableChangeRequest{Table: "bruteforce", Op: "delete", Addresses: []string{"203.0.113.9"}, By: "admin"}); err != nil {
		t.Fatal(err)
	}
	if err := e.m.TableChange(TableChangeRequest{Table: "bruteforce", Op: "add", Addresses: []string{"192.0.2.0/24", "::ffff:192.0.2.7"}}); err != nil {
		t.Fatal(err)
	}
	if err := e.m.TableChange(TableChangeRequest{Table: "bruteforce", Op: "flush"}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []TableChangeRequest{
		{Table: "blocklist", Op: "delete", Addresses: []string{"45.90.0.0/24"}},
		{Table: "bruteforce", Op: "add", Addresses: []string{"300.1.1.1"}},
		{Table: "bruteforce", Op: "add", Addresses: []string{"-f /etc/pf.conf"}},
		{Table: "bruteforce", Op: "add"},
		{Table: "bruteforce", Op: "kill"},
		{Table: "internal", Op: "flush"},
	} {
		if err := e.m.TableChange(bad); err == nil {
			t.Errorf("%+v: no error", bad)
		}
	}
	want := []string{"pfctl -t bruteforce -T delete 203.0.113.9", "pfctl -t bruteforce -T add 192.0.2.0/24 192.0.2.7", "pfctl -t bruteforce -T flush"}
	if strings.Join(r.changes, "\n") != strings.Join(want, "\n") {
		t.Errorf("ran\n%s\nwant\n%s", strings.Join(r.changes, "\n"), strings.Join(want, "\n"))
	}
	ev, _ := e.m.Events(EventsRequest{Kinds: []string{EventTable}})
	if len(ev.Events) != 3 || !strings.Contains(ev.Events[2].Message, "admin took 203.0.113.9 out of <bruteforce>") || ev.Events[2].Subject != "bruteforce" {
		t.Errorf("events %+v", ev.Events)
	}
}
