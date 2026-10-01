package appliance

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dantecatalfamo/OPF/internal/pf"
)

func sampleLines(t *testing.T, name string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "dnslists", name))
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(string(b), "\n")
}

// The first 300 lines of real, widely used lists, fetched from their
// publishers: every name in them is read, and nothing else.
func TestParseRealLists(t *testing.T) {
	for _, tc := range []struct {
		file    string
		blocked int
		first   string
		skipped map[string]int
	}{
		{"stevenblack-hosts.txt", 261, "010sec.com", nil},
		// ||name^ blocks the name and everything under it; two rules are
		// for addresses, which DNS can't block.
		{"adguard-dns.txt", 548, "*.0xclicks.com", map[string]int{skipAddress: 2}},
		{"hagezi-pro-domains.txt", 287, "0.07c225f3.online", nil},
		// *.name lines: the name and everything under it.
		{"hagezi-pro-wildcard.txt", 574, "*.0.07c225f3.online", nil},
		{"hagezi-pro-rpz.txt", 283, "*.1xslots.africa", nil},
		{"oisd-small-rpz.txt", 286, "*.0-02.net", nil},
		// A browser list: none of its first 300 rules is about a whole
		// name, and each is counted by why.
		{"easylist.txt", 0, "", map[string]int{skipPath: 46, skipOptions: 235}},
	} {
		res := parseDomainList(sampleLines(t, tc.file))
		first := ""
		if len(res.Blocked) > 0 {
			first = res.Blocked[0]
		}
		if len(res.Blocked) != tc.blocked || first != tc.first || len(res.Allowed) != 0 {
			t.Errorf("%s: %d blocked (first %q), %d allowed; want %d (first %q)", tc.file, len(res.Blocked), first, len(res.Allowed), tc.blocked, tc.first)
		}
		for why, n := range res.Skipped {
			if tc.skipped[why] != n {
				t.Errorf("%s: skipped %d %s, want %d", tc.file, n, why, tc.skipped[why])
			}
		}
		for _, n := range res.Blocked {
			if !pf.IsBlockName(n) {
				t.Errorf("%s: %q isn't a name", tc.file, n)
			}
		}
	}
}

func TestParseDomainListForms(t *testing.T) {
	res := parseDomainList([]string{
		"# comment", "! adblock comment", "[Adblock Plus 2.0]",
		"0.0.0.0 ads.example.com tracker.example.com # two names",
		"127.0.0.1 localhost",
		"plain.example.org",
		"*.wild.example.net",
		"||adserver.example^",
		"||important.example^$important",
		"@@||ok.example^",
		"||ok.example^", // blocked and allowed: allowed
		"||narrow.example^$third-party",
		"example.com##.ad-slot",
		"||example.com/ads/^",
		"rpz.example CNAME .",
		"*.rpz.example CNAME .",
		"pass.example CNAME rpz-passthru.",
		"redirect.example CNAME elsewhere.example.",
		"$TTL 300", "@ SOA localhost. root.localhost. 1 1 1 1 1", "  NS localhost.",
		"192.0.2.1",
		"0.0.0.0 192.0.2.2",
		"not a name",
	})
	want := []string{"*.adserver.example", "*.important.example", "*.rpz.example", "*.wild.example.net", "ads.example.com", "adserver.example", "important.example", "plain.example.org", "rpz.example", "tracker.example.com", "wild.example.net"}
	if strings.Join(res.Blocked, " ") != strings.Join(want, " ") {
		t.Errorf("blocked:\n got %q\nwant %q", res.Blocked, want)
	}
	if got := strings.Join(res.Allowed, " "); got != "*.ok.example ok.example pass.example" {
		t.Errorf("allowed: %q", got)
	}
	wantSkipped := map[string]int{skipOptions: 1, skipCosmetic: 1, skipPath: 1, skipInvalid: 2, skipAddress: 2}
	for why, n := range wantSkipped {
		if res.Skipped[why] != n {
			t.Errorf("skipped %s: %d, want %d (all: %v)", why, res.Skipped[why], n, res.Skipped)
		}
	}
}

func withDNSList(t *testing.T, e *env, answer pf.BlockAnswer) *pf.Model {
	t.Helper()
	m := e.live().Model
	m.DNS.Blocklists = []pf.DNSBlocklist{{ID: "hosts", Name: "Sample hosts", URL: "https://lists.example.org/hosts", Enabled: true}}
	m.DNS.Blocked = []string{"*.bad.example"}
	m.DNS.Allowed = []string{"good.example.com"}
	m.DNS.BlockAnswer = answer
	return m
}

func stageCommit(t *testing.T, e *env, m *pf.Model) error {
	t.Helper()
	st, err := e.m.Stage(StageRequest{Base: e.live().Version, Model: m})
	if err != nil {
		return err
	}
	c, err := e.m.Commit(CommitRequest{Staged: st.Version})
	if err == nil && c.Status == "pending" {
		_, err = e.m.Confirm(c.ID)
	}
	return err
}

func TestCommitDownloadsDNSList(t *testing.T) {
	e := newEnv(t, time.Minute)
	f := &fetch{body: "0.0.0.0 ads.example.com\n0.0.0.0 good.example.com\n"}
	e.m.Fetcher = f
	if err := stageCommit(t, e, withDNSList(t, e, pf.BlockAnswerNull)); err != nil {
		t.Fatal(err)
	}
	zone := e.read(pf.DNSListZonePath("hosts", pf.BlockAnswerNull))
	if !strings.Contains(zone, "ads.example.com A 0.0.0.0\nads.example.com AAAA ::\n") {
		t.Errorf("zone:\n%s", zone)
	}
	conf := e.read("/var/unbound/etc/unbound.conf")
	own := strings.Index(conf, `name: "opf-own."`)
	list := strings.Index(conf, `name: "opf-list-hosts."`)
	if own < 0 || list < own || !strings.Contains(conf, `module-config: "respip validator iterator"`) || !strings.Contains(conf, "control-enable: yes") {
		t.Errorf("unbound.conf:\n%s", conf)
	}
	// *.bad.example is bad.example too.
	if o := e.read(pf.OwnZonePath); !strings.Contains(o, "good.example.com CNAME rpz-passthru.") || !strings.Contains(o, "*.bad.example A 0.0.0.0") || !strings.Contains(o, "\nbad.example A 0.0.0.0") {
		t.Errorf("own zone:\n%s", o)
	}

	// Another answer: its own zone file, from the copy already here; no
	// new download, and the first zone stays for a revert.
	if err := stageCommit(t, e, withDNSList(t, e, pf.BlockAnswerNXDomain)); err != nil {
		t.Fatal(err)
	}
	if len(f.ran) != 1 {
		t.Errorf("downloaded %d times", len(f.ran))
	}
	if z := e.read(pf.DNSListZonePath("hosts", pf.BlockAnswerNXDomain)); !strings.Contains(z, "ads.example.com CNAME .\n") {
		t.Errorf("nxdomain zone:\n%s", z)
	}
	if e.read(pf.DNSListZonePath("hosts", pf.BlockAnswerNull)) == "<missing>" {
		t.Error("the other answer's zone went")
	}
}

func TestDNSListDownloadFailureRefusesCommit(t *testing.T) {
	e := newEnv(t, time.Minute)
	e.m.Fetcher = &fetch{body: "[Adblock Plus 2.0]\nexample.com##.ad\n||x.example^$third-party\n"}
	err := stageCommit(t, e, withDNSList(t, e, pf.BlockAnswerNull))
	if code(err) != CodeCheckFailed || !strings.Contains(err.Error(), "no names to block") {
		t.Errorf("err = %v", err)
	}
	if e.m.store.Pending() != nil || strings.Contains(e.read("/var/unbound/etc/unbound.conf"), "rpz:") {
		t.Error("the system changed")
	}
}

func TestRefreshDNSList(t *testing.T) {
	e := newEnv(t, time.Minute)
	e.m.Fetcher = &fetch{body: "ads.example.com\n"}
	if err := stageCommit(t, e, withDNSList(t, e, pf.BlockAnswerNull)); err != nil {
		t.Fatal(err)
	}
	e.m.Fetcher = &fetch{body: "ads.example.com\nmore.example.com\n"}
	st, err := e.m.RefreshDNSList("hosts")
	if err != nil || st.Blocked != 2 || st.Warning != "" || st.Refresh.LastAttempt == nil || st.Refresh.LastError != "" {
		t.Fatalf("%+v %v", st, err)
	}
	if !strings.Contains(e.read(pf.DNSListZonePath("hosts", pf.BlockAnswerNull)), "more.example.com A 0.0.0.0") {
		t.Error("zone not rewritten")
	}
	cmds := e.run.commands()
	if want := "unbound-control -c /var/unbound/etc/unbound.conf auth_zone_reload opf-list-hosts."; cmds[len(cmds)-1] != want {
		t.Errorf("last command %q", cmds[len(cmds)-1])
	}
	// A failed refresh keeps the list, and says why.
	e.m.Fetcher = &fetch{fail: "ftp: Error retrieving https://lists.example.org/hosts: 503 Service Unavailable"}
	if _, err := e.m.RefreshDNSList("hosts"); code(err) != CodeCheckFailed {
		t.Errorf("failed refresh: %v", err)
	}
	ls, _ := e.m.DNSLists()
	if len(ls) != 1 || ls[0].Blocked != 2 || !strings.Contains(ls[0].Refresh.LastError, "503") {
		t.Errorf("after a failure: %+v", ls)
	}
}

func TestRefreshSchedule(t *testing.T) {
	e := newEnv(t, time.Minute)
	e.m.Fetcher = &fetch{body: "ads.example.com\n"}
	if err := stageCommit(t, e, withDNSList(t, e, pf.BlockAnswerNull)); err != nil {
		t.Fatal(err)
	}
	f := &fetch{body: "ads.example.com\nnew.example.com\n"}
	e.m.Fetcher = f
	// Just downloaded (the DNS list) and just seeded (the pf list, too
	// old? no: its file is new): nothing due.
	e.m.refreshDue(t.Context())
	if len(f.ran) != 0 {
		t.Fatalf("refreshed early: %q", f.ran)
	}
	// A day later, both are due.
	day := time.Now().Add(-25 * time.Hour)
	for _, p := range []string{filepath.Join(e.root, pf.DNSListsDir, "hosts"), filepath.Join(e.root, pf.TablePath("blocklist"))} {
		os.Chtimes(p, day, day)
	}
	f.body = "198.51.100.0/24\nads.example.com\n" // good enough for either list
	e.m.refreshDue(t.Context())
	if len(f.ran) != 2 {
		t.Fatalf("ran %q", f.ran)
	}
	// A failure is retried an hour later, not at every check.
	for _, p := range []string{filepath.Join(e.root, pf.DNSListsDir, "hosts"), filepath.Join(e.root, pf.TablePath("blocklist"))} {
		os.Chtimes(p, day, day)
	}
	failing := &fetch{fail: "ftp: connect: Connection refused"}
	e.m.Fetcher = failing
	e.m.refreshDue(t.Context())
	e.m.refreshDue(t.Context())
	if len(failing.ran) != 2 {
		t.Errorf("retried at once: %q", failing.ran)
	}
	ts, _ := e.m.Tables()
	if ts[0].Refresh.LastError == "" || ts[0].Refresh.Next == nil || time.Until(*ts[0].Refresh.Next) < 55*time.Minute {
		t.Errorf("after a failure: %+v", ts[0].Refresh)
	}
}

// Lists come from anywhere; nothing in one may make the parser panic,
// and everything it keeps must be a name unbound can take.
func FuzzParseDomainList(f *testing.F) {
	ents, _ := os.ReadDir(filepath.Join("testdata", "dnslists"))
	for _, e := range ents {
		b, _ := os.ReadFile(filepath.Join("testdata", "dnslists", e.Name()))
		f.Add(string(b))
	}
	f.Fuzz(func(t *testing.T, s string) {
		res := parseDomainList(strings.Split(s, "\n"))
		for _, n := range append(res.Blocked, res.Allowed...) {
			if !pf.IsBlockName(n) || isAddr(strings.TrimPrefix(n, "*.")) {
				t.Fatalf("kept %q", n)
			}
		}
	})
}

// Changing only your own names reloads just their zone; adding a list
// (a new zone in unbound.conf) reloads unbound once.
func TestOwnNamesReloadOnlyTheirZone(t *testing.T) {
	e := newEnv(t, time.Minute)
	e.m.Fetcher = &fetch{body: "ads.example.com\n"}
	if err := stageCommit(t, e, withDNSList(t, e, pf.BlockAnswerNull)); err != nil {
		t.Fatal(err)
	}
	full := func() int {
		n := 0
		for _, c := range e.run.commands() {
			if c == "rcctl reload unbound" {
				n++
			}
		}
		return n
	}
	if full() != 1 {
		t.Fatalf("adding a list reloaded unbound %d times: %q", full(), e.run.commands())
	}
	m := e.live().Model
	m.DNS.Blocked = append(m.DNS.Blocked, "more.example")
	if err := stageCommit(t, e, m); err != nil {
		t.Fatal(err)
	}
	cmds := e.run.commands()
	if full() != 1 || cmds[len(cmds)-1] != "unbound-control -c /var/unbound/etc/unbound.conf auth_zone_reload opf-own." {
		t.Errorf("own names alone: %q", cmds)
	}
}

// A list's downloads go once it's out of the configuration for good:
// not while it's only turned off, nor while the commit removing it can
// still be reverted.
func TestPruneDownloads(t *testing.T) {
	e := newEnv(t, time.Minute)
	e.m.Fetcher = &fetch{body: "ads.example.com\n"}
	if err := stageCommit(t, e, withDNSList(t, e, pf.BlockAnswerNull)); err != nil {
		t.Fatal(err)
	}
	files := []string{filepath.Join(pf.DNSListsDir, "hosts"), pf.DNSListZonePath("hosts", pf.BlockAnswerNull)}
	there := func(want bool) {
		t.Helper()
		e.m.pruneDownloads()
		for _, f := range files {
			if got := e.read(f) != "<missing>"; got != want {
				t.Errorf("%s there = %v, want %v", f, got, want)
			}
		}
	}
	there(true)

	// Turned off: kept.
	m := e.live().Model
	m.DNS.Blocklists[0].Enabled = false
	if err := stageCommit(t, e, m); err != nil {
		t.Fatal(err)
	}
	there(true)

	// Removed, but the commit can still be reverted: kept.
	m = e.live().Model
	m.DNS.Blocklists = nil
	m.DNS.Blocked, m.DNS.Allowed = nil, nil
	m.Firewall.Rules[0].Description += " (edited)" // pf.conf: confirmed
	st, err := e.m.Stage(StageRequest{Base: e.live().Version, Model: m})
	if err != nil {
		t.Fatal(err)
	}
	c, err := e.m.Commit(CommitRequest{Staged: st.Version})
	if err != nil {
		t.Fatal(err)
	}
	if c.Status != "pending" {
		t.Fatalf("commit %s, not waiting for confirmation", c.Status)
	}
	there(true)
	if _, err := e.m.Confirm(c.ID); err != nil {
		t.Fatal(err)
	}
	there(false)
	// Another alias's table, or a file being written, is left alone.
	if e.read(pf.TablePath(sampleURLAlias(t, e))) == "<missing>" {
		t.Error("removed a URL alias's table that's still in the configuration")
	}
}

func sampleURLAlias(t *testing.T, e *env) string {
	for _, a := range e.live().Model.Firewall.Aliases {
		if a.Type == pf.AliasURL {
			return a.Name
		}
	}
	t.Fatal("the sample has no URL alias")
	return ""
}
