package appliance

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dantecatalfamo/OPF/internal/pf"
)

// fetch answers ftp with a list, or fails like ftp does.
type fetch struct {
	body string
	fail string
	ran  []string
}

func (f *fetch) Run(_ context.Context, argv ...string) ([]byte, error) {
	f.ran = append(f.ran, strings.Join(argv, " "))
	if f.fail != "" {
		return []byte(f.fail + "\n"), errors.New("exit status 1")
	}
	return []byte(f.body), nil
}

func TestParseList(t *testing.T) {
	entries, skipped := parseList([]string{
		"; Spamhaus DROP List",
		"1.10.16.0/20 ; SBL256894",
		"1.10.16.5/20", // the same network, not masked
		"192.0.2.7",    // an address
		"2001:db8::/32 # v6",
		"<html>",      // not an address
		"fe80::1%em0", // a zone: no
		"",
		"   ",
	})
	want := []string{"1.10.16.0/20", "192.0.2.7", "2001:db8::/32"}
	if strings.Join(entries, " ") != strings.Join(want, " ") || skipped != 2 {
		t.Errorf("got %q, %d skipped", entries, skipped)
	}
}

func listPath(e *env) string { return filepath.Join(e.root, pf.TablePath("blocklist")) }

func stageDisable(t *testing.T, e *env) *Staged {
	m := sample(t)
	disableLANRule(m)
	st, err := e.m.Stage(StageRequest{Base: e.live().Version, Model: m})
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func TestCommitDownloadsMissingList(t *testing.T) {
	e := newEnv(t, time.Minute)
	os.Remove(listPath(e))
	f := &fetch{body: "# a list\n198.51.100.0/24 ; x\n203.0.113.9\n"}
	e.m.Fetcher = f
	st := stageDisable(t, e)
	if _, err := e.m.Commit(CommitRequest{Staged: st.Version}); err != nil {
		t.Fatal(err)
	}
	if len(f.ran) != 1 || f.ran[0] != "ftp -V -o - -- https://lists.example.org/drop.txt" {
		t.Errorf("ran %q", f.ran)
	}
	data, _ := os.ReadFile(listPath(e))
	if !strings.HasSuffix(string(data), "198.51.100.0/24\n203.0.113.9\n") || !strings.HasPrefix(string(data), "# Downloaded by OPF from https://lists.example.org/drop.txt") {
		t.Errorf("list file:\n%s", data)
	}
}

func TestCommitKeepsDownloadedList(t *testing.T) {
	e := newEnv(t, time.Minute)
	f := &fetch{body: "198.51.100.0/24\n"}
	e.m.Fetcher = f
	st := stageDisable(t, e)
	if _, err := e.m.Commit(CommitRequest{Staged: st.Version}); err != nil {
		t.Fatal(err)
	}
	if len(f.ran) != 0 {
		t.Errorf("downloaded again: %q", f.ran)
	}
	if data, _ := os.ReadFile(listPath(e)); string(data) != "192.0.2.0/24\n" {
		t.Errorf("list replaced: %q", data)
	}
}

func TestCommitRefusedWhenDownloadFails(t *testing.T) {
	for _, f := range []*fetch{
		{fail: "ftp: Error retrieving https://lists.example.org/drop.txt: 404 Not Found"},
		{body: "<html><body>Sorry</body></html>\n"}, // not a list
		{body: ""},
	} {
		e := newEnv(t, time.Minute)
		os.Remove(listPath(e))
		e.m.Fetcher = f
		before := e.read("/etc/pf.conf")
		st := stageDisable(t, e)
		_, err := e.m.Commit(CommitRequest{Staged: st.Version})
		if code(err) != CodeCheckFailed || !strings.Contains(err.Error(), "blocklist") {
			t.Errorf("%+v: %v", f, err)
		}
		if e.read("/etc/pf.conf") != before || e.m.store.Pending() != nil {
			t.Error("the system changed")
		}
		if _, err := os.Stat(listPath(e)); err == nil {
			t.Error("a failed download left a list")
		}
	}
	e := newEnv(t, time.Minute)
	os.Remove(listPath(e))
	e.m.Fetcher = &fetch{fail: "ftp: Error retrieving https://lists.example.org/drop.txt: 404 Not Found"}
	st := stageDisable(t, e)
	if _, err := e.m.Commit(CommitRequest{Staged: st.Version}); err == nil || !strings.Contains(err.Error(), "404 Not Found") {
		t.Errorf("ftp's reason should reach the page: %v", err)
	}
}

func TestTrustAnchorOnlyWhenMissing(t *testing.T) {
	e := newEnv(t, time.Minute)
	st := stageDisable(t, e)
	if _, err := e.m.Commit(CommitRequest{Staged: st.Version}); err != nil {
		t.Fatal(err)
	}
	for _, c := range e.run.commands() {
		if strings.HasPrefix(c, "unbound-anchor") {
			t.Errorf("ran %q with root.key there", c)
		}
	}
	e = newEnv(t, time.Minute)
	os.Remove(filepath.Join(e.root, pf.RootKeyPath))
	st = stageDisable(t, e)
	e.m.Commit(CommitRequest{Staged: st.Version})
	want := "unbound-anchor -v -a " + filepath.Join(e.root, pf.RootKeyPath)
	found := false
	for _, c := range e.run.commands() {
		found = found || c == want
	}
	if !found {
		t.Errorf("want %q in %q", want, e.run.commands())
	}
}

func TestRefreshAlias(t *testing.T) {
	e := newEnv(t, time.Minute)
	f := &fetch{body: "198.51.100.0/24\n198.51.100.7\n"}
	e.m.Fetcher = f
	st, err := e.m.RefreshAlias("blocklist")
	if err != nil {
		t.Fatal(err)
	}
	if st.Entries != 2 || st.Fetched == nil || st.Warning != "" {
		t.Errorf("status %+v", st)
	}
	want := "pfctl -t blocklist -T replace -f " + listPath(e)
	if cmds := e.run.commands(); len(cmds) == 0 || cmds[len(cmds)-1] != want {
		t.Errorf("want %q, ran %q", want, cmds)
	}
	// A failed refresh keeps the list there.
	e.m.Fetcher = &fetch{fail: "ftp: connect: Connection refused"}
	if _, err := e.m.RefreshAlias("blocklist"); code(err) != CodeCheckFailed {
		t.Errorf("failed refresh: %v", err)
	}
	if data, _ := os.ReadFile(listPath(e)); !strings.Contains(string(data), "198.51.100.7") {
		t.Errorf("list lost: %q", data)
	}
	if _, err := e.m.RefreshAlias("bruteforce"); code(err) != CodeNotFound {
		t.Errorf("not a URL alias: %v", err)
	}
	if ts, err := e.m.Tables(); err != nil || len(ts) != 1 || ts[0].Name != "blocklist" || ts[0].Entries != 2 {
		t.Errorf("tables %+v %v", ts, err)
	}
}
