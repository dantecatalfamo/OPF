package appliance

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dantecatalfamo/OPF/internal/pf"
	"github.com/dantecatalfamo/OPF/internal/run"
)

// URL aliases are tables pf loads from a file OPF downloads: the first
// time a commit needs one, and again when asked. The download is the
// one time OPF talks to the internet on its own, so it runs ftp(1) as an
// unprivileged user (Fetcher), and this process only reads the lines it
// prints: each must be an address or network, anything else is
// skipped, and the whole is capped.

// Limits on a downloaded list.
const (
	maxListBytes = 32 << 20
	fetchTimeout = 2 * time.Minute
)

// fetcher runs downloads: Fetcher, or else the Manager's runner.
func (m *Manager) fetcher() run.Runner {
	if m.Fetcher != nil {
		return m.Fetcher
	}
	return m.runner()
}

// ListResult is a downloaded list: its addresses, and how many lines
// weren't addresses and were left out.
type ListResult struct {
	Entries []string
	Skipped int
}

// fetchList downloads a list and reads the addresses in it.
func (m *Manager) fetchList(ctx context.Context, url string) (ListResult, error) {
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	var res ListResult
	var lines []string
	size := 0
	tooBig := false
	line := func(l string) {
		if tooBig {
			return
		}
		if size += len(l) + 1; size > maxListBytes {
			tooBig = true
			cancel()
			return
		}
		lines = append(lines, l)
	}
	// -V: no progress meter. The URL comes from a validated model
	// (https:// only), and "--" ends the options before it.
	argv := []string{"ftp", "-V", "-o", "-", "--", url}
	var err error
	if s, ok := m.fetcher().(run.Streamer); ok {
		err = s.Stream(ctx, line, argv...)
	} else {
		var out []byte
		out, err = m.fetcher().Run(ctx, argv...)
		for _, l := range strings.Split(string(out), "\n") {
			line(l)
		}
	}
	if tooBig {
		return res, fmt.Errorf("the list is bigger than %d MB", maxListBytes>>20)
	}
	if err != nil {
		// ftp's error is its last line of output ("ftp: Error retrieving
		// ...: 404 Not Found").
		msg := ""
		for i := len(lines) - 1; i >= 0 && msg == ""; i-- {
			msg = strings.TrimSpace(lines[i])
		}
		if msg == "" {
			msg = err.Error()
		}
		return res, errors.New(printable(msg, maxMessageRunes))
	}
	res.Entries, res.Skipped = parseList(lines)
	if len(res.Entries) == 0 {
		if res.Skipped > 0 {
			lines := "lines that aren't addresses"
			if res.Skipped == 1 {
				lines = "line that isn't an address"
			}
			return res, fmt.Errorf("it has no addresses in it, just %d %s; is it the right URL?", res.Skipped, lines)
		}
		return res, errors.New("it's empty")
	}
	return res, nil
}

// parseList reads the addresses and networks in a list, one a line,
// in the forms blocklists use: "192.0.2.1", "198.51.100.0/24 ; SBL123",
// "# comment". Duplicates are dropped; lines that aren't an address
// are counted.
func parseList(lines []string) (entries []string, skipped int) {
	seen := map[string]bool{}
	for _, l := range lines {
		if i := strings.IndexAny(l, "#;"); i >= 0 {
			l = l[:i]
		}
		f := strings.Fields(l)
		if len(f) == 0 {
			continue
		}
		e := ""
		if p, err := netip.ParsePrefix(f[0]); err == nil && p.Addr().Zone() == "" {
			e = p.Masked().String()
		} else if a, err := netip.ParseAddr(f[0]); err == nil && a.Zone() == "" {
			e = a.String()
		}
		if e == "" {
			skipped++
			continue
		}
		if !seen[e] {
			seen[e] = true
			entries = append(entries, e)
		}
	}
	return entries, skipped
}

// writeList saves a list where pf.conf loads it from, replacing any
// older copy only once the new one is complete.
func (m *Manager) writeList(a pf.Alias, res ListResult) error {
	path := m.store.SystemPath(pf.TablePath(a.Name))
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+a.Name+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	var b strings.Builder
	fmt.Fprintf(&b, "# Downloaded by OPF from %s at %s\n", a.URL, time.Now().UTC().Format(time.RFC3339))
	for _, e := range res.Entries {
		b.WriteString(e + "\n")
	}
	if _, err := tmp.WriteString(b.String()); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return !errors.Is(err, fs.ErrNotExist)
}

// prepareCommit gets the system ready for a model's files to pass their
// checks: it downloads the lists of URL aliases that haven't been yet
// (a list already there is used as it is), and creates unbound's
// trust anchor if DNSSEC needs one and there isn't one, as
// rc.d/unbound does before unbound first starts.
func (m *Manager) prepareCommit(ctx context.Context, model *pf.Model) error {
	for _, a := range model.Firewall.Aliases {
		if a.Type != pf.AliasURL || exists(m.store.SystemPath(pf.TablePath(a.Name))) {
			continue
		}
		res, err := m.fetchList(ctx, a.URL)
		if err != nil {
			return &Error{Code: CodeCheckFailed, Message: fmt.Sprintf("couldn't download the list for %s from %s: %s; nothing was changed", a.Name, a.URL, err),
				Details: []Detail{{Path: pf.TablePath(a.Name), Message: err.Error()}}}
		}
		if err := m.writeList(a, res); err != nil {
			return err
		}
	}
	if model.DNS.Enabled && model.DNS.DNSSEC {
		key := m.store.SystemPath(pf.RootKeyPath)
		if !exists(key) {
			// Its exit status isn't meaningful (1 when it wrote the
			// built-in anchor, 0 on errors too): unbound-checkconf finds
			// out whether the file is there.
			ctx, cancel := context.WithTimeout(ctx, time.Minute)
			defer cancel()
			out, _ := m.actions().Run(ctx, "unbound-anchor", "-v", "-a", key)
			if !exists(key) {
				log.Printf("unbound-anchor didn't create %s: %s", key, firstLine(string(out)))
			}
		}
	}
	return nil
}

// TableStatus is a URL alias's list: when it was downloaded and how
// many entries it has.
type TableStatus struct {
	Name    string     `json:"name"`
	URL     string     `json:"url"`
	Fetched *time.Time `json:"fetched,omitempty"` // nil: not downloaded yet
	Entries int        `json:"entries"`
	// Warning says what went wrong after a refresh downloaded the list,
	// such as pf not taking it.
	Warning string `json:"warning,omitempty"`
}

// Tables returns the lists of the live model's URL aliases.
func (m *Manager) Tables() ([]TableStatus, error) {
	model, _, err := m.live()
	if err != nil {
		return nil, err
	}
	out := []TableStatus{}
	for _, a := range model.Firewall.Aliases {
		if a.Type == pf.AliasURL {
			out = append(out, m.tableStatus(a))
		}
	}
	return out, nil
}

func (m *Manager) tableStatus(a pf.Alias) TableStatus {
	st := TableStatus{Name: a.Name, URL: a.URL}
	path := m.store.SystemPath(pf.TablePath(a.Name))
	fi, err := os.Stat(path)
	if err != nil {
		return st
	}
	t := fi.ModTime()
	st.Fetched = &t
	if data, err := os.ReadFile(path); err == nil {
		for _, l := range strings.Split(string(data), "\n") {
			if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
				st.Entries++
			}
		}
	}
	return st
}

// RefreshAlias downloads a URL alias's list again and loads it into pf.
// If the download fails the list already there stays, as does pf's
// table.
func (m *Manager) RefreshAlias(name string) (*TableStatus, error) {
	model, _, err := m.live()
	if err != nil {
		return nil, err
	}
	var alias *pf.Alias
	for i := range model.Firewall.Aliases {
		if a := &model.Firewall.Aliases[i]; a.Name == name && a.Type == pf.AliasURL {
			alias = a
		}
	}
	if alias == nil {
		return nil, errorf(CodeNotFound, "no downloaded list called %q in the applied configuration", name)
	}
	ctx := context.Background()
	res, err := m.fetchList(ctx, alias.URL)
	if err != nil {
		return nil, errorf(CodeCheckFailed, "couldn't download %s: %s; the list already there is still in use", alias.URL, err)
	}
	if err := m.writeList(*alias, res); err != nil {
		return nil, err
	}
	st := m.tableStatus(*alias)
	// pf only reads the file when the ruleset loads; replace the table's
	// contents now.
	ctx, cancel := context.WithTimeout(ctx, readTimeout)
	defer cancel()
	if out, err := m.actions().Run(ctx, "pfctl", "-t", alias.Name, "-T", "replace", "-f", m.store.SystemPath(pf.TablePath(alias.Name))); err != nil {
		st.Warning = "downloaded, but pf didn't take it: " + firstLine(string(out))
	}
	return &st, nil
}
