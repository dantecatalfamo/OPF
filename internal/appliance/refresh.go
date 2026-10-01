package appliance

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dantecatalfamo/OPF/internal/pf"
)

// Downloaded lists (pf URL aliases, DNS blocklists) are downloaded again
// when they're due: every RefreshHours (24 by default) since the last
// download. A failed attempt keeps the list already there and is tried
// again an hour later (or sooner, for a list refreshed more often), and
// the page says what went wrong.

const refreshRetry = time.Hour

// RefreshState is when a list is downloaded next, and how the last
// attempt went.
type RefreshState struct {
	EveryHours  int        `json:"everyHours"`
	Next        *time.Time `json:"next,omitempty"`
	LastAttempt *time.Time `json:"lastAttempt,omitempty"`
	LastError   string     `json:"lastError,omitempty"`
}

type refreshRecord struct {
	at  time.Time
	err string
}

func aliasKey(name string) string { return "alias:" + name }
func dnsKey(id string) string     { return "dns:" + id }

// noteRefresh records an attempt to download a list.
func (m *Manager) noteRefresh(key string, err error) {
	m.refMu.Lock()
	defer m.refMu.Unlock()
	if m.refs == nil {
		m.refs = map[string]refreshRecord{}
	}
	r := refreshRecord{at: time.Now()}
	if err != nil {
		r.err = err.Error()
	}
	before, seen := m.refs[key]
	m.refs[key] = r
	m.noteListEvent(key, before, r, seen)
}

func (m *Manager) refreshState(key string, fetched *time.Time, hours *int) RefreshState {
	every := 24
	if hours != nil {
		every = *hours
	}
	st := RefreshState{EveryHours: every}
	next := time.Now()
	if fetched != nil {
		next = fetched.Add(time.Duration(every) * time.Hour)
	}
	m.refMu.Lock()
	r, ok := m.refs[key]
	m.refMu.Unlock()
	if ok {
		at := r.at
		st.LastAttempt = &at
		if r.err != "" {
			st.LastError = r.err
			if retry := r.at.Add(min(refreshRetry, time.Duration(every)*time.Hour)); retry.After(next) {
				next = retry
			}
		}
	}
	st.Next = &next
	return st
}

// RunRefresher downloads the applied configuration's lists again as
// they fall due, checking every interval, until ctx is done.
func (m *Manager) RunRefresher(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		m.refreshDue(ctx)
		m.pruneDownloads()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (m *Manager) refreshDue(ctx context.Context) {
	model, _, err := m.live()
	if err != nil || model == nil {
		return
	}
	now := time.Now()
	due := func(st RefreshState) bool { return st.Next != nil && !st.Next.After(now) }
	for _, a := range model.Firewall.Aliases {
		if a.Type == pf.AliasURL && due(m.tableStatus(a).Refresh) {
			if _, err := m.refreshAlias(ctx, a); err != nil {
				log.Printf("refreshing %s: %v", a.Name, err)
			}
		}
	}
	for _, l := range model.DNS.Blocklists {
		if l.Enabled && due(m.dnsListStatus(l).Refresh) {
			if _, err := m.refreshDNSList(ctx, l); err != nil {
				log.Printf("refreshing DNS blocklist %s: %v", l.Name, err)
			}
		}
	}
}

// pruneDownloads removes what was downloaded for lists the
// configuration no longer has: a URL alias's table, a blocklist's names
// and zones. A list that's only turned off keeps them, and so does one
// in the staged configuration. Nothing is removed while a commit waits
// for confirmation, since reverting it needs its lists, and the lock
// keeps a commit from downloading lists for its model, not yet live,
// meanwhile.
func (m *Manager) pruneDownloads() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.store.Pending() != nil {
		return
	}
	live, _, err := m.live()
	if err != nil || live == nil {
		return
	}
	models := []*pf.Model{live}
	if data, staged, err := m.stagedModel(); err == nil && staged {
		if sm, err := decodeModel(data); err == nil {
			models = append(models, sm)
		} else {
			return // unsure what's wanted: keep everything
		}
	} else if err != nil {
		return
	}
	tables, lists := map[string]bool{}, map[string]bool{}
	for _, md := range models {
		for _, a := range md.Firewall.Aliases {
			if a.Type == pf.AliasURL {
				tables[filepath.Base(pf.TablePath(a.Name))] = true
			}
		}
		for _, l := range md.DNS.Blocklists {
			lists[l.ID] = true
			for _, a := range []pf.BlockAnswer{pf.BlockAnswerNull, pf.BlockAnswerNXDomain} {
				lists[filepath.Base(pf.DNSListZonePath(l.ID, a))] = true
			}
		}
	}
	m.prune(filepath.Dir(pf.TablePath("x")), tables)
	m.prune(pf.WGKeyDir, wgKeyFiles(models...))
	m.prune(pf.DNSListsDir, lists)
	m.prune(filepath.Dir(pf.DNSListZonePath("x", pf.BlockAnswerNull)), lists)
}

// prune removes the files in dir (a system path) not in keep. Files
// being written (writeAtomic's dot files) and directories are left.
func (m *Manager) prune(dir string, keep map[string]bool) {
	entries, err := os.ReadDir(m.store.SystemPath(dir))
	if err != nil {
		return
	}
	for _, e := range entries {
		if keep[e.Name()] || strings.HasPrefix(e.Name(), ".") || !e.Type().IsRegular() {
			continue
		}
		path := filepath.Join(dir, e.Name())
		if err := os.Remove(m.store.SystemPath(path)); err != nil {
			log.Printf("removing %s: %v", path, err)
			continue
		}
		log.Printf("removed %s: its list isn't in the configuration any more", path)
	}
}
