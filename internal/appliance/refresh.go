package appliance

import (
	"context"
	"log"
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
