package appliance

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dantecatalfamo/OPF/internal/config"
	"github.com/dantecatalfamo/OPF/internal/pf"
	"github.com/dantecatalfamo/OPF/internal/run"
	"github.com/dantecatalfamo/OPF/internal/sysinfo"
)

// The resolver's own numbers: unbound's counters over its control
// socket, what its response policy zones blocked from the lines it logs
// (rpz-log), and how long it took to come back the last time a commit
// reloaded it whole.

// unboundConf is the configuration unbound-control reads to find the
// control socket.
const unboundConf = "/var/unbound/etc/unbound.conf"

// daemonLog is where syslogd writes unbound's lines, and daemonLogLines
// how many of its last lines are read for the blocked names. newsyslog
// rotates it at 300 KB by default, so that's usually all of it.
const (
	daemonLog      = "/var/log/daemon"
	daemonLogLines = 20000
)

// MaxBlockedNames is how many names DNSBlocked returns.
const MaxBlockedNames = 50

// DNSStats is the resolver's counters and rates.
type DNSStats struct {
	// Enabled is whether the applied configuration runs the resolver;
	// when it doesn't, nothing else is read.
	Enabled bool                  `json:"enabled"`
	Stats   *sysinfo.UnboundStats `json:"stats,omitempty"`
	// Per second over the last few seconds, when the counters didn't
	// start again in between (unbound reloaded).
	QueriesPerSec *float64 `json:"queriesPerSec,omitempty"`
	BlockedPerSec *float64 `json:"blockedPerSec,omitempty"`
	// MemoryBytes is unbound's resident memory, zones included.
	MemoryBytes uint64          `json:"memoryBytes,omitempty"`
	LastReload  *ResolverReload `json:"lastReload,omitempty"`
	Errors      []string        `json:"errors"`
}

// ResolverReload is how long unbound took to answer again after a
// commit reloaded it whole: it loads every zone before it answers.
type ResolverReload struct {
	At      time.Time `json:"at"`
	Seconds float64   `json:"seconds"`
	// Names is how many blocklist and own names it loaded.
	Names int `json:"names"`
	// TimedOut: it hadn't answered after reloadWait.
	TimedOut bool `json:"timedOut,omitempty"`
}

// DNSStats reads unbound's counters.
func (m *Manager) DNSStats() (*DNSStats, error) {
	res := &DNSStats{Errors: []string{}}
	model, _, err := m.live()
	if err != nil {
		return nil, err
	}
	if model == nil || !model.DNS.Enabled {
		return res, nil
	}
	res.Enabled = true
	res.LastReload = m.lastReload()
	then, now, dt, err := m.dnsCounters.sample(func() (sysinfo.UnboundStats, error) {
		out, err := m.read("unbound-control", "-c", unboundConf, "stats_noreset")
		s, ok := sysinfo.ParseUnboundStats(out)
		if !ok {
			if err == nil {
				err = fmt.Errorf("unexpected output")
			}
			return s, err
		}
		return s, nil
	})
	if err != nil {
		res.Errors = append(res.Errors, "couldn't read the resolver's counters (unbound-control stats_noreset); is unbound running?")
	} else {
		res.Stats = &now
		// Counters start again when unbound reloads.
		if dt > 0 && now.Queries >= then.Queries && now.Uptime >= then.Uptime {
			q := float64(now.Queries-then.Queries) / dt.Seconds()
			res.QueriesPerSec = &q
			if b, a := then.Blocked(), now.Blocked(); a >= b {
				r := float64(a-b) / dt.Seconds()
				res.BlockedPerSec = &r
			}
		}
	}
	if out, err := m.read("ps", "-A", "-o", "rss=,comm="); err == nil {
		res.MemoryBytes, _ = sysinfo.ParseProcessRSS(out, "unbound")
	}
	return res, nil
}

// DNSBlocked is what the response policy zones did, from the lines
// unbound logged since Since: in all, by list, and the names blocked
// most. Which device asked isn't kept.
type DNSBlocked struct {
	Since *time.Time `json:"since,omitempty"` // the first line read; nil: none
	// Blocked queries, in all, by your own entries, and by list id.
	Blocked int            `json:"blocked"`
	Own     int            `json:"own"`
	ByList  map[string]int `json:"byList"`
	// Allowed is queries your never-block names let through.
	Allowed int           `json:"allowed"`
	Names   []BlockedName `json:"names"`
	Error   string        `json:"error,omitempty"`
}

// BlockedName is a name blocked, how often, and what blocked it last.
type BlockedName struct {
	Name  string    `json:"name"`
	Count int       `json:"count"`
	Last  time.Time `json:"last"`
	// List is the id of the list that blocked it last; empty when it
	// was your own entry.
	List string `json:"list,omitempty"`
	// Entry is the list's entry that matched: the name, or *. and a
	// name it's under.
	Entry string `json:"entry"`
}

// DNSBlocked reads unbound's rpz-log lines from the daemon log.
func (m *Manager) DNSBlocked() (*DNSBlocked, error) {
	res := &DNSBlocked{ByList: map[string]int{}, Names: []BlockedName{}}
	out, err := m.read("tail", "-n", strconv.Itoa(daemonLogLines), daemonLog)
	if err != nil {
		res.Error = "couldn't read " + daemonLog
		return res, nil
	}
	res.tally(sysinfo.ParseRPZLog(out, time.Now()), MaxBlockedNames)
	return res, nil
}

func (res *DNSBlocked) tally(hits []sysinfo.RPZHit, max int) {
	names := map[string]*BlockedName{}
	for _, h := range hits {
		list, own := "", h.Zone == pf.OwnLogName
		if !own {
			id, ok := strings.CutPrefix(h.Zone, pf.DNSListLogName(""))
			if !ok {
				continue // not one of OPF's zones
			}
			list = id
		}
		if res.Since == nil {
			t := h.Time
			res.Since = &t
		}
		if sysinfo.RPZPass[h.Action] {
			if own {
				res.Allowed++
			}
			continue
		}
		res.Blocked++
		if own {
			res.Own++
		} else {
			res.ByList[list]++
		}
		// Names come from whoever asked: keep only ones that are names,
		// so "never block" can take them as they are.
		name := strings.ToLower(h.Name)
		if !pf.IsBlockName(name) || strings.HasPrefix(name, "*.") {
			continue
		}
		n := names[name]
		if n == nil {
			n = &BlockedName{Name: name}
			names[name] = n
		}
		n.Count++
		if !h.Time.Before(n.Last) {
			n.Last, n.List, n.Entry = h.Time, list, displayable(h.Trigger)
		}
	}
	for _, n := range names {
		res.Names = append(res.Names, *n)
	}
	sort.Slice(res.Names, func(i, j int) bool {
		a, b := res.Names[i], res.Names[j]
		if a.Count != b.Count {
			return a.Count > b.Count
		}
		return a.Name < b.Name
	})
	if len(res.Names) > max {
		res.Names = res.Names[:max]
	}
}

// reloadWait is how long timeReload waits for unbound to answer.
const reloadWait = 3 * time.Minute

type reloadRecord struct {
	mu   sync.Mutex
	last *ResolverReload
}

func (m *Manager) lastReload() *ResolverReload {
	m.reload.mu.Lock()
	defer m.reload.mu.Unlock()
	if m.reload.last == nil {
		return nil
	}
	r := *m.reload.last
	return &r
}

// reloadsResolver says whether a commit changed unbound.conf, which
// reloads unbound whole; a zone changing alone reloads only that zone.
func reloadsResolver(e *config.Entry) bool {
	for _, f := range e.Files {
		if f.Path == unboundConf {
			return true
		}
	}
	return false
}

// timeReload measures, in the background, how long unbound takes to
// answer again after a commit reloaded it: it asks over the control
// socket until it's answered. It's from when the commit finished, a
// moment after unbound was told, so it's slightly short. Under -dry
// nothing reloaded, so there's nothing to time.
func (m *Manager) timeReload() {
	if _, dry := m.actions().(run.Dry); dry {
		return
	}
	start := time.Now()
	go func() {
		rec := &ResolverReload{At: start, Names: m.resolverNames()}
		for {
			// Let the reload begin before the first question.
			time.Sleep(250 * time.Millisecond)
			ctx, cancel := context.WithTimeout(context.Background(), reloadWait-time.Since(start))
			_, err := m.runner().Run(ctx, "unbound-control", "-c", unboundConf, "status")
			cancel()
			if err == nil {
				break
			}
			if time.Since(start) >= reloadWait {
				rec.TimedOut = true
				log.Printf("unbound wasn't answering %s after a commit reloaded it", reloadWait)
				break
			}
		}
		rec.Seconds = time.Since(start).Seconds()
		m.reload.mu.Lock()
		m.reload.last = rec
		m.reload.mu.Unlock()
	}()
}

// resolverNames is how many names the live configuration's enabled
// lists and own entries have.
func (m *Manager) resolverNames() int {
	model, _, err := m.live()
	if err != nil || model == nil {
		return 0
	}
	n := len(model.DNS.Blocked) + len(model.DNS.Allowed)
	for _, l := range model.DNS.Blocklists {
		if l.Enabled {
			if res, _, err := m.readDNSList(l.ID); err == nil {
				n += len(res.Blocked) + len(res.Allowed)
			}
		}
	}
	return n
}
