package main

import (
	"fmt"
	"hash/fnv"
	"math"
	"strings"
	"time"

	"github.com/dantecatalfamo/OPF/internal/pf"
)

// unbound for the mock: its counters (unbound-control stats_noreset),
// the lines rpz-log writes to the daemon log, and its size in ps, in
// the formats in internal/sysinfo/testdata. Queries arrive at a
// wandering rate; with blocklists or your own blocked names on, some
// are blocked, by names ad and tracking networks use.

// mockBlockedNames are what the mock's devices look up and get blocked,
// the first ones most.
var mockBlockedNames = []string{
	"securepubads.g.doubleclick.net", "app-measurement.com", "graph.facebook.com",
	"ads.samsungads.com", "telemetry.microsoft.com", "pagead2.googlesyndication.com",
	"stats.g.doubleclick.net", "api.segment.io", "browser.sentry-cdn.com",
	"device-metrics-us.amazon.com", "log.tiktokv.com", "ssl.google-analytics.com",
}

// mockBlockShare is the share of queries blocked when something blocks.
const mockBlockShare = 0.12

func mockBlocking(m *pf.Model) (zones []string, blocking bool) {
	if !m.DNS.Enabled {
		return nil, false
	}
	if len(m.DNS.Blocked) > 0 {
		zones = append(zones, pf.OwnLogName)
	}
	for _, l := range m.DNS.Blocklists {
		if l.Enabled {
			zones = append(zones, pf.DNSListLogName(l.ID))
		}
	}
	return zones, len(zones) > 0
}

func mockUnboundStats(m *pf.Model, t float64) string {
	up := t + 3*86400 + 4000 // since unbound last started
	queries := wander("dns queries", 24, t) + 24*(up-t)
	hits := queries * 0.78
	var b strings.Builder
	w := func(k string, v float64) { fmt.Fprintf(&b, "%s=%d\n", k, int64(v)) }
	w("total.num.queries", queries)
	w("total.num.cachehits", hits)
	w("total.num.cachemiss", queries-hits)
	w("total.num.prefetch", queries*0.02)
	fmt.Fprintf(&b, "total.recursion.time.avg=%.6f\n", 0.058+0.01*math.Sin(t/50))
	fmt.Fprintf(&b, "total.recursion.time.median=%.6f\n", 0.031+0.004*math.Sin(t/70))
	fmt.Fprintf(&b, "time.up=%.6f\n", up)
	w("mem.cache.rrset", 4.1e6)
	w("mem.cache.message", 2.2e6)
	w("mem.mod.iterator", 16748)
	w("mem.mod.validator", 287430)
	w("num.query.type.A", queries*0.62)
	w("num.query.type.AAAA", queries*0.29)
	w("num.query.type.HTTPS", queries*0.07)
	w("num.query.type.PTR", queries*0.02)
	_, blocking := mockBlocking(m)
	blocked := 0.0
	if blocking {
		blocked = wander("dns blocked", 24*mockBlockShare, t) + 24*mockBlockShare*(up-t)
		action := "local_data"
		if m.DNS.BlockAnswer == pf.BlockAnswerNXDomain {
			action = "nxdomain"
		}
		w("num.rpz.action."+action, blocked)
		if len(m.DNS.Allowed) > 0 {
			w("num.rpz.action.passthru", queries*0.004)
		}
	}
	nx := queries * 0.06
	w("num.answer.rcode.NOERROR", queries-nx-queries*0.001)
	w("num.answer.rcode.NXDOMAIN", nx)
	w("num.answer.rcode.SERVFAIL", queries*0.001)
	w("num.answer.rcode.nodata", queries*0.09)
	if m.DNS.DNSSEC {
		w("num.answer.secure", queries*0.17)
		w("num.answer.bogus", queries*0.00005)
	}
	return b.String()
}

// mockDaemonLog is the daemon log's last lines: a blocked query every
// few seconds over the last hour, and the odd other daemon's line.
func mockDaemonLog(m *pf.Model, now time.Time) string {
	zones, blocking := mockBlocking(m)
	var b strings.Builder
	start := now.Add(-time.Hour).Truncate(time.Second)
	fmt.Fprintf(&b, "%s gw unbound: [29114:0] info: start of service (unbound 1.26.1).\n", start.Format(time.Stamp))
	if !blocking {
		return b.String()
	}
	const every = 4 * time.Second
	clients := []string{"192.168.1.23", "192.168.1.40", "192.168.1.51", "fd00::23"}
	for at := start.Truncate(every).Add(every); !at.After(now); at = at.Add(every) {
		h := fnv.New32a()
		fmt.Fprint(h, at.Unix())
		r := h.Sum32()
		// Squaring skews it: the first names come up most.
		f := float64(r%1000) / 1000
		name := mockBlockedNames[int(f*f*float64(len(mockBlockedNames)))]
		// Your own names block a few; the lists the rest.
		zone := zones[int(r/1000)%len(zones)]
		if zone == pf.OwnLogName && len(zones) > 1 && r%10 != 0 {
			zone = zones[1+int(r/7)%(len(zones)-1)]
		}
		action := "local_data"
		if m.DNS.BlockAnswer == pf.BlockAnswerNXDomain || zone == pf.OwnLogName {
			action = "nxdomain"
		}
		// Lists block a name and everything under it: the name's
		// registered domain, roughly.
		labels := strings.Split(name, ".")
		entry := "*." + strings.Join(labels[max(0, len(labels)-2):], ".")
		if zone == pf.OwnLogName {
			entry = m.DNS.Blocked[int(r)%len(m.DNS.Blocked)]
			name = entry
			if under, ok := strings.CutPrefix(entry, "*."); ok {
				name = "cdn." + under
			}
		}
		typ := []string{"A", "AAAA", "HTTPS"}[r%3]
		fmt.Fprintf(&b, "%s gw unbound: [29114:0] info: rpz: applied [%s] %s. %s %s@%d %s. %s IN\n",
			at.Format(time.Stamp), zone, entry, action, clients[r%uint32(len(clients))], 1024+r%60000, name, typ)
		if r%13 == 0 && len(m.DNS.Allowed) > 0 {
			ok := strings.TrimPrefix(m.DNS.Allowed[int(r)%len(m.DNS.Allowed)], "*.")
			fmt.Fprintf(&b, "%s gw unbound: [29114:0] info: rpz: applied [%s] %s. passthru %s@%d %s. A IN\n",
				at.Format(time.Stamp), pf.OwnLogName, ok, clients[r%uint32(len(clients))], 1024+r%60000, ok)
		}
		if r%17 == 0 {
			fmt.Fprintf(&b, "%s gw dhcpd[5512]: DHCPACK on 192.168.1.40 to 3c:22:fb:10:aa:01 via em1\n", at.Format(time.Stamp))
		}
	}
	return b.String()
}

// mockUnboundRSS is unbound's resident size: a base and, for each name
// in a loaded list, about what the host test measured (TODO.md).
func mockUnboundRSS(names int) string {
	kb := 38*1024 + names*1400/1024
	return fmt.Sprintf(" 1204 init\n%5d unbound\n18220 opf\n", kb)
}
