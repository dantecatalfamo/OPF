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
		action := "rpz-local-data"
		if m.DNS.BlockAnswer == pf.BlockAnswerNXDomain {
			action = "rpz-nxdomain"
		}
		w("num.rpz.action."+action, blocked)
		if len(m.DNS.Allowed) > 0 {
			w("num.rpz.action.rpz-passthru", queries*0.004)
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
		action := "rpz-local-data"
		if m.DNS.BlockAnswer == pf.BlockAnswerNXDomain || zone == pf.OwnLogName {
			action = "rpz-nxdomain"
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
			fmt.Fprintf(&b, "%s gw unbound: [29114:0] info: rpz: applied [%s] %s. rpz-passthru %s@%d %s. A IN\n",
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

// mockUnboundControl answers the resolver tools' commands as unbound
// would: a cache of the sample's usual names, the model's local names.
func mockUnboundControl(m *pf.Model, args []string) string {
	switch args[0] {
	case "lookup":
		return "The following name servers are used for lookup of " + args[1] + "\n;rrset 172800 4 0 8 0\ncom.\t172800\tIN\tNS\ta.gtld-servers.net.\ncom.\t172800\tIN\tNS\tb.gtld-servers.net.\nDelegation with 4 names, of which 4 can be examined to query further addresses.\nIt provides 8 IP addresses.\n192.5.6.30 \trto 42 msec, ttl 812, ping 38 var 1 rtt 42, tA 0, tAAAA 0, tother 0, EDNS 0 probed.\n"
	case "dump_cache":
		var b strings.Builder
		b.WriteString("START_RRSET_CACHE\n")
		for _, r := range [][2]string{{"www.openbsd.org.", "A\t199.185.178.80"}, {"openbsd.org.", "A\t199.185.178.80"}, {"github.com.", "A\t140.82.112.4"}, {"api.github.com.", "A\t140.82.113.6"}, {"pool.ntp.org.", "A\t162.159.200.1"}} {
			fmt.Fprintf(&b, ";rrset 2400 1 0 8 3\n%s\t2400\tIN\t%s\n", r[0], r[1])
		}
		b.WriteString("END_RRSET_CACHE\nSTART_MSG_CACHE\nmsg www.openbsd.org. IN A 33152 1 2400 3 1 0 0\nmsg github.com. IN A 33152 1 2400 3 1 0 0\nEND_MSG_CACHE\nEOF\n")
		return b.String()
	case "list_local_zones", "list_local_data":
		// What the generated unbound.conf gives it.
		var b strings.Builder
		for _, l := range strings.Split(pf.GenerateUnboundConf(m), "\n") {
			l = strings.TrimSpace(l)
			if z, ok := strings.CutPrefix(l, "local-zone: "); ok && args[0] == "list_local_zones" {
				b.WriteString(strings.ReplaceAll(z, `"`, "") + "\n")
			} else if d, ok := strings.CutPrefix(l, "local-data: "); ok && args[0] == "list_local_data" {
				f := strings.Fields(strings.Trim(d, `"'`))
				if len(f) > 1 && f[1] == "IN" {
					f = append([]string{f[0], "3600"}, f[1:]...)
				}
				b.WriteString(strings.Join(f, "\t") + "\n")
			}
		}
		return b.String()
	}
	return "ok\n" // the flushes
}
