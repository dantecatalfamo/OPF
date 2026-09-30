package sysinfo

import (
	"strconv"
	"strings"
	"time"
)

// UnboundStats is unbound's counters from `unbound-control
// stats_noreset`, summed over its threads (the total.* lines). Counters
// count since unbound started or last reloaded. The maps come from
// extended-statistics, which leave out counters that are zero.
type UnboundStats struct {
	Queries     uint64 `json:"queries"`
	CacheHits   uint64 `json:"cacheHits"`
	CacheMisses uint64 `json:"cacheMisses"`
	Prefetches  uint64 `json:"prefetches"`
	// Recursion times are for answers that weren't in the cache, in
	// seconds.
	RecursionAvg    float64 `json:"recursionAvg"`
	RecursionMedian float64 `json:"recursionMedian"`
	Uptime          float64 `json:"uptime"` // seconds since it started or reloaded

	Extended bool `json:"extended"` // the maps below are there
	// Answers by response code (NOERROR, NXDOMAIN, SERVFAIL...), and
	// "nodata" for NOERROR answers with no records.
	Answers map[string]uint64 `json:"answers"`
	// Secure answers passed DNSSEC validation; bogus ones failed it.
	Secure uint64 `json:"secure"`
	Bogus  uint64 `json:"bogus"`
	// RPZ is response policy actions taken, by action (nxdomain,
	// local_data, passthru...).
	RPZ        map[string]uint64 `json:"rpz"`
	QueryTypes map[string]uint64 `json:"queryTypes"`
	// Memory is bytes in use by unbound's caches and modules, by name
	// (cache.rrset, mod.iterator...). It leaves out zones: the process's
	// size is the full cost.
	Memory map[string]uint64 `json:"memory"`
}

// RPZPass are the policy actions that let a query through rather than
// block it.
var RPZPass = map[string]bool{"passthru": true, "disabled": true, "no_override": true, "invalid": true}

// Blocked is how many queries a policy zone blocked.
func (s UnboundStats) Blocked() uint64 {
	var n uint64
	for a, c := range s.RPZ {
		if !RPZPass[a] {
			n += c
		}
	}
	return n
}

// ParseUnboundStats reads `unbound-control stats_noreset`: lines of
// name=value.
func ParseUnboundStats(out string) (UnboundStats, bool) {
	s := UnboundStats{Answers: map[string]uint64{}, RPZ: map[string]uint64{}, QueryTypes: map[string]uint64{}, Memory: map[string]uint64{}}
	seen := false
	for _, l := range lines(out) {
		k, v, ok := strings.Cut(strings.TrimSpace(l), "=")
		if !ok {
			continue
		}
		n, _ := strconv.ParseUint(v, 10, 64)
		f, _ := strconv.ParseFloat(v, 64)
		switch {
		case k == "total.num.queries":
			s.Queries, seen = n, true
		case k == "total.num.cachehits":
			s.CacheHits = n
		case k == "total.num.cachemiss":
			s.CacheMisses = n
		case k == "total.num.prefetch":
			s.Prefetches = n
		case k == "total.recursion.time.avg":
			s.RecursionAvg = f
		case k == "total.recursion.time.median":
			s.RecursionMedian = f
		case k == "time.up":
			s.Uptime = f
		case k == "num.answer.secure":
			s.Secure, s.Extended = n, true
		case k == "num.answer.bogus":
			s.Bogus, s.Extended = n, true
		case strings.HasPrefix(k, "num.answer.rcode."):
			s.Answers[strings.TrimPrefix(k, "num.answer.rcode.")], s.Extended = n, true
		case strings.HasPrefix(k, "num.rpz.action."):
			s.RPZ[strings.TrimPrefix(k, "num.rpz.action.")], s.Extended = n, true
		case strings.HasPrefix(k, "num.query.type."):
			s.QueryTypes[strings.TrimPrefix(k, "num.query.type.")], s.Extended = n, true
		case strings.HasPrefix(k, "mem."):
			s.Memory[strings.TrimPrefix(k, "mem.")] = n
		}
	}
	return s, seen
}

// RPZHit is one query a response policy zone acted on, from the line
// unbound logs for it with rpz-log (in syslog's daemon log):
//
//	Sep 29 10:00:00 fw unbound: [123:0] info: rpz: applied [opf:list:ads] *.example.net. local_data 192.0.2.10@53211 ads.example.net. A IN
type RPZHit struct {
	Time time.Time `json:"time"`
	// Zone is the zone's rpz-log-name, in brackets in the line; empty
	// when it has none.
	Zone string `json:"zone,omitempty"`
	// Trigger is the zone's entry that matched: the name, or *. and one.
	Trigger string `json:"trigger"`
	Action  string `json:"action"`
	Client  string `json:"client,omitempty"` // the address that asked, without its port
	Name    string `json:"name"`             // what it asked for, without the final dot
	Type    string `json:"type"`
}

// ParseRPZLog reads unbound's rpz-log lines out of a syslog file,
// skipping every other line. Syslog's timestamps have no year: each is
// taken to be the latest one that isn't after now.
func ParseRPZLog(out string, now time.Time) []RPZHit {
	var hs []RPZHit
	for _, l := range lines(out) {
		if h, ok := parseRPZLine(l, now); ok {
			hs = append(hs, h)
		}
	}
	return hs
}

func parseRPZLine(l string, now time.Time) (RPZHit, bool) {
	var h RPZHit
	_, rest, ok := strings.Cut(l, " unbound: ")
	if !ok || len(l) < 15 {
		return h, false
	}
	_, rest, ok = strings.Cut(rest, " info: rpz: applied ")
	if !ok {
		return h, false
	}
	t, err := time.ParseInLocation("Jan _2 15:04:05", l[:15], now.Location())
	if err != nil {
		return h, false
	}
	h.Time = withYear(t, now)
	f := strings.Fields(rest)
	if len(f) > 0 && strings.HasPrefix(f[0], "[") && strings.HasSuffix(f[0], "]") {
		h.Zone = f[0][1 : len(f[0])-1]
		f = f[1:]
	}
	// Then [trigger kind] entry action [client@port], and the query:
	// name type class.
	if len(f) < 5 {
		return h, false
	}
	q := f[len(f)-3:]
	f = f[:len(f)-3]
	h.Name, h.Type = strings.TrimSuffix(q[0], "."), q[1]
	if c, port, ok := strings.Cut(f[len(f)-1], "@"); ok {
		if _, err := strconv.ParseUint(port, 10, 16); err != nil {
			return h, false
		}
		h.Client = c
		f = f[:len(f)-1]
	}
	if len(f) < 2 {
		return h, false
	}
	h.Action = f[len(f)-1]
	h.Trigger = strings.TrimSuffix(f[len(f)-2], ".")
	return h, h.Name != "" && rpzActions[h.Action]
}

// rpzActions are the actions unbound logs (rpz_action_to_string); a
// line with anything else there isn't one it wrote.
var rpzActions = map[string]bool{
	"nxdomain": true, "nodata": true, "passthru": true, "drop": true, "tcp_only": true,
	"local_data": true, "disabled": true, "cname_override": true, "no_override": true, "invalid": true,
}

// ParseProcessRSS reads `ps -A -o rss=,comm=` and returns the resident
// memory of the processes called name, in bytes (ps prints kilobytes).
func ParseProcessRSS(out, name string) (uint64, bool) {
	var total uint64
	found := false
	for _, l := range lines(out) {
		f := strings.Fields(l)
		if len(f) != 2 || f[1] != name {
			continue
		}
		kb, err := strconv.ParseUint(f[0], 10, 64)
		if err != nil {
			continue
		}
		total += kb * 1024
		found = true
	}
	return total, found
}
