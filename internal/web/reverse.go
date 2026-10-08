package web

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/dantecatalfamo/OPF/internal/appliance"
)

// Reverse DNS for the addresses a page shows (connections, the firewall
// log), when someone asks for them. This process asks the firewall's
// own resolver, unbound on 127.0.0.1, itself: it can open sockets but
// can't read /etc/resolv.conf, and unbound has the network's own
// reverse names (DHCP leases, reservations) and caches the rest. The
// answers are kept here, in memory, for a while.

const (
	// reverseMax is the most addresses one request may ask about.
	reverseMax = 256
	// reverseCache is the most answers kept; past it the expired ones
	// go, then all of them.
	reverseCache = 4096
	// How long an answer is kept: a name, no name, and a failure.
	reverseNameTTL   = 10 * time.Minute
	reverseNoneTTL   = 5 * time.Minute
	reverseFailedTTL = 30 * time.Second
	// reverseParallel is how many lookups run at once, for every
	// request together; reverseTimeout bounds each.
	reverseParallel = 8
	reverseTimeout  = 3 * time.Second
	// reverseDeadline bounds a whole request.
	reverseDeadline = 10 * time.Second
)

// ReverseLookup returns the names an address has (PTR records). An
// error that isn't a *net.DNSError saying it's not found means the
// lookup failed.
type ReverseLookup func(ctx context.Context, addr string) ([]string, error)

// unboundLookup asks unbound on 127.0.0.1, whatever resolv.conf says.
func unboundLookup() ReverseLookup {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, "127.0.0.1:53")
		},
	}
	return r.LookupAddr
}

type reverseAnswer struct {
	name   string // "" for none
	failed bool
	until  time.Time
}

type reverser struct {
	lookup ReverseLookup
	slots  chan struct{}
	mu     sync.Mutex
	cache  map[netip.Addr]reverseAnswer
}

func newReverser(lookup ReverseLookup) *reverser {
	return &reverser{lookup: lookup, slots: make(chan struct{}, reverseParallel), cache: map[netip.Addr]reverseAnswer{}}
}

// SetReverseLookup replaces how addresses are looked up (the mock's
// made-up names), forgetting what was kept.
func (s *Server) SetReverseLookup(f ReverseLookup) { s.reverse = newReverser(f) }

// hostName is a PTR answer as it's shown: without its final dot, and
// only if it's a host name. The answer comes from whoever controls the
// address's reverse zone, so anything else is dropped.
func hostName(s string) string {
	s = strings.TrimSuffix(s, ".")
	if s == "" || len(s) > 253 {
		return ""
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 {
			return ""
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
				return ""
			}
		}
	}
	return s
}

func (v *reverser) cached(a netip.Addr, now time.Time) (reverseAnswer, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	ans, ok := v.cache[a]
	if ok && now.After(ans.until) {
		delete(v.cache, a)
		ok = false
	}
	return ans, ok
}

func (v *reverser) keep(a netip.Addr, ans reverseAnswer, now time.Time) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(v.cache) >= reverseCache {
		for k, x := range v.cache {
			if now.After(x.until) {
				delete(v.cache, k)
			}
		}
		if len(v.cache) >= reverseCache {
			clear(v.cache)
		}
	}
	v.cache[a] = ans
}

func (v *reverser) one(ctx context.Context, a netip.Addr) reverseAnswer {
	now := time.Now()
	if ans, ok := v.cached(a, now); ok {
		return ans
	}
	select {
	case v.slots <- struct{}{}:
		defer func() { <-v.slots }()
	case <-ctx.Done():
		return reverseAnswer{failed: true}
	}
	lctx, cancel := context.WithTimeout(ctx, reverseTimeout)
	defer cancel()
	names, err := v.lookup(lctx, a.String())
	var dnsErr *net.DNSError
	var ans reverseAnswer
	switch {
	case err == nil:
		for _, n := range names {
			if ans.name = hostName(n); ans.name != "" {
				break
			}
		}
		ans.until = now.Add(reverseNameTTL)
		if ans.name == "" {
			ans.until = now.Add(reverseNoneTTL)
		}
	case errors.As(err, &dnsErr) && dnsErr.IsNotFound:
		ans.until = now.Add(reverseNoneTTL)
	case ctx.Err() != nil:
		// The request gave up: not the address's fault, so not kept.
		return reverseAnswer{failed: true}
	default:
		ans = reverseAnswer{failed: true, until: now.Add(reverseFailedTTL)}
	}
	v.keep(a, ans, now)
	return ans
}

type reverseRequest struct {
	Addresses []string `json:"addresses"`
}

// reverseResult has a name for each address asked about that has one,
// "" for each that has none, and lists those it couldn't look up.
type reverseResult struct {
	Names  map[string]string `json:"names"`
	Failed []string          `json:"failed"`
}

func (s *Server) reverseNames(w http.ResponseWriter, r *http.Request) {
	var req reverseRequest
	if !decode(w, r, &req) {
		return
	}
	if len(req.Addresses) > reverseMax {
		writeError(w, http.StatusBadRequest, &appliance.Error{Code: appliance.CodeInvalid, Message: "too many addresses: ask about at most 256 at once"})
		return
	}
	var addrs []netip.Addr
	seen := map[netip.Addr]bool{}
	for _, s := range req.Addresses {
		a, err := netip.ParseAddr(s)
		if err != nil || a.Zone() != "" {
			writeError(w, http.StatusBadRequest, &appliance.Error{Code: appliance.CodeInvalid, Message: "not an address: " + s})
			return
		}
		if a = a.Unmap(); !seen[a] {
			seen[a] = true
			addrs = append(addrs, a)
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), reverseDeadline)
	defer cancel()
	out := reverseResult{Names: map[string]string{}, Failed: []string{}}
	answers := make([]reverseAnswer, len(addrs))
	var wg sync.WaitGroup
	for i, a := range addrs {
		wg.Go(func() { answers[i] = s.reverse.one(ctx, a) })
	}
	wg.Wait()
	for i, a := range addrs {
		if answers[i].failed {
			out.Failed = append(out.Failed, a.String())
		} else {
			out.Names[a.String()] = answers[i].name
		}
	}
	writeJSON(w, http.StatusOK, out)
}
