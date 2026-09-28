package leases

import (
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/dantecatalfamo/OPF/internal/pf"
)

// Record is an A record in unbound's local data.
type Record struct {
	Name string // fully qualified, lower case, with the trailing dot
	IP   netip.Addr
}

// Skipped is a lease whose name wasn't registered, and why.
type Skipped struct {
	IP       netip.Addr
	Hostname string
	Reason   string
}

// TTL is how long resolvers may cache a lease's record. Leases move, so
// it's shorter than unbound's default for local data.
const TTL = 300

// A single DNS label (RFC 1123): letters, digits and inner hyphens.
var labelRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// Names no client may claim, because software looks them up to find
// services: web proxy auto-discovery, Windows' ISATAP tunnels.
var reservedLabels = []string{"localhost", "wpad", "isatap"}

// Enabled reports whether m asks for leases to be registered.
func Enabled(m *pf.Model) bool {
	return m.DNS.Enabled && m.DNS.RegisterDynamicLeases && m.System.Domain != ""
}

// Zone is the domain leases are registered under, as a fully qualified
// name.
func Zone(m *pf.Model) string {
	return strings.ToLower(m.System.Domain) + "."
}

// Static returns the names the configuration itself defines or
// reserves, fully qualified: the router, every reservation (whether or
// not it's registered), and every host override. Leases can't claim
// them, and a Watcher never touches their records.
func Static(m *pf.Model) map[string]bool {
	zone := Zone(m)
	names := map[string]bool{}
	add := func(host, domain string) {
		if host != "" {
			names[strings.ToLower(host)+"."+strings.ToLower(domain)+"."] = true
		}
	}
	add(m.System.Hostname, m.System.Domain)
	for _, l := range reservedLabels {
		names[l+"."+zone] = true
	}
	for _, s := range m.DHCP {
		for _, r := range s.Reservations {
			add(r.Hostname, m.System.Domain)
		}
	}
	for _, o := range m.DNS.Overrides {
		add(o.Host, o.Domain)
	}
	return names
}

// Records returns the records to register for the leases current at
// now. A client picks its own hostname, so a lease is only registered
// when:
//
//   - its hostname is a single valid label, which is lower-cased (no
//     dots, so it can't name something outside the zone);
//   - the name isn't one of the configuration's (Static), so a client
//     can't take over the router's name, a reserved device's, or wpad;
//   - no other current lease asks for the same name. When two do,
//     neither gets it: a newcomer can't take a name from a device
//     that's already using it, only stop it being registered;
//   - its address is in an enabled scope's dynamic range and isn't a
//     reservation's.
//
// The rest are returned as Skipped, except leases without a hostname.
func Records(m *pf.Model, leases []Lease, now time.Time) ([]Record, []Skipped) {
	if !Enabled(m) {
		return nil, nil
	}
	zone := Zone(m)
	static := Static(m)

	type span struct{ lo, hi netip.Addr }
	var ranges []span
	reserved := map[netip.Addr]bool{}
	for _, s := range m.DHCP {
		for _, r := range s.Reservations {
			if a, err := netip.ParseAddr(r.IP); err == nil {
				reserved[a] = true
			}
		}
		lo, err1 := netip.ParseAddr(s.RangeStart)
		hi, err2 := netip.ParseAddr(s.RangeEnd)
		if s.Enabled && err1 == nil && err2 == nil && lo.Is4() && hi.Is4() && lo.Compare(hi) <= 0 {
			ranges = append(ranges, span{lo, hi})
		}
	}
	inRange := func(a netip.Addr) bool {
		for _, r := range ranges {
			if a.Compare(r.lo) >= 0 && a.Compare(r.hi) <= 0 {
				return true
			}
		}
		return false
	}

	var skipped []Skipped
	byName := map[string][]Lease{}
	for _, l := range Current(leases, now) {
		if l.Hostname == "" {
			continue
		}
		skip := func(reason string) { skipped = append(skipped, Skipped{l.IP, l.Hostname, reason}) }
		label := strings.ToLower(l.Hostname)
		switch {
		case !labelRE.MatchString(label):
			skip("not a valid host name")
		case static[label+"."+zone]:
			skip("the name is taken by the configuration")
		case !l.IP.Is4() || !inRange(l.IP):
			skip("the address isn't in a DHCP range")
		case reserved[l.IP]:
			skip("the address is reserved for another device")
		default:
			byName[label] = append(byName[label], l)
		}
	}

	var records []Record
	for label, ls := range byName {
		if len(ls) > 1 {
			for _, l := range ls {
				skipped = append(skipped, Skipped{l.IP, l.Hostname, "another device uses the same name"})
			}
			continue
		}
		records = append(records, Record{Name: label + "." + zone, IP: ls[0].IP})
	}
	slices.SortFunc(records, func(a, b Record) int { return strings.Compare(a.Name, b.Name) })
	slices.SortFunc(skipped, func(a, b Skipped) int { return a.IP.Compare(b.IP) })
	return records, skipped
}
