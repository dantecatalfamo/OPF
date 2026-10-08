package pf

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// Local DNS records beyond host names (which are DNS.Overrides): aliases,
// mail servers, text, services, reverse names and CA authorisations,
// written as unbound local-data, and how each local domain answers the
// names it has no record for.
//
// unbound 1.26.1 (OpenBSD 7.9) answers a CNAME in local-data with the
// CNAME alone, whatever the zone type, and many clients' resolvers don't
// look the target up themselves. A redirect zone at the name does make
// it follow the CNAME, but through the internet, so a target of ours
// comes back "no such name". So an alias is written one of two ways:
// to one of this configuration's names with addresses, as that name's
// addresses; to anything else, as a CNAME in a redirect zone, which
// answers for the names under it too.

type DNSRecordType string

const (
	DNSRecordCNAME DNSRecordType = "CNAME" // an alias: Value is the name it stands for
	DNSRecordMX    DNSRecordType = "MX"    // Value is the mail server, Priority its preference
	DNSRecordTXT   DNSRecordType = "TXT"   // Value is the text
	DNSRecordSRV   DNSRecordType = "SRV"   // Value is the target, with Priority, Weight and Port
	DNSRecordPTR   DNSRecordType = "PTR"   // Name is an IP address, Value its name
	DNSRecordCAA   DNSRecordType = "CAA"   // Tag is issue, issuewild or iodef; Value what it allows
)

// DNSRecord is a record of the resolver's own. Name is the full name
// without the final dot ("office.arpa", "_sip._tcp.office.arpa"), or for
// a PTR the address.
type DNSRecord struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Type        DNSRecordType `json:"type"`
	Value       string        `json:"value"`
	Priority    *int          `json:"priority,omitempty"`
	Weight      *int          `json:"weight,omitempty"`
	Port        *int          `json:"port,omitempty"`
	Tag         string        `json:"tag,omitempty"`
	TTL         *int          `json:"ttl,omitempty"` // seconds; nil is DefaultDNSTTL
	Description string        `json:"description,omitempty"`
}

type DNSZoneType string

const (
	// DNSZoneStatic answers only from your records: any other name
	// under the domain is "no such name".
	DNSZoneStatic DNSZoneType = "static"
	// DNSZoneTransparent answers from your records first and looks up
	// the rest as usual, for a domain that also exists outside.
	DNSZoneTransparent DNSZoneType = "transparent"
)

// DNSZone says how a domain answers names without a record. The
// system's domain is static unless a zone says otherwise.
type DNSZone struct {
	Name string      `json:"name"`
	Type DNSZoneType `json:"type"`
}

const (
	DefaultDNSTTL = 3600
	MaxDNSRecords = 2000
	MaxDNSZones   = 64
	maxTXT        = 2048
)

// zoneType is how the local zone holding name answers ("" when none
// does), and that zone's name.
func zoneType(m *Model, name string) (DNSZoneType, string) {
	name = strings.ToLower(name)
	best, typ := "", DNSZoneType("")
	consider := func(z string, t DNSZoneType) {
		z = strings.ToLower(z)
		if z != "" && (name == z || strings.HasSuffix(name, "."+z)) && len(z) >= len(best) {
			best, typ = z, t
		}
	}
	consider(m.System.Domain, systemZoneType(m))
	for _, z := range m.DNS.Zones {
		consider(z.Name, z.Type)
	}
	return typ, best
}

func systemZoneType(m *Model) DNSZoneType {
	for _, z := range m.DNS.Zones {
		if strings.EqualFold(z.Name, m.System.Domain) {
			return z.Type
		}
	}
	return DNSZoneStatic
}

// LocalAddresses are the names this configuration gives addresses, in
// lower case with no final dot: host names, and reserved devices' when
// they're registered.
func LocalAddresses(m *Model) map[string][]string {
	names := map[string][]string{}
	add := func(n, a string) {
		n = strings.ToLower(n)
		if !slices.Contains(names[n], a) {
			names[n] = append(names[n], a)
		}
	}
	for _, o := range m.DNS.Overrides {
		add(o.Host+"."+o.Domain, o.IP)
	}
	if m.DNS.RegisterReservations && m.System.Domain != "" {
		for _, s := range m.DHCP {
			for _, r := range s.Reservations {
				if r.Hostname != "" {
					add(r.Hostname+"."+m.System.Domain, r.IP)
				}
			}
		}
	}
	return names
}

func addressRR(a string) string {
	if ip, err := netip.ParseAddr(a); err == nil && ip.Is6() {
		return "AAAA"
	}
	return "A"
}

func recordTTL(r DNSRecord) int {
	if r.TTL != nil {
		return *r.TTL
	}
	return DefaultDNSTTL
}

// txtStrings splits text into the quoted strings of at most 255 bytes
// a TXT record is made of.
func txtStrings(s string) string {
	var parts []string
	for len(s) > 255 {
		parts = append(parts, `"`+s[:255]+`"`)
		s = s[255:]
	}
	return strings.Join(append(parts, `"`+s+`"`), " ")
}

// recordLines are unbound.conf's lines for the local zones and records.
// Records are single-quoted, so a TXT's double quotes need no escaping;
// validation keeps quotes and backslashes out of every value.
func recordLines(m *Model) []string {
	d := m.DNS
	var lines []string
	for _, z := range d.Zones {
		if !strings.EqualFold(z.Name, m.System.Domain) {
			lines = append(lines, fmt.Sprintf("\tlocal-zone: \"%s.\" %s", z.Name, z.Type))
		}
	}
	local := LocalAddresses(m)
	for _, r := range d.Records {
		ttl := recordTTL(r)
		rr := func(format string, a ...any) {
			lines = append(lines, fmt.Sprintf("\tlocal-data: '%s. %d IN %s'", r.Name, ttl, fmt.Sprintf(format, a...)))
		}
		switch r.Type {
		case DNSRecordCNAME:
			if addrs, ok := local[strings.ToLower(r.Value)]; ok {
				for _, a := range addrs {
					rr("%s %s", addressRR(a), a)
				}
			} else {
				lines = append(lines, fmt.Sprintf("\tlocal-zone: \"%s.\" redirect", r.Name))
				rr("CNAME %s.", r.Value)
			}
		case DNSRecordMX:
			rr("MX %d %s.", deref(r.Priority), r.Value)
		case DNSRecordTXT:
			rr("TXT %s", txtStrings(r.Value))
		case DNSRecordSRV:
			target := r.Value + "."
			if r.Value == "." {
				target = "."
			}
			rr("SRV %d %d %d %s", deref(r.Priority), deref(r.Weight), deref(r.Port), target)
		case DNSRecordCAA:
			rr("CAA 0 %s \"%s\"", r.Tag, r.Value)
		case DNSRecordPTR:
			lines = append(lines, fmt.Sprintf("\tlocal-data-ptr: \"%s %d %s.\"", r.Name, ttl, r.Value))
		}
	}
	return lines
}

func deref(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}

// PrivateTopLevel are single-label names used for networks of one's own,
// which may answer only their own names: ICANN's .internal, the
// reserved test names, and ones commonly used inside networks.
var PrivateTopLevel = []string{"internal", "lan", "home", "corp", "intranet", "private", "localdomain", "test", "example", "invalid"}

// IsTopLevel is a single-label name that may be the internet's: a
// domain answering only its own names there would hide every name
// under it (com, org, uk).
func IsTopLevel(name string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	return name != "" && !strings.Contains(name, ".") && !slices.Contains(PrivateTopLevel, name)
}

// isRecordName is a name a record can have: labels of letters, digits,
// hyphens and underscores (_sip._tcp, _dmarc), no final dot, no
// wildcard.
func isRecordName(s string) bool {
	return !strings.HasPrefix(s, "*") && !strings.HasSuffix(s, ".") && IsBlockName(s)
}

// isHostTarget is a name a record can point at: a host name, so letters,
// digits and hyphens only.
func isHostTarget(s string) bool {
	if s == "" || len(s) > 253 || strings.HasSuffix(s, ".") {
		return false
	}
	for _, l := range strings.Split(s, ".") {
		if !dnsLabelRE.MatchString(l) {
			return false
		}
	}
	return true
}

// recordText is what a TXT or CAA value may hold: printable ASCII
// without quotes or backslashes, which unbound's parser would take as
// the end of the string or an escape.
func recordText(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c > 0x7e || c == '"' || c == '\'' || c == '\\' {
			return false
		}
	}
	return true
}

func (v *validator) dnsRecords() {
	m, d := v.m, v.m.DNS
	if len(d.Zones) > MaxDNSZones {
		v.fail("dns.zones", "at most %d", MaxDNSZones)
	}
	zones := map[string]bool{}
	for i, z := range d.Zones {
		p := at("dns.zones", i)
		n := strings.ToLower(z.Name)
		switch {
		case !isHostTarget(z.Name):
			v.fail(p+".name", "%q isn't a domain", z.Name)
		case n == "arpa" || n == "in-addr.arpa" || n == "ip6.arpa":
			v.fail(p+".name", "%s holds every reverse name; use a domain under it", z.Name)
		case z.Type == DNSZoneStatic && IsTopLevel(n):
			v.fail(p+".type", "%s is a top-level domain: answering only your names in it would hide every name under it", z.Name)
		}
		v.unique(p+".name", zones, n, "domain")
		v.oneOf(p+".type", string(z.Type), string(DNSZoneStatic), string(DNSZoneTransparent))
	}

	if len(d.Records) > MaxDNSRecords {
		v.fail("dns.records", "at most %d", MaxDNSRecords)
	}
	local := LocalAddresses(m)
	// What's at each name besides records: the names this configuration
	// gives addresses, and the firewall's own.
	taken := map[string]string{}
	for n := range local {
		taken[n] = "a host name or reserved device"
	}
	if m.System.Hostname != "" && m.System.Domain != "" {
		taken[strings.ToLower(m.System.Hostname+"."+m.System.Domain)] = "the firewall's own name"
	}
	apex := map[string]bool{strings.ToLower(m.System.Domain): true}
	for n := range zones {
		apex[n] = true
	}
	aliases := map[string]string{} // alias name → the name it stands for
	at1 := map[string][]int{}      // name → records there
	for i, r := range d.Records {
		if r.Type == DNSRecordCNAME {
			aliases[strings.ToLower(r.Name)] = r.Value
		}
		if r.Type != DNSRecordPTR {
			at1[strings.ToLower(r.Name)] = append(at1[strings.ToLower(r.Name)], i)
		}
	}

	ids := map[string]bool{}
	same := map[string]bool{}
	ptrs := map[netip.Addr]bool{}
	for i, r := range d.Records {
		p := at("dns.records", i)
		v.re(p+".id", r.ID, idRE, "id")
		v.unique(p+".id", ids, r.ID, "record id")
		v.text(p+".description", r.Description, 200, false)
		if r.TTL != nil {
			v.intRange(p+".ttl", *r.TTL, 0, 604800)
		}
		port := func(path string, n *int, what string) {
			if n == nil {
				v.fail(path, "enter the %s", what)
			} else {
				v.intRange(path, *n, 0, 65535)
			}
		}
		name := strings.ToLower(r.Name)
		if r.Type == DNSRecordPTR {
			a, err := netip.ParseAddr(r.Name)
			if err != nil || a.Zone() != "" {
				v.fail(p+".name", "%q isn't an IP address", r.Name)
			} else if ptrs[a] {
				v.fail(p+".name", "%s already has a reverse name", r.Name)
			} else {
				ptrs[a] = true
			}
			if !isHostTarget(r.Value) {
				v.fail(p+".value", "%q isn't a host name", r.Value)
			}
		} else if !isRecordName(r.Name) {
			v.fail(p+".name", "%q isn't a name like office.arpa or _sip._tcp.office.arpa", r.Name)
			continue
		}
		key := strings.Join([]string{string(r.Type), name, strings.ToLower(r.Value), r.Tag, strconv.Itoa(deref(r.Priority)), strconv.Itoa(deref(r.Weight)), strconv.Itoa(deref(r.Port))}, " ")
		if same[key] {
			v.fail(p, "is the same as another record")
		}
		same[key] = true

		switch r.Type {
		case DNSRecordCNAME:
			v.dnsAlias(p, r, local, taken, apex, aliases, at1)
		case DNSRecordMX:
			port(p+".priority", r.Priority, "preference")
			if !isHostTarget(r.Value) {
				v.fail(p+".value", "%q isn't a host name", r.Value)
			}
		case DNSRecordTXT:
			switch {
			case r.Value == "":
				v.fail(p+".value", "enter the text")
			case len(r.Value) > maxTXT:
				v.fail(p+".value", "is %d characters; the most is %d", len(r.Value), maxTXT)
			case !recordText(r.Value):
				v.fail(p+".value", "only printable ASCII, without quotes or backslashes")
			}
		case DNSRecordSRV:
			port(p+".priority", r.Priority, "priority")
			port(p+".weight", r.Weight, "weight")
			port(p+".port", r.Port, "port")
			if r.Value != "." && !isHostTarget(r.Value) {
				v.fail(p+".value", "%q isn't a host name (or . for none)", r.Value)
			}
		case DNSRecordCAA:
			v.oneOf(p+".tag", r.Tag, "issue", "issuewild", "iodef")
			switch {
			case r.Value == "" || len(r.Value) > 255:
				v.fail(p+".value", "enter what it allows, at most 255 characters")
			case !recordText(r.Value) || strings.Contains(r.Value, " "):
				v.fail(p+".value", "only printable ASCII, without spaces, quotes or backslashes")
			}
		case DNSRecordPTR:
		default:
			v.fail(p+".type", "must be one of CNAME, MX, TXT, SRV, PTR, CAA, not %q", r.Type)
		}
	}
}

// dnsAlias checks a CNAME: alone at its name, and pointing somewhere it can
// be followed.
func (v *validator) dnsAlias(p string, r DNSRecord, local map[string][]string, taken map[string]string, apex map[string]bool, aliases map[string]string, at1 map[string][]int) {
	name, target := strings.ToLower(r.Name), strings.ToLower(r.Value)
	if !isHostTarget(r.Value) {
		v.fail(p+".value", "%q isn't a host name", r.Value)
		return
	}
	switch {
	case apex[name]:
		v.fail(p+".name", "%s is a domain; an alias can't be a domain itself", r.Name)
	case taken[name] != "":
		v.fail(p+".name", "%s is already %s; an alias must be the only thing at its name", r.Name, taken[name])
	case len(at1[name]) > 1:
		v.fail(p+".name", "%s has other records; an alias must be the only thing at its name", r.Name)
	}
	if target == name {
		v.fail(p+".value", "an alias can't stand for itself")
		return
	}
	if to, ok := aliases[target]; ok {
		v.fail(p+".value", "%s is an alias too; point at the name it stands for, %s", r.Value, to)
		return
	}
	if _, ok := local[target]; ok {
		return // written as the target's addresses
	}
	if t, zone := zoneType(v.m, target); t == DNSZoneStatic {
		v.fail(p+".value", "%s has no address here, and %s answers only its own names: point at a host name or reserved device", r.Value, zone)
		return
	}
	// A CNAME in a redirect zone, which takes the names under it too.
	under := func(n string) bool { return strings.HasSuffix(n, "."+name) }
	for n := range taken {
		if under(n) {
			v.fail(p+".name", "%s is under this alias, which would answer for it too", n)
			return
		}
	}
	for n := range at1 {
		if under(n) {
			v.fail(p+".name", "%s has records, and is under this alias, which would answer for it too", n)
			return
		}
	}
	for n := range apex {
		if under(n) {
			v.fail(p+".name", "the domain %s is under this alias, which would answer for it too", n)
			return
		}
	}
}

// The firewall's own name, answered on each inside network with the
// firewall's address there. unbound picks the answers by the network
// the question comes from (access-control-view); with view-first, every
// other name falls through to the zones above. (interface-view, by the
// address asked, didn't apply on 7.9.)

// firewallView is the view for an inside interface's network.
func firewallView(i Iface) string { return "opf-net-" + i.ID }

// selfView is the firewall's own questions' view, from loopback: its
// name with its address on every inside network, as one record would
// without views. Without it, the firewall's name didn't exist on the
// firewall (the name is only in the networks' views).
const selfView = "opf-self"

// firewallName is the firewall's name, fully qualified without the
// final dot, or "" when it has none.
func firewallName(m *Model) string {
	if m.System.Hostname == "" || m.System.Domain == "" {
		return ""
	}
	return m.System.Hostname + "." + m.System.Domain
}

// firewallViewLines are the server: lines that put each inside
// network in its view.
func firewallViewLines(m *Model, inside []Iface) []string {
	if firewallName(m) == "" {
		return nil
	}
	var lines []string
	for _, i := range inside {
		lines = append(lines, fmt.Sprintf("\taccess-control-view: %s/%d %s", networkAddr(i.IPv4.Address, *i.IPv4.Prefix), *i.IPv4.Prefix, firewallView(i)))
	}
	if len(inside) > 0 {
		lines = append(lines, "\taccess-control-view: 127.0.0.0/8 "+selfView)
	}
	return lines
}

// firewallViews are the views themselves.
func firewallViews(m *Model, inside []Iface) []string {
	name := firewallName(m)
	if name == "" {
		return nil
	}
	var lines []string
	for _, i := range inside {
		lines = append(lines, "", "view:",
			fmt.Sprintf("\tname: \"%s\"", firewallView(i)),
			"\tview-first: yes",
			fmt.Sprintf("\tlocal-data: \"%s. IN A %s\"", name, i.IPv4.Address))
	}
	if len(inside) > 0 {
		lines = append(lines, "", "view:", fmt.Sprintf("\tname: \"%s\"", selfView), "\tview-first: yes")
		for _, i := range inside {
			lines = append(lines, fmt.Sprintf("\tlocal-data: \"%s. IN A %s\"", name, i.IPv4.Address))
		}
	}
	return lines
}

// ReverseName is an address's reverse (PTR) name.
type ReverseName struct {
	IP   netip.Addr
	Name string // fully qualified, without the final dot
}

// ReverseNames are the reverse names the configuration gives, one per
// address: a reverse name record's first, then the firewall's on each
// inside network, host names, and reserved devices' when they're in
// DNS. A lease's name only gets a reverse name when its address has
// none of these.
func ReverseNames(m *Model) []ReverseName {
	var out []ReverseName
	seen := map[netip.Addr]bool{}
	add := func(ip, name string) {
		a, err := netip.ParseAddr(ip)
		if err != nil || seen[a] || name == "" {
			return
		}
		seen[a] = true
		out = append(out, ReverseName{IP: a, Name: name})
	}
	for _, r := range m.DNS.Records {
		if r.Type == DNSRecordPTR {
			add(r.Name, r.Value)
		}
	}
	if name := firewallName(m); name != "" {
		for _, i := range staticIfaces(m) {
			if i.Role != RoleWAN {
				add(i.IPv4.Address, name)
			}
		}
	}
	for _, o := range m.DNS.Overrides {
		add(o.IP, o.Host+"."+o.Domain)
	}
	if m.DNS.RegisterReservations && m.System.Domain != "" {
		for _, s := range m.DHCP {
			for _, r := range s.Reservations {
				if r.Hostname != "" {
					add(r.IP, r.Hostname+"."+m.System.Domain)
				}
			}
		}
	}
	return out
}

// reverseLines are local-data-ptr lines for the reverse names that
// aren't records (recordLines writes those, with their TTL).
func reverseLines(m *Model) []string {
	explicit := map[netip.Addr]bool{}
	for _, r := range m.DNS.Records {
		if a, err := netip.ParseAddr(r.Name); err == nil && r.Type == DNSRecordPTR {
			explicit[a] = true
		}
	}
	var lines []string
	for _, r := range ReverseNames(m) {
		if !explicit[r.IP] {
			lines = append(lines, fmt.Sprintf("\tlocal-data-ptr: \"%s %s.\"", r.IP, r.Name))
		}
	}
	return lines
}
