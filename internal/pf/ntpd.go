package pf

import (
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// ntpd.conf(5): the time servers ntpd syncs to, the sensors it reads,
// the HTTPS servers whose Date bounds what the servers may say, and the
// addresses it serves time on. The grammar is OpenBSD 7.9's parse.y.

// NTPSettings are ntpd's options beyond SystemSettings.NTPServers.
type NTPSettings struct {
	// Servers are time servers with options, or synced to at only one
	// of their addresses.
	Servers []NTPServer `json:"servers,omitempty"`
	// Sensors are timedelta sensors (sensor(4)): a GPS or radio clock.
	Sensors []NTPSensor `json:"sensors,omitempty"`
	// Constraints are HTTPS servers whose Date header bounds the time
	// the servers give; an NTP server far off it is ignored. None, and
	// ntpd believes the servers.
	Constraints []NTPConstraint `json:"constraints,omitempty"`
	// ServeOn are the interfaces (ids) whose networks the firewall
	// serves time to (NTPServed): ntpd answers on each one's address,
	// pf lets the network ask it unless a rule on it says otherwise,
	// and DHCP tells its devices to use it.
	ServeOn []string `json:"serveOn,omitempty"`
	// Listen are other addresses ntpd serves time on, for which pf has
	// to be told by hand to let the queries in.
	Listen []NTPListen `json:"listen,omitempty"`
	// QueryFrom are the addresses ntpd asks the servers from: at most
	// one IPv4 and one IPv6 address. Unset, the outgoing interface's.
	QueryFrom []string `json:"queryFrom,omitempty"`
}

// NTPServer is a server or servers line.
type NTPServer struct {
	// Address is a host name or an IP address.
	Address string `json:"address"`
	// One syncs to the name's first address that answers (server),
	// rather than to every address it has (servers).
	One bool `json:"one,omitempty"`
	// Trusted skips the constraints for its time: for setting the clock
	// at boot where no constraint can be reached.
	Trusted bool `json:"trusted,omitempty"`
	// Weight is its influence against the others, 1 to 10; 0 is 1.
	Weight int `json:"weight,omitempty"`
}

// NTPSensor is a sensor line.
type NTPSensor struct {
	// Device is a sensor device, such as nmea0, or * for every one.
	Device string `json:"device"`
	// Correction is added to its time, in microseconds.
	Correction int `json:"correction,omitempty"`
	// RefID is the reference ID shown to clients, 1 to 4 letters or
	// digits, such as GPS.
	RefID string `json:"refid,omitempty"`
	// Stratum is the stratum served, 1 to 15; 0 is 1.
	Stratum int  `json:"stratum,omitempty"`
	Trusted bool `json:"trusted,omitempty"`
	Weight  int  `json:"weight,omitempty"`
}

// NTPConstraint is a constraint or constraints line.
type NTPConstraint struct {
	// URL is an https:// URL, a host name or an IP address.
	URL string `json:"url"`
	// Every asks every address the name has and takes their median
	// (constraints); otherwise the first that answers (constraint).
	Every bool `json:"every,omitempty"`
	// Addresses are IP addresses to try for the URL's host, without
	// looking it up; not with Every.
	Addresses []string `json:"addresses,omitempty"`
}

// NTPListen is a listen on line.
type NTPListen struct {
	// Address is an IP address, or * for every one.
	Address string `json:"address"`
	// RTable is only read from older models, and from an ntpd.conf
	// being imported: Upgrade drops it, and Validate refuses it, so
	// such a line is left out. OPF creates no routing tables.
	RTable int `json:"rtable,omitempty"`
}

// MaxNTPItems bounds each of NTPSettings' lists, and NTPServers.
const MaxNTPItems = 32

var (
	ntpDeviceRE = regexp.MustCompile(`^(\*|[a-z]{1,12}[0-9]{1,3})$`)
	ntpRefIDRE  = regexp.MustCompile(`^[A-Za-z0-9]{1,4}$`)
	// The path of a constraint's URL: what a URL's path holds, less
	// what ntpd's lexer or a quoted string would take for something else.
	ntpPathRE = regexp.MustCompile(`^/[A-Za-z0-9._~&'()*+,;=:@/%-]{0,200}$`)
	// A word ntpd's lexer reads whole, unquoted.
	ntpWordRE = regexp.MustCompile(`^[A-Za-z0-9:_*][A-Za-z0-9:_*.-]*$`)
	ntpNumRE  = regexp.MustCompile(`^-?[0-9]+$`)
)

// ntpKeywords are ntpd.conf's keywords, which an unquoted word is taken
// for.
var ntpKeywords = []string{"constraint", "constraints", "correction", "from", "listen", "on", "query", "refid", "rtable", "sensor", "server", "servers", "stratum", "trusted", "weight"}

// ntpdWord writes a validated name as ntpd reads it: as it is, or
// quoted when it would be read as a keyword or a number.
func ntpdWord(s string) string {
	if ntpWordRE.MatchString(s) && !ntpNumRE.MatchString(s) && !slices.Contains(ntpKeywords, s) {
		return s
	}
	return `"` + s + `"`
}

// NTPEligible is whether the firewall can serve time to an interface's
// network: as for the resolver (DNSEligible), one inside, with a fixed
// IPv4 address to listen on and a network to let in.
func NTPEligible(i *Iface) bool { return DNSEligible(i) }

// NTPServed are the interfaces the firewall serves time to.
func NTPServed(m *Model) []Iface {
	if m.System.NTP == nil || Unmanaged(m, AreaNTP) {
		return nil
	}
	var out []Iface
	for _, i := range m.Interfaces {
		if NTPEligible(&i) && slices.Contains(m.System.NTP.ServeOn, i.ID) {
			out = append(out, i)
		}
	}
	return out
}

// ntpServes is whether the firewall serves time to the interface.
func ntpServes(m *Model, id string) bool {
	return slices.ContainsFunc(NTPServed(m), func(i Iface) bool { return i.ID == id })
}

func ntpdConf(m *Model) string {
	s := m.System
	n := s.NTP
	if n == nil {
		n = &NTPSettings{}
	}
	var lines []string
	add := func(format string, args ...any) { lines = append(lines, fmt.Sprintf(format, args...)) }
	for _, i := range NTPServed(m) {
		if !slices.Contains(n.Listen, NTPListen{Address: i.IPv4.Address}) {
			add("listen on %s", i.IPv4.Address)
		}
	}
	for _, l := range n.Listen {
		add("listen on %s", ntpdWord(l.Address))
	}
	// Before the servers: it applies to those after it.
	for _, q := range n.QueryFrom {
		add("query from %s", ntpdWord(q))
	}
	for _, srv := range s.NTPServers {
		add("servers %s", ntpdWord(srv))
	}
	for _, srv := range n.Servers {
		line := "servers "
		if srv.One {
			line = "server "
		}
		line += ntpdWord(srv.Address)
		if srv.Trusted {
			line += " trusted"
		}
		if srv.Weight != 0 {
			line += fmt.Sprintf(" weight %d", srv.Weight)
		}
		add("%s", line)
	}
	for _, sn := range n.Sensors {
		line := "sensor " + ntpdWord(sn.Device)
		if sn.Correction != 0 {
			line += fmt.Sprintf(" correction %d", sn.Correction)
		}
		if sn.RefID != "" {
			line += " refid " + ntpdWord(sn.RefID)
		}
		if sn.Stratum != 0 {
			line += fmt.Sprintf(" stratum %d", sn.Stratum)
		}
		if sn.Trusted {
			line += " trusted"
		}
		if sn.Weight != 0 {
			line += fmt.Sprintf(" weight %d", sn.Weight)
		}
		add("%s", line)
	}
	for _, c := range n.Constraints {
		if c.Every {
			add(`constraints from "%s"`, c.URL)
			continue
		}
		line := fmt.Sprintf(`constraint from "%s"`, c.URL)
		for _, a := range c.Addresses {
			line += fmt.Sprintf(` "%s"`, a)
		}
		add("%s", line)
	}
	return strings.Join(lines, "\n") + "\n"
}

// ntpSources is how many time servers and sensors there are.
func ntpSources(s SystemSettings) int {
	n := len(s.NTPServers)
	if s.NTP != nil {
		n += len(s.NTP.Servers) + len(s.NTP.Sensors)
	}
	return n
}

// ntp checks the time servers and the rest of ntpd.conf; system checks
// there's a source.
func (v *validator) ntp() {
	s := v.m.System
	n := s.NTP
	if n == nil {
		n = &NTPSettings{}
	}
	count := func(path string, l int) {
		if l > MaxNTPItems {
			v.fail(path, "at most %d", MaxNTPItems)
		}
	}
	count("system.ntpServers", len(s.NTPServers))
	for i, srv := range s.NTPServers {
		v.host(at("system.ntpServers", i), srv)
	}
	if s.NTP == nil {
		return
	}
	count("system.ntp.servers", len(n.Servers))
	for i, srv := range n.Servers {
		p := at("system.ntp.servers", i)
		v.host(p+".address", srv.Address)
		v.ntpWeight(p+".weight", srv.Weight)
	}
	count("system.ntp.sensors", len(n.Sensors))
	for i, sn := range n.Sensors {
		p := at("system.ntp.sensors", i)
		if !ntpDeviceRE.MatchString(sn.Device) {
			v.fail(p+".device", "%q isn't a sensor device, such as nmea0, or *", sn.Device)
		}
		v.intRange(p+".correction", sn.Correction, -127000000, 127000000)
		if sn.RefID != "" && !ntpRefIDRE.MatchString(sn.RefID) {
			v.fail(p+".refid", "1 to 4 letters or digits")
		}
		if sn.Stratum != 0 {
			v.intRange(p+".stratum", sn.Stratum, 1, 15)
		}
		v.ntpWeight(p+".weight", sn.Weight)
	}
	count("system.ntp.constraints", len(n.Constraints))
	for i, c := range n.Constraints {
		p := at("system.ntp.constraints", i)
		v.ntpConstraintURL(p+".url", c.URL)
		if c.Every && len(c.Addresses) > 0 {
			v.fail(p+".addresses", "a constraint asking every address the name has can't be given addresses")
		}
		if len(c.Addresses) > 8 {
			v.fail(p+".addresses", "at most 8")
		}
		for j, a := range c.Addresses {
			v.addr(at(p+".addresses", j), a, false)
		}
	}
	seenOn := map[string]bool{}
	for i, id := range n.ServeOn {
		p := at("system.ntp.serveOn", i)
		v.unique(p, seenOn, id, "interface")
		f := v.ifaceRef(p, id)
		switch {
		case f == nil:
		case Unmanaged(v.m, AreaNTP):
			v.fail(p, "ntpd is configured by hand; OPF serves no time until it's handed over")
		case f.Role == RoleWAN:
			v.fail(p, "the firewall doesn't serve time to a WAN (%s)", f.Name)
		case f.WireGuard != nil && f.WireGuard.Exit != nil:
			v.fail(p, "%s is a way out through a VPN provider; the firewall doesn't serve time there", f.Name)
		case !NTPEligible(f) && f.Enabled:
			// Off, it's kept, and served again once it's on.
			v.fail(p, "%s gets its address by DHCP; for now time is only served on interfaces with a fixed address", f.Name)
		}
	}
	count("system.ntp.listen", len(n.Listen))
	seen := map[string]bool{}
	for i, l := range n.Listen {
		p := at("system.ntp.listen", i)
		if l.Address != "*" {
			v.addr(p+".address", l.Address, false)
		}
		if l.RTable != 0 {
			v.fail(p+".rtable", "OPF doesn't run ntpd in another routing table")
		}
		v.unique(p+".address", seen, l.Address, "address")
	}
	families := map[bool]bool{}
	for i, q := range n.QueryFrom {
		p := at("system.ntp.queryFrom", i)
		a := v.addr(p, q, false)
		if !a.IsValid() {
			continue
		}
		if families[a.Is4()] {
			v.fail(p, "only one IPv4 and one IPv6 address: ntpd asks from the last of each")
		}
		families[a.Is4()] = true
	}
}

func (v *validator) ntpWeight(path string, w int) {
	if w != 0 {
		v.intRange(path, w, 1, 10)
	}
}

// ntpConstraintURL is an https:// URL without a port, or a host name or
// IP address: what ntpd takes apart as host and path.
func (v *validator) ntpConstraintURL(path, s string) {
	host, rest := s, ""
	if after, ok := strings.CutPrefix(s, "https://"); ok {
		host = after
		if i := strings.IndexByte(after, '/'); i >= 0 {
			host, rest = after[:i], after[i:]
		}
	}
	if rest != "" && !ntpPathRE.MatchString(rest) {
		v.fail(path, "the URL's path can only have letters, digits and URL punctuation")
		return
	}
	if host == "" {
		v.fail(path, "enter a URL like https://www.example.com/, or a host name or address")
		return
	}
	v.host(path, host)
}

// ntpToken is a word of ntpd.conf as its lexer reads it.
type ntpToken struct {
	s       string
	keyword bool
	number  bool
}

// ntpTokens reads a line of ntpd.conf, a backslash-newline already
// joined; a reason when ntpd's lexer would stumble on it, or when it
// has a backslash before any comment, whose escapes OPF doesn't read.
func ntpTokens(line string) ([]ntpToken, string) {
	const unread, escaped = "ntpd can't read it", "OPF doesn't read backslashes in ntpd.conf"
	var toks []ntpToken
	for i := 0; i < len(line); {
		c := line[i]
		switch {
		case c == ' ' || c == '\t':
			i++
		case c == '#':
			return toks, ""
		case c == '\\':
			return nil, escaped
		case c == '"' || c == '\'':
			end := strings.IndexByte(line[i+1:], c)
			if end < 0 {
				return nil, unread
			}
			if strings.Contains(line[i+1:i+1+end], `\`) {
				return nil, escaped
			}
			toks = append(toks, ntpToken{s: line[i+1 : i+1+end]})
			i += end + 2
		default:
			j := i
			for j < len(line) && line[j] != ' ' && line[j] != '\t' && line[j] != '#' {
				if line[j] == '\\' {
					return nil, escaped
				}
				j++
			}
			w := line[i:j]
			switch {
			case ntpNumRE.MatchString(w):
				toks = append(toks, ntpToken{s: w, number: true})
			case ntpLexWord(w):
				toks = append(toks, ntpToken{s: w, keyword: slices.Contains(ntpKeywords, w)})
			default:
				return nil, unread
			}
			i = j
		}
	}
	return toks, ""
}

// ntpLexWord is whether ntpd's lexer reads w, unquoted, as one word:
// one starting with a letter, digit, :, _ or *, then letters, digits
// and punctuation but for ( ) { } < > ! = / # and ,.
func ntpLexWord(w string) bool {
	alnum := func(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' }
	if w == "" || !(alnum(w[0]) || strings.IndexByte(":_*", w[0]) >= 0) {
		return false
	}
	for i := 1; i < len(w); i++ {
		c := w[i]
		punct := c > ' ' && c < 0x7f && !alnum(c)
		if !alnum(c) && (!punct || strings.IndexByte("(){}<>!=/#,", c) >= 0) {
			return false
		}
	}
	return true
}

// ntpStatement is a statement of ntpd.conf taken into the model.
type ntpStatement struct {
	kind string // "servers", "server", "sensor", "constraint", "constraints", "listen", "query"
	srv  NTPServer
	sn   NTPSensor
	c    NTPConstraint
	l    NTPListen
	q    string
}

// parseNTPStatement reads a statement's tokens; false when ntpd
// wouldn't read it.
func parseNTPStatement(t []ntpToken) (ntpStatement, bool) {
	kw := func(i int, k string) bool { return i < len(t) && t[i].keyword && t[i].s == k }
	str := func(i int) bool { return i < len(t) && !t[i].keyword && !t[i].number }
	num := func(i int) (int, bool) {
		if i >= len(t) || !t[i].number {
			return 0, false
		}
		n, err := strconv.Atoi(t[i].s)
		return n, err == nil
	}
	var st ntpStatement
	if len(t) == 0 || !t[0].keyword {
		return st, false
	}
	st.kind = t[0].s
	switch st.kind {
	case "listen":
		if !kw(1, "on") || !str(2) {
			return st, false
		}
		st.l.Address = t[2].s
		for i := 3; i < len(t); i += 2 {
			n, ok := num(i + 1)
			if !kw(i, "rtable") || !ok {
				return st, false
			}
			st.l.RTable = n
		}
		return st, true
	case "query":
		if !kw(1, "from") || !str(2) || len(t) != 3 {
			return st, false
		}
		st.q = t[2].s
		return st, true
	case "server", "servers":
		if !str(1) {
			return st, false
		}
		st.srv = NTPServer{Address: t[1].s, One: st.kind == "server"}
		for i := 2; i < len(t); i++ {
			switch {
			case kw(i, "trusted"):
				st.srv.Trusted = true
			case kw(i, "weight"):
				n, ok := num(i + 1)
				if !ok {
					return st, false
				}
				st.srv.Weight = n
				i++
			default:
				return st, false
			}
		}
		return st, true
	case "sensor":
		if !str(1) {
			return st, false
		}
		st.sn.Device = t[1].s
		for i := 2; i < len(t); i++ {
			var n *int
			switch {
			case kw(i, "trusted"):
				st.sn.Trusted = true
				continue
			case kw(i, "refid") && str(i+1):
				st.sn.RefID = t[i+1].s
				i++
				continue
			case kw(i, "correction"):
				n = &st.sn.Correction
			case kw(i, "stratum"):
				n = &st.sn.Stratum
			case kw(i, "weight"):
				n = &st.sn.Weight
			default:
				return st, false
			}
			v, ok := num(i + 1)
			if !ok {
				return st, false
			}
			*n = v
			i++
		}
		return st, true
	case "constraint", "constraints":
		if !kw(1, "from") || !str(2) {
			return st, false
		}
		st.c = NTPConstraint{URL: t[2].s, Every: st.kind == "constraints"}
		for i := 3; i < len(t); i++ {
			if st.c.Every || !str(i) {
				return st, false
			}
			st.c.Addresses = append(st.c.Addresses, t[i].s)
		}
		return st, true
	}
	return st, false
}

// importNTP reads ntpd.conf into the model.
func importNTP(m *Model, src ImportSources) (ImportArea, []ImportNote) {
	const file = NTPdConfPath
	content, ok := src.Files[file]
	a := ImportArea{Running: true, Exact: true} // ntpd runs by default
	var notes []ImportNote
	if !ok {
		// ntpd won't start without its file; OPF's starts it.
		m.System.NTPServers = []string{"pool.ntp.org"}
		a.Summary = "no ntpd.conf, so ntpd doesn't run"
		a.Exact = false
		return a, notes
	}
	n := &NTPSettings{}
	m.System.NTP = n
	lost := func(line int, text, why string) {
		a.Exact = false
		notes = append(notes, ImportNote{File: file, Line: line, Kind: NoteLost, Text: text, Message: why})
	}
	sawServer, comments := false, false
	lines := strings.Split(content, "\n")
	for i := 0; i < len(lines); i++ {
		start, line := i, lines[i]
		// A line ending in a backslash goes on onto the next.
		for strings.HasSuffix(line, `\`) && i+1 < len(lines) {
			i++
			line = line[:len(line)-1] + lines[i]
		}
		text := strings.TrimSpace(line)
		if text == "" {
			continue
		}
		toks, why := ntpTokens(line)
		if why != "" {
			lost(start+1, text, why)
			continue
		}
		if len(toks) == 0 {
			comments = true
			continue
		}
		if strings.Contains(line, "#") {
			comments = true
		}
		st, ok := parseNTPStatement(toks)
		if !ok {
			lost(start+1, text, "ntpd can't read it")
			continue
		}
		// Each statement must be one the model holds valid.
		before := *n
		servers := m.System.NTPServers
		what := ""
		switch st.kind {
		case "listen":
			n.Listen = append(n.Listen, st.l)
			what = "an address ntpd serves time on"
		case "query":
			if sawServer {
				lost(start+1, text, "it applies only to the servers after it, and OPF writes it before them all")
				continue
			}
			// The last of each family is the one that counts.
			q, err := netip.ParseAddr(st.q)
			if err == nil {
				n.QueryFrom = slices.DeleteFunc(n.QueryFrom, func(s string) bool {
					p, err := netip.ParseAddr(s)
					return err == nil && p.Is4() == q.Is4()
				})
			}
			n.QueryFrom = append(n.QueryFrom, st.q)
			what = "the address ntpd asks the servers from"
		case "server", "servers":
			sawServer = true
			if st.srv == (NTPServer{Address: st.srv.Address}) {
				m.System.NTPServers = append(m.System.NTPServers, st.srv.Address)
			} else {
				n.Servers = append(n.Servers, st.srv)
			}
			what = "a time server"
		case "sensor":
			n.Sensors = append(n.Sensors, st.sn)
			what = "a time sensor"
		case "constraint", "constraints":
			n.Constraints = append(n.Constraints, st.c)
			what = "a constraint on the servers' time"
		}
		v := &validator{m: m}
		v.ntp()
		if len(v.errs) > 0 {
			*n = before
			m.System.NTPServers = servers
			lost(start+1, text, "OPF can't write it: "+v.errs[0].Message)
			continue
		}
		notes = append(notes, ImportNote{File: file, Line: start + 1, Kind: NoteModel, Text: text, Message: what})
	}
	if comments {
		notes = append(notes, ImportNote{File: file, Kind: NoteLost, Message: "its comments aren't kept"})
	}
	if n.empty() {
		m.System.NTP = nil
	}
	if ntpSources(m.System) == 0 {
		// ntpd runs, syncing to nothing; OPF needs a source.
		m.System.NTPServers = []string{"pool.ntp.org"}
		a.Exact = false
		notes = append(notes, ImportNote{File: file, Kind: NoteLost, Message: "it has no time servers; OPF adds pool.ntp.org"})
	}
	sources := len(m.System.NTPServers) + len(n.Servers)
	a.Summary = fmt.Sprintf("%d time servers", sources)
	if sources == 1 {
		a.Summary = "1 time server"
	}
	if len(n.Sensors) > 0 {
		a.Summary += fmt.Sprintf(", %d sensors", len(n.Sensors))
	}
	return a, notes
}

func (n *NTPSettings) empty() bool {
	return len(n.Servers)+len(n.Sensors)+len(n.Constraints)+len(n.Listen)+len(n.QueryFrom) == 0
}

// NTPKeywords are ntpd.conf's keywords, for the conformance suite to
// compare with ntpd's parse.y.
func NTPKeywords() []string { return slices.Clone(ntpKeywords) }
