package sysinfo

import (
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// PfInfo is `pfctl -v -s info`: whether pf is on, the state table, and
// traffic on the statistics interface (set loginterface).
type PfInfo struct {
	Enabled bool `json:"enabled"`
	// EnabledFor is how long pf has been enabled, in seconds.
	EnabledFor int64  `json:"enabledFor,omitempty"`
	Debug      string `json:"debug,omitempty"`
	States     uint64 `json:"states"`
	HalfOpen   uint64 `json:"halfOpenTcp"`
	// Counters are the "Counters" and "Limit Counters" sections by name
	// (match, state-mismatch, synfloods detected...): totals since pf
	// was enabled.
	Counters map[string]uint64 `json:"counters"`
	// Iface is the statistics interface's traffic, when one is set.
	Iface *PfIfaceStats `json:"iface,omitempty"`
}

// PfIfaceStats is the "Interface Stats for" section, IPv4 and IPv6
// added together.
type PfIfaceStats struct {
	Name              string `json:"name"`
	BytesIn           uint64 `json:"bytesIn"`
	BytesOut          uint64 `json:"bytesOut"`
	PacketsInPassed   uint64 `json:"packetsInPassed"`
	PacketsInBlocked  uint64 `json:"packetsInBlocked"`
	PacketsOutPassed  uint64 `json:"packetsOutPassed"`
	PacketsOutBlocked uint64 `json:"packetsOutBlocked"`
}

// ParsePfInfo reads `pfctl -s info` or `pfctl -v -s info`, following
// pfctl's print_status: a Status line, then sections whose rows are a
// name, a total and sometimes a rate, and names can have spaces, so
// the numbers are read from the right.
func ParsePfInfo(out string) (PfInfo, bool) {
	p := PfInfo{Counters: map[string]uint64{}}
	found := false
	section := ""
	sub := "" // Packets In / Packets Out, inside Interface Stats
	for _, l := range lines(out) {
		if strings.TrimSpace(l) == "" {
			continue
		}
		if rest, ok := strings.CutPrefix(l, "Status: "); ok {
			found = true
			f := strings.Fields(rest)
			p.Enabled = len(f) > 0 && f[0] == "Enabled"
			// Enabled for 23 days 05:12:40   Debug: err
			for i := 0; i+1 < len(f); i++ {
				if f[i+1] == "days" {
					if d, err := strconv.ParseInt(f[i], 10, 64); err == nil {
						p.EnabledFor += d * 86400
					}
				}
				if f[i] == "Debug:" {
					p.Debug = f[i+1]
				}
			}
			for _, x := range f {
				if hms := parseHMS(x); hms >= 0 && strings.Count(x, ":") == 2 {
					p.EnabledFor += hms
				}
			}
			continue
		}
		if l[0] != ' ' {
			section, sub = l, ""
			if name, ok := strings.CutPrefix(l, "Interface Stats for "); ok {
				if f := strings.Fields(name); len(f) > 0 {
					p.Iface = &PfIfaceStats{Name: f[0]}
				}
			}
			continue
		}
		name, nums := splitRow(l)
		switch {
		case strings.HasPrefix(section, "Interface Stats for ") && p.Iface != nil:
			if len(nums) == 0 {
				sub = name // "Packets In", "Packets Out"
				continue
			}
			var sum uint64
			for _, n := range nums {
				sum += n
			}
			switch name {
			case "Bytes In":
				p.Iface.BytesIn = sum
			case "Bytes Out":
				p.Iface.BytesOut = sum
			case "Passed":
				if sub == "Packets In" {
					p.Iface.PacketsInPassed = sum
				} else if sub == "Packets Out" {
					p.Iface.PacketsOutPassed = sum
				}
			case "Blocked":
				if sub == "Packets In" {
					p.Iface.PacketsInBlocked = sum
				} else if sub == "Packets Out" {
					p.Iface.PacketsOutBlocked = sum
				}
			}
		case strings.HasPrefix(section, "State Table") && len(nums) > 0:
			switch name {
			case "current entries":
				p.States = nums[0]
			case "half-open tcp":
				p.HalfOpen = nums[0]
			}
		case (section == "Counters" || section == "Limit Counters") && len(nums) > 0:
			p.Counters[name] = nums[0]
		}
	}
	return p, found
}

// splitRow splits "  state-mismatch   207   0.0/s" into its name and
// the whole numbers after it; a rate ("0.0/s") ends the row.
func splitRow(l string) (string, []uint64) {
	f := strings.Fields(l)
	end := len(f)
	for end > 0 && (strings.HasSuffix(f[end-1], "/s") || f[end-1] == "states") {
		end--
	}
	var nums []uint64
	i := end
	for i > 0 {
		n, err := strconv.ParseUint(f[i-1], 10, 64)
		if err != nil {
			break
		}
		nums = append([]uint64{n}, nums...)
		i--
	}
	return strings.Join(f[:i], " "), nums
}

// parseHMS reads hh:mm:ss (hours unbounded) as seconds, or -1.
func parseHMS(s string) int64 {
	p := strings.Split(s, ":")
	if len(p) != 3 {
		return -1
	}
	var n [3]int64
	for i, x := range p {
		v, err := strconv.ParseInt(x, 10, 64)
		if err != nil || v < 0 || (i > 0 && v > 59) {
			return -1
		}
		n[i] = v
	}
	return n[0]*3600 + n[1]*60 + n[2]
}

// ParsePfMemory reads `pfctl -s memory`: each pool's hard limit.
func ParsePfMemory(out string) map[string]uint64 {
	m := map[string]uint64{}
	for _, l := range lines(out) {
		f := strings.Fields(l)
		if len(f) == 4 && f[1] == "hard" && f[2] == "limit" {
			if n, err := strconv.ParseUint(f[3], 10, 64); err == nil {
				m[f[0]] = n
			}
		}
	}
	return m
}

// PfState is one entry of pf's state table, as `pfctl -vv -s states`
// prints it (pfctl's print_state).
type PfState struct {
	// ID and CreatorID identify it to pfctl -k id.
	ID        string `json:"id"`
	CreatorID string `json:"creatorId"`
	// Iface is the interface it's bound to, or "all" (floating).
	Iface string `json:"iface"`
	Proto string `json:"proto"`
	// Direction is "in" or "out": the direction of the packet that
	// created it, on the interface it was created on.
	Direction string `json:"direction"`
	// Source and Destination are the connection's ends as the device
	// that opened it sees them: for an outgoing state through NAT, the
	// source is the inside host; for an incoming one through a port
	// forward, the destination is the inside host.
	Source      string `json:"source"`
	Destination string `json:"destination"`
	// Translated is the address on the other side of the translation,
	// if there is one: the NAT address an outgoing connection leaves
	// with, or the address an incoming one was sent to before a port
	// forward redirected it.
	Translated string `json:"translated,omitempty"`
	State      string `json:"state"` // ESTABLISHED:ESTABLISHED, MULTIPLE:SINGLE...
	AgeSec     int64  `json:"ageSec"`
	ExpiresSec int64  `json:"expiresSec"`
	Packets    uint64 `json:"packets"`
	Bytes      uint64 `json:"bytes"`
	// Rule is the number of the rule that created it (pfctl -vv -s
	// rules' @N), or -1.
	Rule int `json:"rule"`
}

// ParsePfStates reads `pfctl -vv -s states`. Each state is a line
// starting at the margin, "<iface> <proto> <addresses> <state>", then
// indented lines with its windows (TCP), its age and counters, and its
// id. At most max states are returned; truncated says there were more.
func ParsePfStates(out string, max int) (states []PfState, truncated bool) {
	var cur *PfState
	for _, l := range lines(out) {
		if l == "" {
			continue
		}
		if l[0] != ' ' && l[0] != '\t' {
			s, ok := parseStateLine(l)
			if !ok {
				cur = nil
				continue
			}
			if len(states) >= max {
				truncated = true
				cur = nil
				continue
			}
			states = append(states, s)
			cur = &states[len(states)-1]
			continue
		}
		if cur == nil {
			continue
		}
		t := strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(t, "age "):
			parseStateCounters(cur, t)
		case strings.HasPrefix(t, "id: "):
			f := strings.Fields(t)
			for i := 0; i+1 < len(f); i++ {
				switch f[i] {
				case "id:":
					if isHex(f[i+1], 16) {
						cur.ID = f[i+1]
					}
				case "creatorid:":
					if isHex(f[i+1], 8) {
						cur.CreatorID = f[i+1]
					}
				}
			}
		}
	}
	// A state without an id can't be killed or told apart; leave it
	// out rather than show something the page can't act on.
	kept := states[:0]
	for _, s := range states {
		if s.ID != "" && s.CreatorID != "" {
			kept = append(kept, s)
		}
	}
	return kept, truncated
}

func isHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

// parseStateLine reads "all tcp 203.0.113.24:50001 (192.168.1.112:52344)
// -> 140.82.112.4:443 ESTABLISHED:ESTABLISHED". print_state writes an
// outgoing state as "src -> dst" and an incoming one as "dst <- src",
// each host as it is on the wire for outgoing states (with the address
// inside the firewall in parentheses when NAT changed it) and as it is
// inside for incoming ones (with the address on the wire in
// parentheses).
func parseStateLine(l string) (PfState, bool) {
	f := strings.Fields(l)
	if len(f) < 6 {
		return PfState{}, false
	}
	s := PfState{Iface: f[0], Proto: f[1], Rule: -1}
	arrow := -1
	for i := 2; i < len(f); i++ {
		if f[i] == "->" || f[i] == "<-" {
			arrow = i
			break
		}
	}
	if arrow < 3 || arrow+1 >= len(f) {
		return PfState{}, false
	}
	left := f[2:arrow]
	right := f[arrow+1:]
	// The state names are the last field.
	s.State = right[len(right)-1]
	right = right[:len(right)-1]
	lMain, lParen, ok1 := hostAndParen(left)
	rMain, rParen, ok2 := hostAndParen(right)
	if !ok1 || !ok2 {
		return PfState{}, false
	}
	if f[arrow] == "->" {
		s.Direction = "out"
		s.Source, s.Destination = lMain, rMain
		if lParen != "" {
			s.Source, s.Translated = lParen, lMain
		}
		if rParen != "" {
			s.Destination = rParen
		}
	} else {
		s.Direction = "in"
		s.Destination, s.Source = lMain, rMain
		if lParen != "" {
			s.Translated = lParen
		}
	}
	return s, true
}

// hostAndParen reads "host" or "host (host)".
func hostAndParen(f []string) (main, paren string, ok bool) {
	switch len(f) {
	case 1:
		main = f[0]
	case 2:
		main = f[0]
		p, ok1 := strings.CutPrefix(f[1], "(")
		p, ok2 := strings.CutSuffix(p, ")")
		if !ok1 || !ok2 {
			return "", "", false
		}
		paren = p
	default:
		return "", "", false
	}
	if main, ok = normalizeHost(main); !ok {
		return "", "", false
	}
	if paren != "" {
		if paren, ok = normalizeHost(paren); !ok {
			return "", "", false
		}
	}
	return main, paren, true
}

// normalizeHost reads print_host's "1.2.3.4:443", "1.2.3.4",
// "2001:db8::1[443]" or "2001:db8::1", and returns the address with its
// port the way people write it: 1.2.3.4:443, [2001:db8::1]:443.
func normalizeHost(h string) (string, bool) {
	if i := strings.LastIndexByte(h, '['); i > 0 && strings.HasSuffix(h, "]") {
		a, err := netip.ParseAddr(h[:i])
		port, err2 := strconv.ParseUint(h[i+1:len(h)-1], 10, 16)
		if err != nil || err2 != nil {
			return "", false
		}
		return netip.AddrPortFrom(a, uint16(port)).String(), true
	}
	if a, err := netip.ParseAddr(h); err == nil {
		return a.String(), true
	}
	if ap, err := netip.ParseAddrPort(h); err == nil && ap.Addr().Is4() {
		return ap.String(), true
	}
	return "", false
}

// parseStateCounters reads "age 00:12:34, expires in 23:59:58,
// 1234:5678 pkts, 123456:7890123 bytes, rule 7[, ...]".
func parseStateCounters(s *PfState, t string) {
	for _, part := range strings.Split(t, ", ") {
		f := strings.Fields(part)
		switch {
		case len(f) == 2 && f[0] == "age":
			s.AgeSec = max(parseHMS(f[1]), 0)
		case len(f) == 3 && f[0] == "expires" && f[1] == "in":
			s.ExpiresSec = max(parseHMS(f[2]), 0)
		case len(f) == 2 && (f[1] == "pkts" || f[1] == "bytes"):
			a, b, ok := strings.Cut(f[0], ":")
			x, err1 := strconv.ParseUint(a, 10, 64)
			y, err2 := strconv.ParseUint(b, 10, 64)
			if !ok || err1 != nil || err2 != nil {
				continue
			}
			if f[1] == "pkts" {
				s.Packets = x + y
			} else {
				s.Bytes = x + y
			}
		case len(f) == 2 && f[0] == "rule":
			if n, err := strconv.Atoi(f[1]); err == nil && n >= 0 {
				s.Rule = n
			}
		}
	}
}

// PfRule is one loaded rule's counters, from `pfctl -vv -s rules`.
type PfRule struct {
	Number int `json:"number"`
	// Label is the rule's label, if it has one.
	Label       string `json:"label,omitempty"`
	Evaluations uint64 `json:"evaluations"`
	Packets     uint64 `json:"packets"`
	Bytes       uint64 `json:"bytes"`
	// States is how many states the rule has now.
	States uint64 `json:"states"`
}

// ParsePfRules reads `pfctl -vv -s rules`: "@N <rule>" lines, each
// followed by "[ Evaluations: ... Packets: ... Bytes: ... States: ... ]".
func ParsePfRules(out string) []PfRule {
	var rules []PfRule
	var cur *PfRule
	for _, l := range lines(out) {
		if rest, ok := strings.CutPrefix(l, "@"); ok {
			num, text, _ := strings.Cut(rest, " ")
			n, err := strconv.Atoi(num)
			if err != nil || n < 0 {
				cur = nil
				continue
			}
			rules = append(rules, PfRule{Number: n, Label: ruleLabel(text)})
			cur = &rules[len(rules)-1]
			continue
		}
		t := strings.TrimSpace(l)
		if cur == nil || !strings.HasPrefix(t, "[ Evaluations:") {
			continue
		}
		f := strings.Fields(strings.Trim(t, "[] "))
		for i := 0; i+1 < len(f); i++ {
			n, err := strconv.ParseUint(f[i+1], 10, 64)
			if err != nil {
				continue
			}
			switch f[i] {
			case "Evaluations:":
				cur.Evaluations = n
			case "Packets:":
				cur.Packets = n
			case "Bytes:":
				cur.Bytes = n
			case "States:":
				cur.States = n
			}
		}
	}
	return rules
}

// ruleLabel finds `label "..."` in a rule as pfctl prints it. pfctl
// writes labels without escapes, and OPF's never contain quotes.
func ruleLabel(text string) string {
	_, rest, ok := strings.Cut(text, ` label "`)
	if !ok {
		return ""
	}
	l, _, ok := strings.Cut(rest, `"`)
	if !ok {
		return ""
	}
	return l
}

// PfLogEntry is one packet pf logged, from `tcpdump -n -e -ttt -r
// /var/log/pflog`.
type PfLogEntry struct {
	Time time.Time `json:"time"`
	// Rule is the number of the rule that logged it, and Anchor the
	// anchor it's in, if any (the rule is then numbered in the anchor).
	// -1 is pf's default rule ("rule def"): no rule, pf itself, such as
	// dropping a packet with IP options.
	Rule   int    `json:"rule"`
	Anchor string `json:"anchor,omitempty"`
	Reason string `json:"reason"` // match, short, bad-offset...
	Action string `json:"action"` // pass, block, match...
	// Direction is "in" or "out"; Iface the interface.
	Direction   string `json:"direction"`
	Iface       string `json:"iface"`
	Proto       string `json:"proto,omitempty"` // tcp, udp, icmp; empty if unknown
	Source      string `json:"source,omitempty"`
	Destination string `json:"destination,omitempty"`
	// Info is the rest of tcpdump's line (TCP flags, the ICMP type).
	Info string `json:"info,omitempty"`
}

// ParsePflog reads tcpdump's pflog lines, keeping the last max. The
// timestamp (-ttt) has no year: it's taken to be the latest one that
// isn't after now. Lines that aren't pflog entries are skipped.
func ParsePflog(out string, now time.Time, max int) []PfLogEntry {
	var es []PfLogEntry
	for _, l := range lines(out) {
		e, ok := parsePflogLine(l, now)
		if !ok {
			continue
		}
		es = append(es, e)
		if len(es) > 2*max {
			es = append(es[:0], es[len(es)-max:]...)
		}
	}
	if len(es) > max {
		es = es[len(es)-max:]
	}
	return es
}

// parsePflogLine reads "Sep 29 16:20:01.123456 rule 3/(match) block in
// on em0: 198.51.100.23.51234 > 203.0.113.24.22: S 1:1(0) win 1024".
func parsePflogLine(l string, now time.Time) (PfLogEntry, bool) {
	f := strings.SplitN(l, " ", 5)
	if len(f) < 5 || f[3] != "rule" {
		// Days are space-padded: "Sep  1 ..." splits into an empty field.
		f = strings.Fields(l)
		if len(f) < 5 || f[3] != "rule" {
			return PfLogEntry{}, false
		}
		f = []string{f[0], f[1], f[2], f[3], strings.Join(f[4:], " ")}
	}
	var e PfLogEntry
	t, err := time.ParseInLocation("Jan 2 15:04:05.000000", f[0]+" "+f[1]+" "+f[2], now.Location())
	if err != nil {
		return e, false
	}
	e.Time = withYear(t, now)

	rest := f[4]
	// 3/(match) or 2.anchor.1/(match)
	ruleTok, rest, ok := strings.Cut(rest, " ")
	if !ok {
		return e, false
	}
	num, reason, ok := strings.Cut(ruleTok, "/")
	if !ok || !strings.HasPrefix(reason, "(") || !strings.HasSuffix(reason, ")") {
		return e, false
	}
	e.Reason = reason[1 : len(reason)-1]
	if parts := strings.Split(num, "."); len(parts) == 3 {
		e.Anchor, num = parts[1], parts[2]
	}
	if num == "def" {
		e.Rule = -1
	} else if e.Rule, err = strconv.Atoi(num); err != nil || e.Rule < 0 {
		return e, false
	}
	// block in on em0: <packet>
	head, pkt, ok := strings.Cut(rest, ": ")
	if !ok {
		return e, false
	}
	h := strings.Fields(head)
	if len(h) != 4 || h[2] != "on" || (h[1] != "in" && h[1] != "out") {
		return e, false
	}
	e.Action, e.Direction, e.Iface = h[0], h[1], h[3]
	parsePacket(&e, pkt)
	return e, true
}

// withYear gives a year-less time the latest year that doesn't put it
// more than a day after now (logs can't be from the future, give or
// take clock changes).
func withYear(t, now time.Time) time.Time {
	y := time.Date(now.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), now.Location())
	if y.After(now.Add(24 * time.Hour)) {
		y = y.AddDate(-1, 0, 0)
	}
	return y
}

// parsePacket reads tcpdump's "src.port > dst.port: ..." or "src >
// dst: icmp: ...". tcpdump separates a port from its address with a
// dot, for IPv6 too.
func parsePacket(e *PfLogEntry, pkt string) {
	src, rest, ok := strings.Cut(pkt, " > ")
	if !ok {
		e.Info = pkt
		return
	}
	dst, info, _ := strings.Cut(rest, ": ")
	sAddr, sPort := splitDotPort(src)
	dAddr, dPort := splitDotPort(dst)
	if !sAddr.IsValid() || !dAddr.IsValid() {
		e.Info = pkt
		return
	}
	e.Info = info
	f := strings.Fields(info)
	switch {
	case len(f) > 0 && (f[0] == "icmp:" || f[0] == "icmp6:"):
		e.Proto = "icmp"
	case len(f) > 0 && f[0] == "udp":
		e.Proto = "udp"
	case len(f) > 0 && isTCPFlags(f[0]) && sPort >= 0:
		e.Proto = "tcp"
	case sPort >= 0:
		// A port and a decoded payload (DNS, NTP...): UDP more often
		// than not, but not certain, so it's left unknown.
	}
	e.Source = hostPort(sAddr, sPort)
	e.Destination = hostPort(dAddr, dPort)
}

func isTCPFlags(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !strings.ContainsRune("SFPRUEW.", r) {
			return false
		}
	}
	return true
}

// splitDotPort reads "1.2.3.4.443" or "2001:db8::1.443" (port -1 when
// there's none: "1.2.3.4").
func splitDotPort(s string) (netip.Addr, int) {
	if a, err := netip.ParseAddr(s); err == nil {
		return a, -1
	}
	i := strings.LastIndexByte(s, '.')
	if i < 0 {
		return netip.Addr{}, -1
	}
	a, err := netip.ParseAddr(s[:i])
	p, err2 := strconv.ParseUint(s[i+1:], 10, 16)
	if err != nil || err2 != nil {
		return netip.Addr{}, -1
	}
	return a, int(p)
}

func hostPort(a netip.Addr, port int) string {
	if port < 0 {
		return a.String()
	}
	return netip.AddrPortFrom(a, uint16(port)).String()
}
