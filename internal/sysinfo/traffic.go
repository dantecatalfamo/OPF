package sysinfo

import (
	"strconv"
	"strings"
)

// TableCounters are an address's counters in a pf table with counters:
// what it sent (In) and received (Out), passed or matched, not blocked.
type TableCounters struct {
	SentPackets, SentBytes         uint64
	ReceivedPackets, ReceivedBytes uint64
}

// ParsePfTableCounters reads `pfctl -t T -T show -v`: each address's
// counters, by address.
//
//	   192.168.50.2
//		Cleared:     Wed Oct  7 15:44:41 2026
//		In/Match:    [ Packets: 2957               Bytes: 4348092            ]
func ParsePfTableCounters(out string) map[string]TableCounters {
	res := map[string]TableCounters{}
	addr := ""
	for _, l := range lines(out) {
		if !strings.HasPrefix(l, "\t") {
			addr = strings.TrimSpace(l)
			if addr != "" {
				res[addr] = TableCounters{}
			}
			continue
		}
		name, rest, ok := strings.Cut(strings.TrimSpace(l), ":")
		if !ok || addr == "" {
			continue
		}
		dir, kind, ok := strings.Cut(name, "/")
		if !ok || kind == "Block" {
			continue
		}
		f := strings.Fields(strings.Trim(strings.TrimSpace(rest), "[]"))
		// Packets: N Bytes: N
		if len(f) < 4 || f[0] != "Packets:" || f[2] != "Bytes:" {
			continue
		}
		p, err1 := strconv.ParseUint(f[1], 10, 64)
		b, err2 := strconv.ParseUint(f[3], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		c := res[addr]
		switch dir {
		case "In":
			c.SentPackets += p
			c.SentBytes += b
		case "Out":
			c.ReceivedPackets += p
			c.ReceivedBytes += b
		}
		res[addr] = c
	}
	return res
}

// LabelCounters are a label's counters from `pfctl -s labels`, every
// rule with it together; a ruleset reload starts them again. In is the
// way its connections were opened, Out their replies.
type LabelCounters struct {
	Packets, Bytes       uint64
	InPackets, InBytes   uint64
	OutPackets, OutBytes uint64
}

// ParsePfLabels reads `pfctl -s labels`: label evaluations packets bytes
// in-packets in-bytes out-packets out-bytes states, after the source
// limiters' header lines 7.9 prints first.
func ParsePfLabels(out string) map[string]LabelCounters {
	res := map[string]LabelCounters{}
	for _, l := range lines(out) {
		f := strings.Fields(l)
		if len(f) != 9 {
			continue
		}
		var n [6]uint64
		ok := true
		for i := range n {
			v, err := strconv.ParseUint(f[2+i], 10, 64)
			ok = ok && err == nil
			n[i] = v
		}
		if !ok {
			continue
		}
		c := res[f[0]]
		c.Packets += n[0]
		c.Bytes += n[1]
		c.InPackets += n[2]
		c.InBytes += n[3]
		c.OutPackets += n[4]
		c.OutBytes += n[5]
		res[f[0]] = c
	}
	return res
}
