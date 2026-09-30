package main

import (
	"fmt"
	"hash/fnv"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/dantecatalfamo/OPF/internal/pf"
)

// mockPf answers pfctl and tcpdump for the mock, in the formats in
// internal/sysinfo/testdata. The loaded rules are the mock's own
// generated pf.conf, so labels, numbers and counters match the model;
// connections are made up for the sample's DHCP clients, and ending one
// takes it out of the table.
type mockPf struct {
	mu     sync.Mutex
	killed map[string]bool
}

// mockRule is a loaded rule: its number, text and label.
type mockRule struct {
	n     int
	text  string
	label string
}

// mockRules are the rule lines of the model's ruleset, numbered the
// way pfctl would (ignoring that it expands lists into several rules).
func mockRules(m *pf.Model) []mockRule {
	var rs []mockRule
	for _, l := range pf.GeneratePfRuleset(m) {
		t := strings.TrimSpace(l.Text)
		f := strings.Fields(t)
		if len(f) == 0 || (f[0] != "pass" && f[0] != "block" && f[0] != "match" && f[0] != "antispoof") {
			continue
		}
		lbl := ""
		if _, rest, ok := strings.Cut(t, ` label "`); ok {
			lbl, _, _ = strings.Cut(rest, `"`)
		}
		rs = append(rs, mockRule{n: len(rs), text: t, label: lbl})
	}
	return rs
}

func seed(s string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(s))
	return h.Sum32()
}

func (p *mockPf) rules(m *pf.Model, t float64) string {
	var b strings.Builder
	for _, r := range mockRules(m) {
		k := float64(seed(r.label+r.text)%1000) / 1000
		evals := int64(wander(r.text+" e", 40*(1-k), t)) + int64(20411*(1-k))
		pkts := int64(wander(r.text+" p", 400*k*k, t))
		states := 0
		if strings.HasPrefix(r.text, "pass") {
			states = int(seed(r.text) % 40)
		}
		fmt.Fprintf(&b, "@%d %s\n  [ Evaluations: %-8d  Packets: %-10d  Bytes: %-10d  States: %-6d]\n  [ Inserted: uid 0 pid 11234 State Creations: %-6d]\n",
			r.n, r.text, evals, pkts, pkts*700, states, states*9)
	}
	return b.String()
}

// mockConn is a made-up connection from a client out to the internet.
type mockConn struct {
	id           int
	client       string
	port, remote string
	proto        string
	age          int64
}

var mockRemotes = []string{"140.82.112.4:443", "151.101.1.140:443", "9.9.9.9:853", "17.253.144.10:443", "52.94.236.248:443", "142.250.72.110:443", "104.16.132.229:443", "93.184.215.14:80"}

func (p *mockPf) conns(m *pf.Model, now time.Time) []mockConn {
	var clients []string
	for _, s := range m.DHCP {
		for _, r := range s.Reservations {
			clients = append(clients, r.IP)
		}
	}
	for _, c := range []string{"192.168.1.112", "192.168.1.118", "192.168.1.131", "192.168.20.101", "192.168.20.102"} {
		clients = append(clients, c)
	}
	// Connections last a few minutes and are replaced, so the table
	// changes as the page is watched.
	slot := now.Unix() / 30
	var cs []mockConn
	for i := range 36 {
		gen := slot - int64(i%6)
		h := seed(fmt.Sprint(i, gen))
		c := mockConn{
			id:     i*1000 + int(gen%1000),
			client: clients[int(h)%len(clients)],
			port:   fmt.Sprint(49152 + h%16000),
			remote: mockRemotes[int(h>>8)%len(mockRemotes)],
			proto:  "tcp",
			age:    now.Unix() - gen*30 + int64(h%30),
		}
		if h%7 == 0 {
			c.proto, c.remote = "udp", "9.9.9.9:53"
		}
		cs = append(cs, c)
	}
	return cs
}

// ruleFor is the number of the first rule with a label of kind, on
// iface's rules when iface is set, or fallback.
func ruleFor(rs []mockRule, kind, iface string, fallback int) int {
	for _, r := range rs {
		k, _, ok := pf.ParseLabel(r.label)
		if ok && k == kind && strings.HasPrefix(r.text, "pass") && (iface == "" || strings.Contains(r.text, "on $"+iface+" ")) {
			return r.n
		}
	}
	return fallback
}

func (p *mockPf) states(m *pf.Model, now time.Time) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	rs := mockRules(m)
	var b strings.Builder
	for _, c := range p.conns(m, now) {
		iface := "lan"
		if strings.HasPrefix(c.client, "192.168.20.") {
			iface = "iot"
		}
		for dir, arrow := range []string{"<-", "->"} {
			id := fmt.Sprintf("6505b0d4%08x", c.id*2+dir)
			if p.killed[id] {
				continue
			}
			src := c.client + ":" + c.port
			state := "ESTABLISHED:ESTABLISHED"
			if c.proto == "udp" {
				state = "MULTIPLE:SINGLE"
			}
			rule := ruleFor(rs, pf.LabelRule, iface, 0)
			if arrow == "<-" {
				fmt.Fprintf(&b, "all %s %s <- %s       %s\n", c.proto, c.remote, src, state)
			} else {
				fmt.Fprintf(&b, "all %s 203.0.113.24:%d (%s) -> %s       %s\n", c.proto, 50000+c.id%15000, src, c.remote, state)
				rule = ruleFor(rs, pf.LabelBuiltin, "", 0)
			}
			if c.proto == "tcp" {
				b.WriteString("   [3456789012 + 131328] wscale 7  [1234567890 + 132096] wscale 6\n")
			}
			pk := c.age*3 + int64(seed(id)%500)
			fmt.Fprintf(&b, "   age %s, expires in 23:59:58, %d:%d pkts, %d:%d bytes, rule %d\n", hms(c.age), pk, pk*2, pk*90, pk*1400, rule)
			fmt.Fprintf(&b, "   id: %s creatorid: 1c9d3f2a\n", id)
		}
	}
	return b.String()
}

func hms(s int64) string { return fmt.Sprintf("%02d:%02d:%02d", s/3600, s/60%60, s%60) }

func (p *mockPf) kill(arg string) (string, error) {
	id, _, ok := strings.Cut(arg, "/")
	if !ok {
		return "", fmt.Errorf("mock pfctl: want id/creatorid")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.killed == nil {
		p.killed = map[string]bool{}
	}
	p.killed[id] = true
	return "killed 1 states\n", nil
}

func (p *mockPf) info(m *pf.Model, t float64, now time.Time) string {
	states := strings.Count(p.states(m, now), "\n   id: ")
	wan := "em0"
	for _, i := range m.Interfaces {
		if i.Role == pf.RoleWAN {
			wan = i.Device
		}
	}
	up := int64(t) + 23*86400 + 5*3600
	blocked := int64(wander("blocked", 2.5, t)) + 22124
	return fmt.Sprintf(`Status: Enabled for %d days %s             Debug: err

Hostid:   0x5bd46c7e
Checksum: 0x2b4f1d0e9a8c7b6a5f4e3d2c1b0a9988

Interface Stats for %-6s               IPv4             IPv6
  Bytes In                     %12d                0
  Bytes Out                    %12d                0
  Packets In
    Passed                     %12d                0
    Blocked                    %12d                0
  Packets Out
    Passed                     %12d                0
    Blocked                               0                0

State Table                          Total             Rate
  current entries                  %6d
  half-open tcp                          2
  searches                      %10d          646.3/s
Counters
  match                           %8d           20.5/s
  state-mismatch                       207            0.0/s
`, up/86400, hms(up%86400), wan, int64(wander(wan+" rx", 6e6, t)), int64(wander(wan+" tx", 0.8e6, t)),
		int64(wander("passed", 900, t))+576012345, blocked, int64(wander("out", 700, t))+76802102,
		states, int64(wander("searches", 646, t))+1296523460, int64(wander("match", 20, t))+41203311)
}

var mockAttackers = []string{"198.51.100.23", "198.51.100.201", "185.220.101.4", "45.95.147.10", "162.142.125.9", "192.0.2.66"}
var mockPorts = []int{22, 23, 3389, 445, 8080, 5060, 1433, 443}

// pflog is tcpdump's reading of the last hour of logged packets: probes
// of the WAN blocked by the logging rules, and the odd IoT device
// reaching for the LAN. Entries sit in fixed time slots, so each poll
// sees the same history plus whatever is new.
func (p *mockPf) pflog(m *pf.Model, now time.Time) string {
	rs := mockRules(m)
	var logging []mockRule
	for _, r := range rs {
		if strings.HasPrefix(r.text, "block") && strings.Contains(r.text, " log") {
			logging = append(logging, r)
		}
	}
	if len(logging) == 0 {
		return ""
	}
	wan, wanID, iot, iotID, lanNet := "em0", "wan", "", "", netip.Prefix{}
	for _, i := range m.Interfaces {
		switch {
		case i.Role == pf.RoleWAN:
			wan, wanID = i.Device, i.ID
		case i.VLAN != nil && iot == "":
			iot, iotID = i.Device, i.ID
		case i.Role == pf.RoleLAN && i.IPv4.Prefix != nil && !lanNet.IsValid():
			if a, err := netip.ParseAddr(i.IPv4.Address); err == nil {
				lanNet = netip.PrefixFrom(a, *i.IPv4.Prefix).Masked()
			}
		}
	}
	var b strings.Builder
	const every = 25 // seconds per slot
	last := now.Unix() / every
	for k := last - 3600/every; k <= last; k++ {
		h := seed(fmt.Sprint("log", k))
		if h%3 == 0 {
			continue // quiet slot
		}
		at := time.Unix(k*every+int64(h%every), int64(h%1000)*1000).In(now.Location())
		if at.After(now) {
			continue
		}
		src := fmt.Sprintf("%s.%d", mockAttackers[int(h>>8)%len(mockAttackers)], 1024+h%60000)
		dst := fmt.Sprintf("203.0.113.24.%d", mockPorts[int(h>>12)%len(mockPorts)])
		on, onID := wan, wanID
		if iot != "" && lanNet.IsValid() && h%5 == 0 {
			on, onID = iot, iotID
			src = fmt.Sprintf("192.168.20.10%d.%d", 1+h%3, 40000+h%9000)
			dst = fmt.Sprintf("%s.%d", lanNet.Addr().Next().Next().String(), []int{445, 22, 80}[h%3])
		}
		// A logging rule that applies there: one on that interface, or
		// one on every interface (the default block).
		var fits []mockRule
		for _, r := range logging {
			if strings.Contains(r.text, "on $"+onID+" ") || !strings.Contains(r.text, " on ") {
				fits = append(fits, r)
			}
		}
		if len(fits) == 0 {
			continue
		}
		r := fits[int(h>>4)%len(fits)]
		pkt := "S 3242389126:3242389126(0) win 1024"
		if h%9 == 0 {
			pkt = "udp 412"
		}
		fmt.Fprintf(&b, "%s rule %d/(match) block in on %s: %s > %s: %s\n", at.Format("Jan _2 15:04:05.000000"), r.n, on, src, dst, pkt)
	}
	return b.String()
}
