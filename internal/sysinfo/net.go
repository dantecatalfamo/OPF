package sysinfo

import (
	"math/bits"
	"net/netip"
	"strconv"
	"strings"
)

// Interface is one interface as `ifconfig -A` shows it.
type Interface struct {
	Name  string   `json:"name"`
	Flags []string `json:"flags"`
	// Up is the UP flag (configured up); Running is RUNNING (the
	// driver has resources). Status is the link: "active", "no
	// carrier", or empty when the driver doesn't report one.
	Up          bool     `json:"up"`
	Running     bool     `json:"running"`
	MTU         int      `json:"mtu,omitempty"`
	MAC         string   `json:"mac,omitempty"`
	Description string   `json:"description,omitempty"`
	Media       string   `json:"media,omitempty"`
	Status      string   `json:"status,omitempty"`
	Groups      []string `json:"groups"`
	// IPv4 and IPv6 are its addresses as address/prefix.
	IPv4      []string   `json:"ipv4"`
	IPv6      []string   `json:"ipv6"`
	VLAN      *VLAN      `json:"vlan,omitempty"`
	Carp      *Carp      `json:"carp,omitempty"`
	WireGuard *WireGuard `json:"wireguard,omitempty"`
}

// VLAN is a vlan(4) interface's tag and parent.
type VLAN struct {
	ID     int    `json:"id"`
	Parent string `json:"parent"`
}

// Carp is a carp(4) interface's state (MASTER, BACKUP, INIT).
type Carp struct {
	State   string `json:"state"`
	Device  string `json:"device"`
	VHID    int    `json:"vhid"`
	AdvSkew int    `json:"advskew"`
}

// WireGuard is a wg(4) interface's status. Peers and keys are only
// shown to root.
type WireGuard struct {
	Port      int      `json:"port,omitempty"`
	PublicKey string   `json:"publicKey,omitempty"`
	Peers     []WGPeer `json:"peers"`
}

// WGPeer is one peer of a wg(4) interface.
type WGPeer struct {
	PublicKey   string `json:"publicKey"`
	Description string `json:"description,omitempty"`
	// Endpoint is where its packets last came from, host:port.
	Endpoint string `json:"endpoint,omitempty"`
	TxBytes  uint64 `json:"txBytes"`
	RxBytes  uint64 `json:"rxBytes"`
	// HandshakeAgo is seconds since the last handshake; nil if there
	// hasn't been one.
	HandshakeAgo *int64   `json:"handshakeAgo,omitempty"`
	AllowedIPs   []string `json:"allowedIps"`
}

// ParseIfconfig reads `ifconfig -A` output: a header line per interface
// ("em0: flags=8843<UP,BROADCAST,...> mtu 1500"), then its details
// indented by a tab, with a wg peer's details indented by two.
func ParseIfconfig(out string) []Interface {
	var ifs []Interface
	var cur *Interface
	var peer *WGPeer
	for _, l := range lines(out) {
		if l == "" {
			continue
		}
		if l[0] != '\t' && l[0] != ' ' {
			name, rest, ok := strings.Cut(l, ": flags=")
			if !ok || name == "" || strings.ContainsAny(name, " \t") {
				cur, peer = nil, nil
				continue
			}
			ifs = append(ifs, Interface{Name: name, Groups: []string{}, IPv4: []string{}, IPv6: []string{}})
			cur, peer = &ifs[len(ifs)-1], nil
			if i, j := strings.Index(rest, "<"), strings.Index(rest, ">"); i >= 0 && j > i {
				if fl := rest[i+1 : j]; fl != "" {
					cur.Flags = strings.Split(fl, ",")
				}
				rest = rest[j+1:]
			}
			for _, f := range cur.Flags {
				cur.Up = cur.Up || f == "UP"
				cur.Running = cur.Running || f == "RUNNING"
			}
			if f := strings.Fields(rest); len(f) >= 2 && f[0] == "mtu" {
				cur.MTU, _ = strconv.Atoi(f[1])
			}
			if cur.Flags == nil {
				cur.Flags = []string{}
			}
			continue
		}
		if cur == nil {
			continue
		}
		if strings.HasPrefix(l, "\t\t") {
			if peer != nil {
				parseWGPeerLine(peer, strings.TrimSpace(l))
			}
			continue
		}
		peer = nil
		line := strings.TrimSpace(l)
		key, val, _ := strings.Cut(line, " ")
		switch key {
		case "lladdr":
			cur.MAC = val
		case "description:":
			cur.Description = val
		case "media:":
			cur.Media = val
		case "status:":
			cur.Status = val
		case "groups:":
			cur.Groups = strings.Fields(val)
		case "inet":
			if a := parseInet(strings.Fields(val)); a != "" {
				cur.IPv4 = append(cur.IPv4, a)
			}
		case "inet6":
			if a := parseInet6(strings.Fields(val)); a != "" {
				cur.IPv6 = append(cur.IPv6, a)
			}
		case "encap:":
			// encap: vnetid 20 parent em1 txprio packet rxprio outer
			f := strings.Fields(val)
			v := &VLAN{}
			for i := 0; i+1 < len(f); i++ {
				switch f[i] {
				case "vnetid":
					v.ID, _ = strconv.Atoi(f[i+1])
				case "parent":
					v.Parent = f[i+1]
				}
			}
			cur.VLAN = v
		case "carp:":
			// carp: MASTER carpdev em0 vhid 1 advbase 1 advskew 0
			f := strings.Fields(val)
			if len(f) == 0 {
				continue
			}
			c := &Carp{State: f[0]}
			for i := 1; i+1 < len(f); i++ {
				switch f[i] {
				case "carpdev":
					c.Device = f[i+1]
				case "vhid":
					c.VHID, _ = strconv.Atoi(f[i+1])
				case "advskew":
					c.AdvSkew, _ = strconv.Atoi(f[i+1])
				}
			}
			cur.Carp = c
		case "wgport":
			wg(cur).Port, _ = strconv.Atoi(val)
		case "wgpubkey":
			wg(cur).PublicKey = val
		case "wgpeer":
			w := wg(cur)
			w.Peers = append(w.Peers, WGPeer{PublicKey: val, AllowedIPs: []string{}})
			peer = &w.Peers[len(w.Peers)-1]
		}
	}
	return ifs
}

func wg(i *Interface) *WireGuard {
	if i.WireGuard == nil {
		i.WireGuard = &WireGuard{Peers: []WGPeer{}}
	}
	return i.WireGuard
}

// parseWGPeerLine reads one line of a peer's details, as ifconfig's
// wg_status prints them.
func parseWGPeerLine(p *WGPeer, l string) {
	key, val, _ := strings.Cut(l, " ")
	switch key {
	case "wgdescr", "wgdescr:":
		p.Description = val
	case "wgendpoint":
		if f := strings.Fields(val); len(f) == 2 {
			if a, err := netip.ParseAddr(f[0]); err == nil {
				if port, err := strconv.ParseUint(f[1], 10, 16); err == nil {
					p.Endpoint = netip.AddrPortFrom(a, uint16(port)).String()
				}
			}
		}
	case "tx:":
		// tx: 1234, rx: 5678
		f := strings.Fields(strings.ReplaceAll(val, ",", ""))
		if len(f) == 3 && f[1] == "rx:" {
			p.TxBytes, _ = strconv.ParseUint(f[0], 10, 64)
			p.RxBytes, _ = strconv.ParseUint(f[2], 10, 64)
		}
	case "last":
		// last handshake: 42 seconds ago
		f := strings.Fields(val)
		if len(f) == 4 && f[0] == "handshake:" && f[2] == "seconds" {
			if n, err := strconv.ParseInt(f[1], 10, 64); err == nil && n >= 0 {
				p.HandshakeAgo = &n
			}
		}
	case "wgaip":
		if pf, err := netip.ParsePrefix(val); err == nil {
			p.AllowedIPs = append(p.AllowedIPs, pf.String())
		}
	}
}

// parseInet reads "192.168.1.1 netmask 0xffffff00 broadcast ..." or a
// point-to-point "10.0.0.1 --> 10.0.0.2 netmask 0xffffffff".
func parseInet(f []string) string {
	if len(f) == 0 {
		return ""
	}
	a, err := netip.ParseAddr(f[0])
	if err != nil || !a.Is4() {
		return ""
	}
	for i := 1; i+1 < len(f); i++ {
		if f[i] == "netmask" {
			m, err := strconv.ParseUint(strings.TrimPrefix(f[i+1], "0x"), 16, 32)
			if err != nil {
				return ""
			}
			ones := bits.OnesCount32(uint32(m))
			return netip.PrefixFrom(a, ones).String()
		}
	}
	return netip.PrefixFrom(a, 32).String()
}

// parseInet6 reads "fe80::1%lo0 prefixlen 64 scopeid 0x3 ...". The zone
// is dropped; link-local addresses are shown with their interface.
func parseInet6(f []string) string {
	if len(f) == 0 {
		return ""
	}
	addr, _, _ := strings.Cut(f[0], "%")
	a, err := netip.ParseAddr(addr)
	if err != nil || !a.Is6() {
		return ""
	}
	for i := 1; i+1 < len(f); i++ {
		if f[i] == "prefixlen" {
			n, err := strconv.Atoi(f[i+1])
			if err != nil || n < 0 || n > 128 {
				return ""
			}
			return netip.PrefixFrom(a, n).String()
		}
	}
	return netip.PrefixFrom(a, 128).String()
}

// Counters are an interface's totals since it was created.
type Counters struct {
	RxBytes   uint64 `json:"rxBytes"`
	TxBytes   uint64 `json:"txBytes"`
	RxPackets uint64 `json:"rxPackets"`
	TxPackets uint64 `json:"txPackets"`
	RxErrors  uint64 `json:"rxErrors"`
	TxErrors  uint64 `json:"txErrors"`
	Collision uint64 `json:"collisions"`
}

// ParseNetstatIfaces reads `netstat -ibn` (bytes) and `netstat -in`
// (packets and errors) into counters by interface name. Only the
// <Link> row of each interface is used: the others repeat its
// counters for each address. A row's address column can be empty, so
// numbers are read from the right.
func ParseNetstatIfaces(bytesOut, pktsOut string) map[string]Counters {
	c := map[string]Counters{}
	link := func(out string, want int, set func(name string, n []uint64)) {
		for _, l := range lines(out) {
			f := strings.Fields(l)
			if len(f) < 3+want || f[2] != "<Link>" {
				continue
			}
			n := make([]uint64, want)
			ok := true
			for i := range want {
				x, err := strconv.ParseUint(f[len(f)-want+i], 10, 64)
				if err != nil {
					ok = false
					break
				}
				n[i] = x
			}
			if ok {
				set(strings.TrimSuffix(f[0], "*"), n)
			}
		}
	}
	link(bytesOut, 2, func(name string, n []uint64) {
		x := c[name]
		x.RxBytes, x.TxBytes = n[0], n[1]
		c[name] = x
	})
	link(pktsOut, 5, func(name string, n []uint64) {
		x := c[name]
		x.RxPackets, x.RxErrors, x.TxPackets, x.TxErrors, x.Collision = n[0], n[1], n[2], n[3], n[4]
		c[name] = x
	})
	return c
}

// Ping is a ping(8) summary.
type Ping struct {
	Sent     int     `json:"sent"`
	Received int     `json:"received"`
	LossPct  float64 `json:"lossPct"`
	// Round-trip times in milliseconds; zero when nothing came back.
	MinMs float64 `json:"minMs"`
	AvgMs float64 `json:"avgMs"`
	MaxMs float64 `json:"maxMs"`
}

// ParsePing reads the statistics ping -q prints at the end:
//
//	3 packets transmitted, 3 packets received, 0.0% packet loss
//	round-trip min/avg/max/std-dev = 0.134/0.188/0.230/0.040 ms
//
// ok is false when there are no statistics (ping failed to start).
func ParsePing(out string) (p Ping, ok bool) {
	for _, l := range lines(out) {
		f := strings.Fields(l)
		switch {
		case len(f) >= 7 && f[1] == "packets" && f[2] == "transmitted,":
			p.Sent, _ = strconv.Atoi(f[0])
			p.Received, _ = strconv.Atoi(f[3])
			for i, s := range f {
				if strings.HasSuffix(s, "%") && i+1 < len(f) && f[i+1] == "packet" {
					p.LossPct, _ = strconv.ParseFloat(strings.TrimSuffix(s, "%"), 64)
				}
			}
			ok = true
		case len(f) >= 4 && f[0] == "round-trip" && f[2] == "=":
			t := strings.Split(f[3], "/")
			if len(t) >= 3 {
				p.MinMs, _ = strconv.ParseFloat(t[0], 64)
				p.AvgMs, _ = strconv.ParseFloat(t[1], 64)
				p.MaxMs, _ = strconv.ParseFloat(t[2], 64)
			}
		}
	}
	return p, ok
}
