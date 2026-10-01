package appliance

import (
	"fmt"
	"strings"
	"time"

	"github.com/dantecatalfamo/OPF/internal/pf"
	"github.com/dantecatalfamo/OPF/internal/sysinfo"
)

// Noticing events: each sample is compared with the last. The first
// sample after OPF starts is taken as how things are, not as news.

// watch is what the last sample saw.
type watch struct {
	started   bool
	links     map[string]bool   // interface id: link up
	addrs     map[string]string // DHCP interface id: its first IPv4 address
	gateways  map[string]bool   // gateway id: answering
	endpoints map[string]string // VPN device id: where it last connected from
	services  map[string]bool   // daemon: running
	arpDone   bool
}

func newWatch() *watch {
	return &watch{links: map[string]bool{}, addrs: map[string]string{}, gateways: map[string]bool{}, endpoints: map[string]string{}, services: map[string]bool{}}
}

func ifaceWords(i pf.Iface) string { return fmt.Sprintf("%s (%s)", i.Name, i.Device) }

// linkUp is whether an interface's link works: up, and for a port, a
// carrier; a WireGuard interface has no carrier to lose.
func linkUp(s sysinfo.Interface) bool {
	return s.Up && s.Status != "no carrier" && (s.WireGuard != nil || s.Running)
}

// watchInterfaces notices links going up or down, a DHCP address
// changing, and a VPN device connecting from somewhere new.
func (m *Manager) watchInterfaces(model *pf.Model, ifs []sysinfo.Interface, now time.Time) {
	w, l := m.collect.watch, m.eventLog()
	byDev := map[string]sysinfo.Interface{}
	for _, s := range ifs {
		byDev[s.Name] = s
	}
	peers := map[string]string{} // public key: VPN device's name
	for _, i := range model.Interfaces {
		if i.WireGuard != nil {
			for _, p := range i.WireGuard.Peers {
				peers[p.PublicKey] = p.Name
			}
		}
	}
	peerIDs := tunnelPeers(model)
	for _, i := range model.Interfaces {
		s, ok := byDev[i.Device]
		if !ok || !i.Enabled {
			continue
		}
		up := linkUp(s)
		if was, seen := w.links[i.ID]; seen && was != up && w.started {
			if up {
				l.record(Event{Time: now, Kind: EventLink, Subject: i.ID, Message: ifaceWords(i) + ": link up"})
			} else {
				l.record(Event{Time: now, Kind: EventLink, Subject: i.ID, Warning: true, Message: ifaceWords(i) + ": link down" + map[bool]string{true: " (no carrier)", false: ""}[s.Status == "no carrier"]})
			}
		}
		w.links[i.ID] = up
		if i.IPv4.Mode == "dhcp" {
			addr := ""
			if len(s.IPv4) > 0 {
				addr = strings.SplitN(s.IPv4[0], "/", 2)[0]
			}
			if was, seen := w.addrs[i.ID]; seen && was != addr && addr != "" && w.started {
				msg := fmt.Sprintf("%s has a new address from DHCP: %s", ifaceWords(i), addr)
				if was != "" {
					msg += " (was " + was + ")"
				}
				l.record(Event{Time: now, Kind: EventAddress, Subject: i.ID, Message: msg})
			}
			if addr != "" {
				w.addrs[i.ID] = addr
			}
		}
		if s.WireGuard != nil {
			for _, p := range s.WireGuard.Peers {
				id, ok := peerIDs[p.PublicKey]
				if ok && p.HandshakeAgo != nil {
					l.sawDevice(id, now.Add(-time.Duration(*p.HandshakeAgo)*time.Second), endpointHost(p.Endpoint))
				}
				if !ok || p.Endpoint == "" {
					continue
				}
				host := endpointHost(p.Endpoint)
				if was, seen := w.endpoints[id]; seen && was != host && w.started {
					msg := fmt.Sprintf("%s (%s) connected from %s", peers[p.PublicKey], i.Name, host)
					if was != "" {
						msg += " (was " + was + ")"
					}
					l.record(Event{Time: now, Kind: EventVPN, Subject: id, Message: msg})
				}
				w.endpoints[id] = host
			}
		}
	}
}

// endpointHost is an endpoint without its port: a device roaming
// keeps its address but its port changes with every NAT.
func endpointHost(ep string) string {
	if i := strings.LastIndex(ep, ":"); i > 0 {
		ep = ep[:i]
	}
	return strings.Trim(ep, "[]")
}

// watchSlow notices, every half minute, gateways, new devices and
// daemons.
func (m *Manager) watchSlow(model *pf.Model, gws *GatewaysStatus, now time.Time) {
	w, l := m.collect.watch, m.eventLog()
	if gws != nil && model != nil {
		for _, g := range model.Routing.Gateways {
			h, ok := gws.Gateways[g.ID]
			if !ok || (h.Error != "" && h.Address == "") {
				continue
			}
			if was, seen := w.gateways[g.ID]; seen && was != h.Online && w.started {
				if h.Online {
					l.record(Event{Time: now, Kind: EventGateway, Subject: g.ID, Message: fmt.Sprintf("Gateway %s is answering again", g.Name)})
				} else {
					l.record(Event{Time: now, Kind: EventGateway, Subject: g.ID, Warning: true, Message: fmt.Sprintf("Gateway %s stopped answering (%s)", g.Name, h.Address)})
				}
			}
			w.gateways[g.ID] = h.Online
		}
	}

	// New devices: MAC addresses the ARP table has that OPF hasn't seen,
	// named from their DHCP lease when they have one. The very first
	// look, with nothing remembered, only remembers.
	if t, err := m.ARPTable(); err == nil && t.Error == "" {
		l.mu.Lock()
		fresh := len(l.known) == 0 && !w.arpDone
		l.mu.Unlock()
		names := map[string]string{}
		if ls, err := m.DHCPLeases(); err == nil {
			for _, le := range ls.Leases {
				if le.MAC != "" && le.Hostname != "" {
					names[strings.ToLower(le.MAC)] = le.Hostname
				}
			}
		}
		for _, e := range t.Entries {
			mac := strings.ToLower(e.MAC)
			if !isMAC(mac) || mac == "ff:ff:ff:ff:ff:ff" || strings.HasPrefix(e.Flags, "permanent") || e.Expires == "permanent" {
				continue // incomplete, broadcast, or the firewall's own
			}
			if !l.seen(mac, now, fresh) {
				msg := fmt.Sprintf("New device %s at %s on %s", mac, e.IP, deviceName(model, e.Iface))
				if n := names[mac]; n != "" {
					msg += fmt.Sprintf(" (calls itself “%s”)", n)
				}
				l.record(Event{Time: now, Kind: EventDevice, Subject: mac, Message: msg})
			}
		}
		w.arpDone = true
	}

	// The daemons OPF runs, when the model runs them.
	var daemons []string
	if model != nil {
		for _, d := range model.DHCP {
			if d.Enabled {
				daemons = append(daemons, "dhcpd")
				break
			}
		}
		if model.DNS.Enabled {
			daemons = append(daemons, "unbound")
		}
	}
	daemons = append(daemons, "ntpd")
	for _, d := range daemons {
		_, err := m.read("rcctl", "check", d)
		running := err == nil
		if was, seen := w.services[d]; seen && was != running && w.started {
			if running {
				l.record(Event{Time: now, Kind: EventService, Subject: d, Message: d + " is running again"})
			} else {
				l.record(Event{Time: now, Kind: EventService, Subject: d, Warning: true, Message: d + " stopped"})
			}
		}
		w.services[d] = running
	}
}

// deviceName is an interface's name in the model for a device ("LAN"
// for em1), or the device itself.
func deviceName(m *pf.Model, dev string) string {
	if m != nil {
		for _, i := range m.Interfaces {
			if i.Device == dev {
				return i.Name
			}
		}
	}
	return dev
}

// noteListEvent records a list download failing after working, or
// working again after failing.
func (m *Manager) noteListEvent(key string, before, now refreshRecord, seen bool) {
	kind, name, _ := strings.Cut(key, ":")
	what := map[string]string{"alias": "the list for alias " + name, "dns": "DNS blocklist " + name}[kind]
	switch {
	case now.err != "" && (!seen || before.err == ""):
		m.eventLog().record(Event{Time: now.at, Kind: EventList, Subject: name, Warning: true, Message: "Couldn't download " + what + ": " + now.err})
	case now.err == "" && seen && before.err != "":
		m.eventLog().record(Event{Time: now.at, Kind: EventList, Subject: name, Message: "Downloaded " + what + " again"})
	}
}

// notePatches records security patches that weren't available before.
func (m *Manager) notePatches(before *UpdatesStatus, now *UpdatesStatus) {
	if now.Error != "" || len(now.Patches) == 0 {
		return
	}
	old := map[string]bool{}
	if before != nil {
		for _, p := range before.Patches {
			old[p] = true
		}
	}
	var fresh []string
	for _, p := range now.Patches {
		if !old[p] {
			fresh = append(fresh, p)
		}
	}
	if len(fresh) > 0 && (before != nil && before.CheckedAt != nil) {
		m.eventLog().record(Event{Time: *now.CheckedAt, Kind: EventUpdates, Warning: true, Message: fmt.Sprintf("%d new security %s: %s", len(fresh), map[bool]string{true: "patch", false: "patches"}[len(fresh) == 1], strings.Join(fresh, ", "))})
	}
}
