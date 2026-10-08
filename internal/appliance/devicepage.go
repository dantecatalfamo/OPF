package appliance

import (
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/dantecatalfamo/OPF/internal/pf"
	"github.com/dantecatalfamo/OPF/internal/sysinfo"
)

// The devices OPF knows of, each with everything it knows about who it
// is: its DHCP lease and reservation, its ARP entries, the network it's
// on, its VPN tunnel, when it was first seen. Keys are those the DNS
// activity and the traffic are kept under (devices.go), so a device's
// page can show those too.

// DeviceInfo is one device.
type DeviceInfo struct {
	Key  string `json:"key"`
	Kind string `json:"kind"` // device, vpn
	Name string `json:"name,omitempty"`
	// NameFrom is where the name came from: "reservation" (the admin's),
	// "dns" (the name its lease has in DNS), "asked" (what the device
	// calls itself, which DNS refused or isn't asked to give it), or
	// "vpn" (the VPN device's).
	NameFrom string `json:"nameFrom,omitempty"`
	MAC      string `json:"mac,omitempty"`
	// Addresses are those it has now, or last had.
	Addresses []string `json:"addresses"`
	// Networks are the inside networks its addresses are on.
	Networks    []DeviceNetwork    `json:"networks"`
	Lease       *DHCPLease         `json:"lease,omitempty"`
	Reservation *DeviceReservation `json:"reservation,omitempty"`
	ARP         []ARPEntry         `json:"arp,omitempty"`
	VPN         *DeviceVPN         `json:"vpn,omitempty"`
	// FirstSeen is when OPF first saw its MAC address (the event log).
	FirstSeen *time.Time `json:"firstSeen,omitempty"`
}

// DeviceNetwork is an interface of the model a device is on.
type DeviceNetwork struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Device string `json:"device"`
}

// DeviceReservation is a DHCP reservation for a device.
type DeviceReservation struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
	IP       string `json:"ip"`
	Network  string `json:"network"` // the DHCP scope's interface id
}

// DeviceVPN is a VPN device's tunnel and, when the tunnel's up, its
// state now.
type DeviceVPN struct {
	Tunnel       string `json:"tunnel"`
	TunnelName   string `json:"tunnelName"`
	Peer         string `json:"peer"`
	Address      string `json:"address"`
	ClientRoutes string `json:"clientRoutes"`
	// From the interface now, when it's up.
	Endpoint     string `json:"endpoint,omitempty"`
	HandshakeAgo *int64 `json:"handshakeAgo,omitempty"`
	RxBytes      uint64 `json:"rxBytes"`
	TxBytes      uint64 `json:"txBytes"`
	// What OPF remembers of its last handshake.
	LastSeen *time.Time `json:"lastSeen,omitempty"`
	LastFrom string     `json:"lastFrom,omitempty"`
}

// Devices is every device OPF knows of.
type Devices struct {
	Devices []DeviceInfo `json:"devices"`
	Errors  []string     `json:"errors"`
}

// knownSince is when the event log first saw a MAC address.
func (l *eventLog) knownSince(mac string) (time.Time, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	t, ok := l.known[strings.ToLower(mac)]
	return t, ok
}

// networkOf is the inside interface whose network holds addr.
func networkOf(model *pf.Model, addr string) (pf.Iface, bool) {
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return pf.Iface{}, false
	}
	for _, i := range model.Interfaces {
		if i.Role == pf.RoleWAN || i.IPv4.Mode != pf.IPv4Static || i.IPv4.Prefix == nil {
			continue
		}
		if ia, err := netip.ParseAddr(i.IPv4.Address); err == nil {
			if p, err := ia.Prefix(*i.IPv4.Prefix); err == nil && p.Contains(a) {
				return i, true
			}
		}
	}
	return pf.Iface{}, false
}

// allDevices gathers every device: those with a DHCP lease, a reservation,
// an ARP entry on an inside network, or a VPN tunnel. live adds each VPN
// device's state now (ifconfig), for one device's page.
func (m *Manager) allDevices(live bool) (*Devices, error) {
	model, err := m.liveOrEmpty()
	if err != nil {
		return nil, apiError(err)
	}
	out := &Devices{Devices: []DeviceInfo{}, Errors: []string{}}
	byKey := map[string]*DeviceInfo{}
	get := func(key, kind string) *DeviceInfo {
		if d := byKey[key]; d != nil {
			return d
		}
		d := &DeviceInfo{Key: key, Kind: kind, Addresses: []string{}, Networks: []DeviceNetwork{}}
		byKey[key] = d
		return d
	}
	addAddr := func(d *DeviceInfo, a string) {
		if a != "" && !slices.Contains(d.Addresses, a) {
			d.Addresses = append(d.Addresses, a)
		}
	}

	if ls, err := m.DHCPLeases(); err == nil {
		if ls.Error != "" {
			out.Errors = append(out.Errors, ls.Error)
		}
		for _, l := range ls.Leases {
			if l.MAC == "" {
				continue
			}
			mac := strings.ToLower(l.MAC)
			d := get(deviceMAC+mac, "device")
			d.MAC = mac
			lease := l
			d.Lease = &lease
			addAddr(d, l.IP)
		}
	}
	for _, s := range model.DHCP {
		for _, r := range s.Reservations {
			if r.MAC == "" {
				continue
			}
			mac := strings.ToLower(r.MAC)
			d := get(deviceMAC+mac, "device")
			d.MAC = mac
			d.Reservation = &DeviceReservation{ID: r.ID, Hostname: r.Hostname, IP: r.IP, Network: s.Iface}
		}
	}
	if t, err := m.ARPTable(); err == nil {
		if t.Error != "" {
			out.Errors = append(out.Errors, t.Error)
		}
		for _, e := range t.Entries {
			// The firewall's own, and anything not on an inside network,
			// aren't its devices.
			if !validMAC(e.MAC) || strings.Contains(e.Flags, "local") {
				continue
			}
			if _, ok := networkOf(model, e.IP); !ok {
				continue
			}
			mac := strings.ToLower(e.MAC)
			d := get(deviceMAC+mac, "device")
			d.MAC = mac
			d.ARP = append(d.ARP, e)
			addAddr(d, e.IP)
		}
	}
	var peers map[string]sysinfo.WGPeer // by public key
	if live {
		peers = map[string]sysinfo.WGPeer{}
		if ifs, err := m.Interfaces(); err == nil {
			for _, i := range ifs.Interfaces {
				if i.WireGuard != nil {
					for _, p := range i.WireGuard.Peers {
						peers[p.PublicKey] = p
					}
				}
			}
		}
	}
	for _, i := range model.Interfaces {
		if i.WireGuard == nil || i.WireGuard.Exit != nil {
			continue
		}
		for _, p := range i.WireGuard.Peers {
			d := get(deviceVPN+p.ID, "vpn")
			d.Name, d.NameFrom = p.Name, "vpn"
			addr := strings.TrimSuffix(p.Address, "/32")
			addAddr(d, addr)
			v := &DeviceVPN{Tunnel: i.ID, TunnelName: i.Name, Peer: p.ID, Address: p.Address, ClientRoutes: string(p.ClientRoutes)}
			if s, ok := m.eventLog().device(p.ID); ok {
				at := s.At
				v.LastSeen, v.LastFrom = &at, s.From
			}
			if st, ok := peers[p.PublicKey]; ok {
				v.Endpoint, v.HandshakeAgo, v.RxBytes, v.TxBytes = st.Endpoint, st.HandshakeAgo, st.RxBytes, st.TxBytes
			}
			d.VPN = v
			d.Networks = append(d.Networks, DeviceNetwork{ID: i.ID, Name: i.Name, Device: i.Device})
		}
	}

	for _, d := range byKey {
		if d.Kind == "device" {
			// A reservation's name, else the lease's in DNS, else the
			// one the device asked for.
			switch {
			case d.Reservation != nil && d.Reservation.Hostname != "":
				d.Name, d.NameFrom = d.Reservation.Hostname, "reservation"
			case d.Lease != nil && d.Lease.DNSName != "":
				d.Name, d.NameFrom = d.Lease.DNSName, "dns"
			case d.Lease != nil && d.Lease.Hostname != "":
				d.Name, d.NameFrom = d.Lease.Hostname, "asked"
			}
			if t, ok := m.eventLog().knownSince(d.MAC); ok {
				d.FirstSeen = &t
			}
			if d.Reservation != nil && len(d.Addresses) == 0 {
				addAddr(d, d.Reservation.IP)
			}
			for _, a := range d.Addresses {
				if i, ok := networkOf(model, a); ok && !slices.ContainsFunc(d.Networks, func(n DeviceNetwork) bool { return n.ID == i.ID }) {
					d.Networks = append(d.Networks, DeviceNetwork{ID: i.ID, Name: i.Name, Device: i.Device})
				}
			}
		}
		out.Devices = append(out.Devices, *d)
	}
	sort.Slice(out.Devices, func(i, j int) bool {
		a, b := out.Devices[i], out.Devices[j]
		if (a.Name == "") != (b.Name == "") {
			return a.Name != ""
		}
		if a.Name != b.Name {
			return strings.ToLower(a.Name) < strings.ToLower(b.Name)
		}
		return a.Key < b.Key
	})
	return out, nil
}

// Devices is every device OPF knows of.
func (m *Manager) Devices() (*Devices, error) { return m.allDevices(false) }

// Device is one device, with its VPN state now. A key OPF has counted
// traffic or DNS activity under but knows nothing else about (an
// address only, say) is still a device: its page shows those.
func (m *Manager) Device(key string) (*DeviceInfo, error) {
	all, err := m.allDevices(true)
	if err != nil {
		return nil, err
	}
	for _, d := range all.Devices {
		if d.Key == key {
			return &d, nil
		}
	}
	switch {
	case strings.HasPrefix(key, deviceAddress):
		addr := strings.TrimPrefix(key, deviceAddress)
		if _, err := netip.ParseAddr(addr); err == nil {
			d := &DeviceInfo{Key: key, Kind: "address", Addresses: []string{addr}, Networks: []DeviceNetwork{}}
			if model, err := m.liveOrEmpty(); err == nil {
				if i, ok := networkOf(model, addr); ok {
					d.Networks = append(d.Networks, DeviceNetwork{ID: i.ID, Name: i.Name, Device: i.Device})
				}
			}
			return d, nil
		}
	case key == deviceFirewall:
		return &DeviceInfo{Key: key, Kind: "firewall", Name: "This firewall", Addresses: []string{}, Networks: []DeviceNetwork{}}, nil
	case strings.HasPrefix(key, deviceMAC) && validMAC(strings.TrimPrefix(key, deviceMAC)):
		// Not seen now (no lease or ARP entry), but its activity may be kept.
		return &DeviceInfo{Key: key, Kind: "device", MAC: strings.TrimPrefix(key, deviceMAC), Addresses: []string{}, Networks: []DeviceNetwork{}}, nil
	}
	return nil, errorf(CodeNotFound, "OPF knows no device %q", key)
}
