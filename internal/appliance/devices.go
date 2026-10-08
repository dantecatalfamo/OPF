package appliance

import (
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/dantecatalfamo/OPF/internal/leases"
	"github.com/dantecatalfamo/OPF/internal/pf"
)

// Who an address is, as a key counts are kept under, for the DNS
// activity and the traffic alike: a MAC address from the DHCP leases or
// the ARP table ("mac:..."), a VPN device ("vpn:<peer id>"), the
// firewall itself, or else the address.
const (
	deviceMAC      = "mac:"
	deviceVPN      = "vpn:"
	deviceAddress  = "ip:"
	deviceFirewall = "firewall"
)

const (
	// devicesEvery is how often the addresses' devices are looked up
	// again (leases, ARP); an address not found is looked up again
	// sooner, at most every missEvery, so a device that has only just
	// appeared isn't kept under its address.
	devicesEvery = time.Minute
	missEvery    = 10 * time.Second
)

// deviceDirectory is the addresses' devices, from the last look.
type deviceDirectory struct {
	mu     sync.Mutex
	byAddr map[netip.Addr]string
	at     time.Time
}

// deviceResolver says who an address is, looking up again when it's
// been a while, or sooner for an address it doesn't know.
func (m *Manager) deviceResolver(model *pf.Model, now time.Time) func(string) string {
	m.lookUpDevices(model, now, devicesEvery)
	return func(client string) string {
		addr, err := netip.ParseAddr(client)
		if err != nil {
			return deviceAddress + client
		}
		addr = addr.Unmap()
		if addr.IsLoopback() {
			return deviceFirewall
		}
		if k, ok := m.deviceAt(addr); ok {
			return k
		}
		if m.lookUpDevices(model, now, missEvery) {
			if k, ok := m.deviceAt(addr); ok {
				return k
			}
		}
		return deviceAddress + addr.String()
	}
}

func (m *Manager) deviceAt(addr netip.Addr) (string, bool) {
	d := &m.devices
	d.mu.Lock()
	defer d.mu.Unlock()
	k, ok := d.byAddr[addr]
	return k, ok
}

// knownAddresses are the addresses the last look found a device at.
func (m *Manager) knownAddresses(model *pf.Model, now time.Time) []netip.Addr {
	m.lookUpDevices(model, now, devicesEvery)
	d := &m.devices
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]netip.Addr, 0, len(d.byAddr))
	for a := range d.byAddr {
		out = append(out, a)
	}
	return out
}

// lookUpDevices refreshes who each address is unless it was looked up
// less than every ago, and says whether it did.
func (m *Manager) lookUpDevices(model *pf.Model, now time.Time, every time.Duration) bool {
	d := &m.devices
	d.mu.Lock()
	if d.byAddr != nil && now.Sub(d.at) < every && !now.Before(d.at) {
		d.mu.Unlock()
		return false
	}
	d.at = now
	d.mu.Unlock()
	found := map[netip.Addr]string{}
	// The ARP table first: the leases' say who has an address now, so
	// they win. The firewall's own entries (local) aren't devices.
	if t, err := m.ARPTable(); err == nil {
		for _, e := range t.Entries {
			addr, err1 := netip.ParseAddr(e.IP)
			if err1 == nil && validMAC(e.MAC) && !strings.Contains(e.Flags, "local") {
				found[addr] = deviceMAC + strings.ToLower(e.MAC)
			}
		}
	}
	if m.leases != nil {
		if all, err := leases.Read(m.leases.File); err == nil {
			for _, l := range leases.Current(all, now) {
				if l.MAC != "" {
					found[l.IP] = deviceMAC + strings.ToLower(l.MAC)
				}
			}
		}
	}
	for _, i := range model.Interfaces {
		if i.WireGuard == nil {
			continue
		}
		for _, p := range i.WireGuard.Peers {
			// A tunnel address is the device's own: 10.8.0.2/32.
			if pre, err := netip.ParsePrefix(p.Address); err == nil {
				found[pre.Addr()] = deviceVPN + p.ID
			} else if addr, err := netip.ParseAddr(p.Address); err == nil {
				found[addr] = deviceVPN + p.ID
			}
		}
	}
	d.mu.Lock()
	d.byAddr = found
	d.mu.Unlock()
	return true
}
