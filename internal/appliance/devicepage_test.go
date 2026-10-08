package appliance

import (
	"strings"
	"testing"
)

func TestDevices(t *testing.T) {
	e, _ := activityEnv(t) // a lease for 192.168.1.112, the sample's ARP table
	all, err := e.m.Devices()
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]DeviceInfo{}
	for _, d := range all.Devices {
		by[d.Key] = d
	}
	// The lease and the ARP entry are one device, on the LAN.
	laptop, ok := by["mac:3c:22:fb:91:04:7d"]
	if !ok || laptop.Lease == nil || len(laptop.ARP) != 1 || laptop.Name != "priya-mbp" || len(laptop.Networks) != 1 || laptop.Networks[0].ID != "lan" {
		t.Errorf("laptop %+v", laptop)
	}
	// A reservation names its device.
	// Where each name came from: the device's own choice says so.
	if laptop.NameFrom != "asked" {
		t.Errorf("the lease's name: from %q", laptop.NameFrom)
	}
	if files := by["mac:00:1b:21:3a:4f:10"]; files.Reservation == nil || files.Name != "files" || files.NameFrom != "reservation" {
		t.Errorf("reserved device %+v", files)
	}
	// VPN devices from the model, on their tunnel.
	if p := by["vpn:p1"]; p.Kind != "vpn" || p.Name != "Priya phone" || p.VPN == nil || p.VPN.Tunnel == "" || len(p.Networks) != 1 {
		t.Errorf("VPN device %+v %+v", p, p.VPN)
	}
	// The WAN's neighbour isn't one of the network's devices.
	for _, d := range all.Devices {
		if strings.HasPrefix(strings.Join(d.Addresses, ","), "203.0.113.") {
			t.Errorf("a WAN neighbour: %+v", d)
		}
	}
	if d, err := e.m.Device("mac:3c:22:fb:91:04:7d"); err != nil || d.Lease == nil {
		t.Errorf("one device: %+v %v", d, err)
	}
	if d, err := e.m.Device("ip:192.168.1.77"); err != nil || d.Kind != "address" || d.Networks[0].ID != "lan" {
		t.Errorf("an address only: %+v %v", d, err)
	}
	if _, err := e.m.Device("nonsense"); code(err) != CodeNotFound {
		t.Errorf("an unknown key: %v", err)
	}
}
