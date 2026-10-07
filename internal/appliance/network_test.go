package appliance

import (
	"testing"
)

func TestParseARPOutput(t *testing.T) {
	output := `? (192.168.1.1) at 00:0d:b9:5e:21:a0 on em0 expires in 1198 seconds
myhost (192.168.1.20) at 00:1b:21:3a:4f:10 on em1 permanent published
? (192.168.1.40) at a4:5d:36:0c:81:9e on em1 expires in 445 seconds
? (10.8.0.2) at (incomplete) on wg0 expires in 60 seconds
`
	entries := parseARPOutput(output)
	if len(entries) != 4 {
		t.Fatalf("got %d entries, want 4: %+v", len(entries), entries)
	}

	// Check first entry
	if e := entries[0]; e.IP != "192.168.1.1" || e.MAC != "00:0d:b9:5e:21:a0" || e.Iface != "em0" || e.Expires != "1198s" {
		t.Errorf("entry 0: %+v", e)
	}

	// Check entry with hostname
	if e := entries[1]; e.IP != "192.168.1.20" || e.Hostname != "myhost" || e.Expires != "permanent" || e.Flags != "published" {
		t.Errorf("entry 1 (with hostname): %+v", e)
	}

	// Check incomplete entry
	if e := entries[3]; e.IP != "10.8.0.2" || e.MAC != "(incomplete)" {
		t.Errorf("entry 3 (incomplete): %+v", e)
	}
}

func TestParseRoutingOutput(t *testing.T) {
	output := `Routing tables

Internet:
Destination        Gateway            Flags   Refs      Use   Mtu  Prio Iface
default            203.0.113.1        UGS        2    12345     -    12 em0
10.8.0/24          10.8.0.1           UCn        1        0     -     4 wg0
127/8              127.0.0.1          UGRS       0        0 32768     8 lo0
192.168.1/24       192.168.1.1        UCn        1        0     -     4 em1
`
	routes := parseRoutingOutput(output)
	if len(routes) != 4 {
		t.Fatalf("got %d routes, want 4: %+v", len(routes), routes)
	}

	// Check default route
	if r := routes[0]; r.Destination != "default" || r.Gateway != "203.0.113.1" || r.Flags != "UGS" || r.Iface != "em0" || r.Priority != 12 {
		t.Errorf("default route: %+v", r)
	}

	// Check interface route
	if r := routes[1]; r.Destination != "10.8.0/24" || r.Source != "interface" {
		t.Errorf("interface route: %+v", r)
	}

	// Check loopback
	if r := routes[2]; r.Iface != "lo0" || r.Priority != 8 {
		t.Errorf("loopback route: %+v", r)
	}
}

// OpenBSD 7.9's arp -an, from the test VM: a table, not the other BSDs'
// "? (address) at" lines.
func TestParseARPTable(t *testing.T) {
	output := `Host                                 Ethernet Address    Netif Expire    Flags
100.64.1.2                           fe:e1:ba:d0:39:14    vio0 17m38s    
100.64.1.3                           fe:e1:bb:d1:72:dc    vio0 permanent l
192.168.50.2                         fe:e1:ba:d1:94:cf    vio1 19m10s
10.8.0.2                             (incomplete)         wg0 expired
   
`
	entries := parseARPOutput(output)
	if len(entries) != 4 {
		t.Fatalf("got %d entries, want 4: %+v", len(entries), entries)
	}
	if e := entries[0]; e.IP != "100.64.1.2" || e.MAC != "fe:e1:ba:d0:39:14" || e.Iface != "vio0" || e.Expires != "17m38s" || e.Flags != "" {
		t.Errorf("entry 0: %+v", e)
	}
	if e := entries[1]; e.Expires != "permanent" || e.Flags != "local" {
		t.Errorf("entry 1 (the firewall's own): %+v", e)
	}
	if e := entries[3]; e.IP != "10.8.0.2" || e.MAC != "(incomplete)" || e.Iface != "wg0" {
		t.Errorf("entry 3 (incomplete): %+v", e)
	}
}
