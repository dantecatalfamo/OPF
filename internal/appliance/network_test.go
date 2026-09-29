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
