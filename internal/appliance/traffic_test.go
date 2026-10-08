package appliance

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dantecatalfamo/OPF/internal/activity"
	"github.com/dantecatalfamo/OPF/internal/pf"
)

// fakePfTable is pf's traffic table: OPF's adds and deletes change it,
// and show -v reports each address's counters.
type fakePfTable struct {
	mu      sync.Mutex
	entries map[string][2]uint64 // sent, received
	unknown uint64
	// The firewall's own rule's bytes: those it sent, the replies.
	selfSent, selfReceived uint64
	commands               []string
	exists                 bool
}

func (f *fakePfTable) Run(_ context.Context, argv ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cmd := strings.Join(argv, " ")
	f.commands = append(f.commands, cmd)
	switch {
	case strings.HasPrefix(cmd, "pfctl -t opf_hosts -T show -v"):
		if !f.exists {
			return []byte("pfctl: Table does not exist.\n"), fmt.Errorf("exit status 1")
		}
		var b strings.Builder
		for _, a := range slices.Sorted(func(yield func(string) bool) {
			for k := range f.entries {
				if !yield(k) {
					return
				}
			}
		}) {
			c := f.entries[a]
			fmt.Fprintf(&b, "   %s\n\tCleared:     Wed Oct  7 15:44:41 2026\n\tIn/Match:    [ Packets: 1 Bytes: %d ]\n\tOut/Match:   [ Packets: 1 Bytes: %d ]\n", a, c[0], c[1])
		}
		return []byte(b.String()), nil
	case strings.HasPrefix(cmd, "pfctl -t opf_hosts -T add "):
		for _, a := range argv[5:] {
			f.entries[a] = [2]uint64{}
		}
	case strings.HasPrefix(cmd, "pfctl -t opf_hosts -T delete "):
		for _, a := range argv[5:] {
			delete(f.entries, a)
		}
	case cmd == "pfctl -t opf_hosts -T kill":
		f.entries, f.exists = map[string][2]uint64{}, false
	case cmd == "pfctl -s labels":
		return []byte(fmt.Sprintf("opf:traffic-unknown:lan 5 3 %d 2 %d 1 0 1\nopf:traffic-self:firewall 9 20 %d 10 %d 10 %d 4\n",
			f.unknown, f.unknown, f.selfSent+f.selfReceived, f.selfSent, f.selfReceived)), nil
	case cmd == "pfctl -s Tables":
		if f.exists {
			return []byte("opf_hosts\n"), nil
		}
	}
	return nil, nil
}

func (f *fakePfTable) has(a string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.entries[a]
	return ok
}

func (f *fakePfTable) count(a string, sent, received uint64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.entries[a]
	f.entries[a] = [2]uint64{c[0] + sent, c[1] + received}
}

const FirewallKeyForTest = "firewall"

func TestTrafficPerDevice(t *testing.T) {
	e := newEnv(t, time.Minute)
	m := e.live().Model
	m.Firewall.Traffic = &pf.TrafficAccounting{Enabled: true, Days: 7}
	if err := stageCommit(t, e, m); err != nil {
		t.Fatal(err)
	}
	model := e.live().Model
	fake := &fakePfTable{entries: map[string][2]uint64{}, exists: true}
	e.m.Runner, e.m.Actions = fake, fake
	now := time.Now()

	// The first tick: the devices on the inside networks go in the
	// table (the sample ARP table's), the WAN's neighbour doesn't.
	e.m.readTraffic(model, now)
	if !fake.has("192.168.1.112") || !fake.has("192.168.20.101") || fake.has("203.0.113.1") {
		t.Fatalf("table %v", fake.entries)
	}
	// Traffic, and some from an address OPF doesn't know.
	fake.count("192.168.1.112", 1000, 50_000)
	fake.count("192.168.20.101", 200, 300)
	fake.unknown = 4096
	fake.selfSent, fake.selfReceived = 700, 70_000
	e.m.readTraffic(model, now.Add(10*time.Second))
	tr, err := e.m.Traffic(DNSActivityRequest{Days: 1})
	if err != nil || !tr.Enabled {
		t.Fatalf("%+v %v", tr, err)
	}
	if tr.Total.Sent != 1200 || tr.Total.Received != 50_300 || tr.Unknown != 4096 {
		t.Errorf("total %+v, unknown %d", tr.Total, tr.Unknown)
	}
	// The firewall's own row: apart from the devices' total.
	if tr.Firewall.Sent != 700 || tr.Firewall.Received != 70_000 || tr.DeviceInfo[FirewallKeyForTest].Kind != "firewall" {
		t.Errorf("firewall %+v %+v", tr.Firewall, tr.DeviceInfo[FirewallKeyForTest])
	}
	var top activity.TrafficDevice
	for _, d := range tr.Devices {
		if d.Key == "mac:3c:22:fb:91:04:7d" {
			top = d
		}
	}
	if top.Received != 50_000 || tr.DeviceInfo[top.Key].Kind != "device" {
		t.Errorf("top device %+v %+v", top, tr.DeviceInfo[top.Key])
	}
	d, err := e.m.TrafficDevice(DNSActivityRequest{Days: 1, Device: top.Key})
	if err != nil || d.Total.Sent != 1000 {
		t.Errorf("device %+v %v", d, err)
	}

	// Not seen for over an hour: its last counts are read, then it's
	// taken out.
	fake.count("192.168.20.101", 5, 5)
	e.m.traffic.mu.Lock()
	for a := range e.m.traffic.seen {
		if a.String() == "192.168.20.101" {
			e.m.traffic.seen[a] = now.Add(-2 * time.Hour)
		}
	}
	e.m.traffic.mu.Unlock()
	e.m.devices.mu.Lock()
	for a := range e.m.devices.byAddr {
		if a.String() == "192.168.20.101" {
			delete(e.m.devices.byAddr, a)
		}
	}
	e.m.devices.at = now.Add(20 * time.Second) // no new look this tick
	e.m.devices.mu.Unlock()
	e.m.readTraffic(model, now.Add(20*time.Second))
	if fake.has("192.168.20.101") {
		t.Error("a device not seen for hours is still in the table")
	}
	if tr, _ := e.m.Traffic(DNSActivityRequest{Days: 1}); tr.Total.Sent != 1205 {
		t.Errorf("its last counts: %+v", tr.Total)
	}

	// Saved, and off: the saved traffic and the table go.
	if err := e.m.SaveTraffic(); err != nil {
		t.Fatal(err)
	}
	model.Firewall.Traffic.Enabled = false
	e.m.readTraffic(model, now.Add(30*time.Second))
	if _, err := os.Stat(e.m.store.StatePath(trafficFile)); err == nil {
		t.Error("the saved traffic is still there")
	}
	if fake.exists {
		t.Error("pf's table wasn't killed")
	}
}
