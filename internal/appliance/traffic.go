package appliance

import (
	"context"
	"errors"
	"io/fs"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/dantecatalfamo/OPF/internal/activity"
	"github.com/dantecatalfamo/OPF/internal/pf"
	"github.com/dantecatalfamo/OPF/internal/sysinfo"
)

// Traffic per device (pf.TrafficAccounting): pf counts each address in
// its table (pf.TrafficTable), every packet both ways; every collector
// tick OPF reads what the counters gained into the hour's counts, by
// device, and keeps the table to the network's devices: those the
// leases, the ARP table and the VPN's devices show, on an inside
// network, dropped an hour after they were last seen. What came from an
// address not in the table yet is counted apart (the traffic-unknown
// rules).

const (
	trafficFile = "traffic.json"
	// staleAfter is how long an address stays in the table after OPF
	// last saw a device there.
	staleAfter = time.Hour
)

type trafficState struct {
	mu     sync.Mutex
	loaded bool
	store  *activity.TrafficStore
	// seen is when each address in the table was last seen.
	seen map[netip.Addr]time.Time
	// dropped: turning it off has been cleaned up after.
	dropped bool
}

func (m *Manager) trafficStore() *activity.TrafficStore {
	t := &m.traffic
	if !t.loaded {
		t.loaded = true
		t.store = &activity.TrafficStore{}
		if f, err := os.Open(m.store.StatePath(trafficFile)); err == nil {
			if s, err := activity.LoadTraffic(f); err == nil {
				t.store = s
			} else {
				log.Printf("starting the traffic over: %v", err)
			}
			f.Close()
		}
	}
	return t.store
}

func (m *Manager) saveTraffic() error {
	if !m.traffic.loaded {
		return nil
	}
	path := m.store.StatePath(trafficFile)
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+trafficFile+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := m.traffic.store.Save(tmp); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// SaveTraffic saves the traffic; the collector calls it with the graphs.
func (m *Manager) SaveTraffic() error {
	m.traffic.mu.Lock()
	defer m.traffic.mu.Unlock()
	return m.saveTraffic()
}

// insideNetworks are the networks whose devices are counted.
func insideNetworks(model *pf.Model) []netip.Prefix {
	var out []netip.Prefix
	for _, i := range pf.TrafficIfaces(model) {
		if i.IPv4.Mode != pf.IPv4Static || i.IPv4.Prefix == nil {
			continue
		}
		if a, err := netip.ParseAddr(i.IPv4.Address); err == nil {
			if p, err := a.Prefix(*i.IPv4.Prefix); err == nil {
				out = append(out, p)
			}
		}
	}
	return out
}

// readTraffic reads pf's counters and keeps its table to the devices.
func (m *Manager) readTraffic(model *pf.Model, now time.Time) {
	t := &m.traffic
	t.mu.Lock()
	defer t.mu.Unlock()
	if model == nil || !pf.KeepsTraffic(model) {
		m.dropTraffic()
		return
	}
	t.dropped = false
	s := m.trafficStore()
	s.Prune(now, model.Firewall.Traffic.Days)

	// The counters, before the table changes, so an address taken out
	// has its last counts read.
	out, err := m.read("pfctl", "-t", pf.TrafficTable, "-T", "show", "-v")
	if err != nil {
		return // the commit that turns it on hasn't loaded the rules yet
	}
	counters := map[string]activity.Counter{}
	inTable := map[netip.Addr]bool{}
	for addr, c := range sysinfo.ParsePfTableCounters(out) {
		counters[addr] = activity.Counter{Sent: c.SentBytes, Received: c.ReceivedBytes, SentPackets: c.SentPackets, ReceivedPackets: c.ReceivedPackets}
		if a, err := netip.ParseAddr(addr); err == nil {
			inTable[a] = true
		}
	}
	s.Read(now, counters, m.deviceResolver(model, now))
	if out, err := m.read("pfctl", "-s", "labels"); err == nil {
		unknown := map[string]uint64{}
		for l, c := range sysinfo.ParsePfLabels(out) {
			kind, _, ok := pf.ParseLabel(l)
			switch {
			case !ok:
			case kind == pf.LabelTrafficUnknown:
				unknown[l] = c.Bytes
			case kind == pf.LabelTrafficSelf:
				// Its connections are opened by the firewall: In is what
				// it sent, Out the replies it got.
				s.ReadSelf(now, activity.Counter{Sent: c.InBytes, Received: c.OutBytes, SentPackets: c.InPackets, ReceivedPackets: c.OutPackets})
			}
		}
		s.ReadUnknown(now, unknown)
	}

	// The table: the devices on the inside networks now, and those seen
	// within staleAfter.
	if t.seen == nil {
		t.seen = map[netip.Addr]time.Time{}
	}
	nets := insideNetworks(model)
	for _, a := range m.knownAddresses(model, now) {
		if slices.ContainsFunc(nets, func(p netip.Prefix) bool { return p.Contains(a) }) {
			t.seen[a] = now
		}
	}
	var add, del []string
	for a, at := range t.seen {
		switch {
		case now.Sub(at) > staleAfter:
			delete(t.seen, a)
		case !inTable[a]:
			add = append(add, a.String())
		}
	}
	for a := range inTable {
		if _, ok := t.seen[a]; !ok {
			del = append(del, a.String())
		}
	}
	m.changeTrafficTable("add", add)
	m.changeTrafficTable("delete", del)
}

func (m *Manager) changeTrafficTable(op string, addrs []string) {
	if len(addrs) == 0 {
		return
	}
	slices.Sort(addrs)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := m.actions().Run(ctx, append([]string{"pfctl", "-t", pf.TrafficTable, "-T", op}, addrs...)...); err != nil {
		log.Printf("traffic per device: couldn't %s %s: %v", op, strings.Join(addrs, " "), err)
	}
}

// dropTraffic deletes what was kept, and pf's table, once traffic isn't
// counted any more. Call it with t.mu held.
func (m *Manager) dropTraffic() {
	t := &m.traffic
	if t.dropped {
		return
	}
	t.dropped = true
	t.seen = nil
	path := m.store.StatePath(trafficFile)
	if _, err := os.Stat(path); err == nil || (t.loaded && len(t.store.Hours) > 0) {
		t.store, t.loaded = &activity.TrafficStore{}, true
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			log.Printf("deleting the traffic: %v", err)
		}
	}
	// The rules are gone with the commit that turned it off; the table
	// persists until it's killed.
	if out, err := m.read("pfctl", "-s", "Tables"); err == nil && slices.Contains(strings.Fields(out), pf.TrafficTable) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		m.actions().Run(ctx, "pfctl", "-t", pf.TrafficTable, "-T", "kill")
	}
}

// TrafficRequest asks for the last Days days (today counts as one), or
// one device's (Device).
type TrafficRequest = DNSActivityRequest

// Traffic is what the network's devices sent and received over the
// days asked for.
type Traffic struct {
	// The setting in effect; when Enabled is false nothing else is set.
	Enabled bool `json:"enabled"`
	Days    int  `json:"days"`
	*activity.TrafficSummary
	DeviceInfo map[string]ActivityDevice `json:"deviceInfo,omitempty"`
	// SavedBytes is the traffic kept, as last saved.
	SavedBytes int64 `json:"savedBytes"`
}

// TrafficDeviceView is one device's traffic by hour.
type TrafficDeviceView struct {
	ActivityDevice
	*activity.TrafficDeviceHours
}

// Traffic is the network's traffic over req.Days.
func (m *Manager) Traffic(req TrafficRequest) (*Traffic, error) {
	model, _, err := m.live()
	if err != nil {
		return nil, apiError(err)
	}
	out := &Traffic{}
	if model == nil || !pf.KeepsTraffic(model) {
		return out, nil
	}
	out.Enabled, out.Days = true, model.Firewall.Traffic.Days
	if fi, err := os.Stat(m.store.StatePath(trafficFile)); err == nil {
		out.SavedBytes = fi.Size()
	}
	m.traffic.mu.Lock()
	sum := m.trafficStore().Summary(time.Now(), activityDays(req.Days, out.Days))
	m.traffic.mu.Unlock()
	out.TrafficSummary = &sum
	names := m.deviceNames(model)
	out.DeviceInfo = map[string]ActivityDevice{}
	for _, d := range sum.Devices {
		out.DeviceInfo[d.Key] = describeDevice(d.Key, names, model)
	}
	return out, nil
}

// TrafficDevice is one device's traffic over req.Days.
func (m *Manager) TrafficDevice(req TrafficRequest) (*TrafficDeviceView, error) {
	model, _, err := m.live()
	if err != nil {
		return nil, apiError(err)
	}
	if model == nil || !pf.KeepsTraffic(model) {
		return nil, errorf(CodeNotFound, "traffic isn't kept for each device")
	}
	m.traffic.mu.Lock()
	d, ok := m.trafficStore().Device(req.Device, time.Now(), activityDays(req.Days, model.Firewall.Traffic.Days))
	m.traffic.mu.Unlock()
	if !ok {
		return nil, errorf(CodeNotFound, "nothing is kept for that device over those days")
	}
	return &TrafficDeviceView{ActivityDevice: describeDevice(req.Device, m.deviceNames(model), model), TrafficDeviceHours: &d}, nil
}

// ForgetTraffic deletes one device's traffic, or with no device all of
// it.
func (m *Manager) ForgetTraffic(req TrafficRequest) error {
	m.traffic.mu.Lock()
	defer m.traffic.mu.Unlock()
	m.trafficStore().ForgetDevice(req.Device)
	return apiError(m.saveTraffic())
}
