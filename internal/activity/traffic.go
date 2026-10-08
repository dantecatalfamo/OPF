package activity

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"time"
)

// Traffic is what devices sent and received, by hour, from pf's
// per-address counters (pf.TrafficAccounting). Like the DNS activity it
// keeps counts only, bounded: at most MaxDevices a day, the rest pooled
// as Other.

// Bytes is traffic: sent and received, by the device it's counted for.
type Bytes struct {
	Sent            int64 `json:"sent"`
	Received        int64 `json:"received"`
	SentPackets     int64 `json:"sentPackets,omitempty"`
	ReceivedPackets int64 `json:"receivedPackets,omitempty"`
}

func (b *Bytes) add(o Bytes) {
	b.Sent += o.Sent
	b.Received += o.Received
	b.SentPackets += o.SentPackets
	b.ReceivedPackets += o.ReceivedPackets
}

// Total is what went both ways.
func (b Bytes) Total() int64 { return b.Sent + b.Received }

// TrafficHour is an hour's traffic.
type TrafficHour struct {
	Start int64 `json:"start"` // Unix seconds, on the hour
	// Total is every device's; Unknown what came from addresses not in
	// pf's table yet (a device OPF hadn't seen), counted apart.
	Total   Bytes            `json:"total"`
	Unknown int64            `json:"unknown,omitempty"`
	Devices map[string]Bytes `json:"devices,omitempty"`
	// Firewall is what the firewall started itself, apart from Total:
	// a device's lookup it passes on is the device's and then the
	// firewall's.
	Firewall Bytes `json:"firewall,omitzero"`
}

// Counter is a cumulative count pf keeps, as last read.
type Counter struct {
	Sent, Received               uint64
	SentPackets, ReceivedPackets uint64
}

// TrafficStore is the traffic kept, oldest hour first, and the counters
// as last read (so a restart doesn't count again what was counted).
// It isn't safe for concurrent use.
type TrafficStore struct {
	Hours []*TrafficHour `json:"hours"`
	// DeviceCap is how many devices a day are kept apart; 0 is
	// DefaultTrafficDevices. Set by whoever reads, from the settings.
	DeviceCap int `json:"-"`
	// Last is each address's counters, and each unknown-traffic label's
	// bytes, when they were last read.
	Last        map[string]Counter `json:"last,omitempty"`
	LastUnknown map[string]uint64  `json:"lastUnknown,omitempty"`
	LastSelf    Counter            `json:"lastSelf,omitzero"`
}

// FirewallKey is the firewall's own row's key, as in the DNS activity.
const FirewallKey = "firewall"

// ReadSelf takes the firewall's own counters (its rule's: they start
// again when the ruleset reloads).
func (s *TrafficStore) ReadSelf(now time.Time, c Counter) {
	h := s.hour(now)
	before := s.LastSelf
	h.Firewall.add(Bytes{
		Sent: delta(c.Sent, before.Sent), Received: delta(c.Received, before.Received),
		SentPackets: delta(c.SentPackets, before.SentPackets), ReceivedPackets: delta(c.ReceivedPackets, before.ReceivedPackets),
	})
	s.LastSelf = c
}

// delta is what a cumulative counter gained since it was last read. A
// counter lower than before was started again (its address taken out of
// the table and put back, or its label's rules reloaded): it all counts.
func delta(now, before uint64) int64 {
	if now < before {
		return int64(now)
	}
	return int64(now - before)
}

// DefaultTrafficDevices is TrafficStore's cap when none is set.
const DefaultTrafficDevices = 512

func (s *TrafficStore) deviceCap() int {
	if s.DeviceCap > 0 {
		return s.DeviceCap
	}
	return DefaultTrafficDevices
}

func (s *TrafficStore) hour(t time.Time) *TrafficHour {
	start := t.Truncate(time.Hour).Unix()
	if n := len(s.Hours); n > 0 && s.Hours[n-1].Start >= start {
		return s.Hours[n-1]
	}
	h := &TrafficHour{Start: start}
	s.Hours = append(s.Hours, h)
	return h
}

// Read takes counters pf reports, by address, and who each address is
// (device keys; "" for one it doesn't know yet, counted under the
// address), and counts what they gained since the last read. An address
// read for the first time counts all it has: OPF adds it to the table
// at zero.
func (s *TrafficStore) Read(now time.Time, counters map[string]Counter, deviceOf func(addr string) string) {
	if s.Last == nil {
		s.Last = map[string]Counter{}
	}
	h := s.hour(now)
	// The devices that already have a place this hour keep it; a day's
	// MaxDevices counts across its hours.
	day := s.devicesToday(now)
	for addr, c := range counters {
		before := s.Last[addr]
		b := Bytes{
			Sent: delta(c.Sent, before.Sent), Received: delta(c.Received, before.Received),
			SentPackets: delta(c.SentPackets, before.SentPackets), ReceivedPackets: delta(c.ReceivedPackets, before.ReceivedPackets),
		}
		s.Last[addr] = c
		if b == (Bytes{}) {
			continue
		}
		key := deviceOf(addr)
		if key == "" {
			key = "ip:" + addr
		}
		if !day[key] && len(day) >= s.deviceCap() {
			key = Other
		}
		day[key] = true
		h.Total.add(b)
		if h.Devices == nil {
			h.Devices = map[string]Bytes{}
		}
		d := h.Devices[key]
		d.add(b)
		h.Devices[key] = d
	}
	// Addresses pf no longer has: nothing more to count from them.
	for addr := range s.Last {
		if _, ok := counters[addr]; !ok {
			delete(s.Last, addr)
		}
	}
}

// ReadUnknown takes the unknown-traffic labels' bytes.
func (s *TrafficStore) ReadUnknown(now time.Time, labels map[string]uint64) {
	if s.LastUnknown == nil {
		s.LastUnknown = map[string]uint64{}
	}
	h := s.hour(now)
	for l, n := range labels {
		h.Unknown += delta(n, s.LastUnknown[l])
		s.LastUnknown[l] = n
	}
}

func (s *TrafficStore) devicesToday(now time.Time) map[string]bool {
	start := midnight(now).Unix()
	seen := map[string]bool{}
	for i := len(s.Hours) - 1; i >= 0 && s.Hours[i].Start >= start; i-- {
		for k := range s.Hours[i].Devices {
			seen[k] = true
		}
	}
	return seen
}

// Prune drops hours older than days days before now (today counts as
// one).
func (s *TrafficStore) Prune(now time.Time, days int) {
	cut := midnight(now).AddDate(0, 0, 1-days).Unix()
	for len(s.Hours) > 0 && s.Hours[0].Start < cut {
		s.Hours = s.Hours[1:]
	}
}

// ForgetDevice drops a device's traffic; "" drops everything, but not
// the counters as last read, which aren't anyone's.
func (s *TrafficStore) ForgetDevice(key string) {
	if key == "" {
		s.Hours = nil
		return
	}
	if key == FirewallKey {
		for _, h := range s.Hours {
			h.Firewall = Bytes{}
		}
		return
	}
	for _, h := range s.Hours {
		if b, ok := h.Devices[key]; ok {
			h.Total.Sent -= b.Sent
			h.Total.Received -= b.Received
			h.Total.SentPackets -= b.SentPackets
			h.Total.ReceivedPackets -= b.ReceivedPackets
			delete(h.Devices, key)
		}
	}
}

// TrafficHourCounts is an hour's traffic, for a page.
type TrafficHourCounts struct {
	Start   time.Time `json:"start"`
	Unknown int64     `json:"unknown,omitempty"`
	Bytes
}

// TrafficDevice is a device's traffic over the days asked for.
type TrafficDevice struct {
	Key string `json:"key"`
	Bytes
}

// TrafficSummary is the network's traffic since Since.
type TrafficSummary struct {
	Since   time.Time           `json:"since"`
	Total   Bytes               `json:"total"`
	Unknown int64               `json:"unknown"`
	Hours   []TrafficHourCounts `json:"hours"`
	// Devices, those that moved most first; the firewall among them
	// (FirewallKey), when it moved anything, but not in Total.
	Devices []TrafficDevice `json:"devices"`
	// Firewall is what it started itself.
	Firewall Bytes `json:"firewall"`
}

// Summary is the last days days (today counts as one).
func (s *TrafficStore) Summary(now time.Time, days int) TrafficSummary {
	since := midnight(now).AddDate(0, 0, 1-days)
	out := TrafficSummary{Since: since, Hours: []TrafficHourCounts{}, Devices: []TrafficDevice{}}
	devs := map[string]*Bytes{}
	for _, h := range s.Hours {
		if h.Start < since.Unix() {
			continue
		}
		out.Total.add(h.Total)
		out.Unknown += h.Unknown
		out.Hours = append(out.Hours, TrafficHourCounts{Start: time.Unix(h.Start, 0), Unknown: h.Unknown, Bytes: h.Total})
		out.Firewall.add(h.Firewall)
		for k, b := range h.Devices {
			d := devs[k]
			if d == nil {
				d = &Bytes{}
				devs[k] = d
			}
			d.add(b)
		}
	}
	for k, b := range devs {
		out.Devices = append(out.Devices, TrafficDevice{Key: k, Bytes: *b})
	}
	if out.Firewall.Total() > 0 {
		out.Devices = append(out.Devices, TrafficDevice{Key: FirewallKey, Bytes: out.Firewall})
	}
	sort.Slice(out.Devices, func(i, j int) bool {
		a, b := out.Devices[i], out.Devices[j]
		if a.Total() != b.Total() {
			return a.Total() > b.Total()
		}
		return a.Key < b.Key
	})
	return out
}

// TrafficDeviceHours is one device's traffic by hour.
type TrafficDeviceHours struct {
	Key   string              `json:"key"`
	Since time.Time           `json:"since"`
	Total Bytes               `json:"total"`
	Hours []TrafficHourCounts `json:"hours"`
}

// Device is a device's last days days; false when nothing of it is kept.
func (s *TrafficStore) Device(key string, now time.Time, days int) (TrafficDeviceHours, bool) {
	since := midnight(now).AddDate(0, 0, 1-days)
	out := TrafficDeviceHours{Key: key, Since: since, Hours: []TrafficHourCounts{}}
	found := false
	for _, h := range s.Hours {
		b, ok := h.Devices[key]
		if key == FirewallKey {
			b, ok = h.Firewall, h.Firewall.Total() > 0
		}
		if h.Start < since.Unix() || !ok {
			continue
		}
		found = true
		out.Total.add(b)
		out.Hours = append(out.Hours, TrafficHourCounts{Start: time.Unix(h.Start, 0), Bytes: b})
	}
	return out, found
}

// Save writes the store as JSON.
func (s *TrafficStore) Save(w io.Writer) error { return json.NewEncoder(w).Encode(s) }

// LoadTraffic reads a saved store, checking it's in order.
func LoadTraffic(r io.Reader) (*TrafficStore, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxFileSize {
		return nil, fmt.Errorf("activity: the saved traffic is over %d bytes", maxFileSize)
	}
	var s TrafficStore
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	for i, h := range s.Hours {
		if h == nil || (i > 0 && h.Start <= s.Hours[i-1].Start) {
			return nil, fmt.Errorf("activity: the saved traffic's hours are out of order")
		}
	}
	return &s, nil
}

// An hour's traffic at most, saved, measured (TestTrafficWorstCase):
// a little for the hour itself and about 140 bytes a device.
const (
	WorstTrafficHourBase = 256
	WorstTrafficDevice   = 140
)

// WorstTraffic is the most days of traffic can take with devices kept
// apart a day.
func WorstTraffic(days, devices int) int64 {
	return (WorstTrafficHourBase + WorstTrafficDevice*int64(devices)) * 24 * int64(days)
}
