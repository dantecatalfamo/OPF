package activity

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"time"
)

// Bounds on what's kept a day. A device past MaxDevices in a day is
// counted as Other; the caps are what keeps a month a few megabytes.
const (
	MaxDevices  = 128
	NetworkTop  = 200 // names and blocked names a day, for the network
	DeviceTop   = 25  // names and blocked names a day, for each device
	Other       = "other"
	maxFileSize = 64 << 20 // a saved store larger than this isn't read
)

// Counts are what the resolver did.
type Counts struct {
	// Queries is every answer, blocks included.
	Queries int64 `json:"queries"`
	Blocked int64 `json:"blocked"`
	// Allowed is queries your never-block names let through a list.
	Allowed  int64 `json:"allowed,omitempty"`
	NXDomain int64 `json:"nxdomain,omitempty"` // not counting blocks
	ServFail int64 `json:"servfail,omitempty"`
	Cached   int64 `json:"cached,omitempty"`
}

func (c *Counts) add(o Counts) {
	c.Queries += o.Queries
	c.Blocked += o.Blocked
	c.Allowed += o.Allowed
	c.NXDomain += o.NXDomain
	c.ServFail += o.ServFail
	c.Cached += o.Cached
}

// Hour is an hour's counts, for the network and each device, and the
// blocks by list.
type Hour struct {
	Start   int64             `json:"start"` // Unix seconds, on the hour
	Total   Counts            `json:"total"`
	ByList  map[string]int64  `json:"byList,omitempty"` // "" is your own names
	Devices map[string]Counts `json:"devices,omitempty"`
}

// Day is a day's top names, for the network and each device: those
// looked up, those blocked, and those that don't exist (NXDOMAIN, not
// counting blocks), which a misbehaving device asks for by the hundred.
type Day struct {
	Start   int64                 `json:"start"` // Unix seconds, local midnight
	Names   TopK                  `json:"names"`
	Blocked TopK                  `json:"blocked"`
	Missing TopK                  `json:"missing"`
	Devices map[string]*DeviceDay `json:"devices,omitempty"`
}

// DeviceDay is a device's day.
type DeviceDay struct {
	Names   TopK `json:"names"`
	Blocked TopK `json:"blocked"`
	Missing TopK `json:"missing"`
	// The address it last asked from, and when.
	Address string `json:"address"`
	Last    int64  `json:"last"`
}

// Store is everything kept, oldest first, and where the reader of
// unbound's log had got to (so a restart doesn't count lines twice).
// It isn't safe for concurrent use.
type Store struct {
	Hours []*Hour `json:"hours"`
	Days  []*Day  `json:"days"`
	// Log is the reader's place in unbound's log file.
	Log LogPosition `json:"log"`
}

// LogPosition is how far into which file the log has been read.
type LogPosition struct {
	Inode  uint64 `json:"inode"`
	Offset int64  `json:"offset"`
}

// Answer is one answer the resolver gave.
type Answer struct {
	Time time.Time
	// Device is who asked: a key the caller chooses (a MAC address, a
	// VPN device), "" when devices aren't kept. Address is where from.
	Device, Address string
	Name            string
	Rcode           string
	Cached          bool
}

// Block is a query a response policy zone acted on.
type Block struct {
	Time            time.Time
	Device, Address string
	Name            string
	// List is the list that matched, "" for your own names; Entry the
	// entry. Pass: it was let through, not blocked.
	List, Entry string
	Pass        bool
}

func (s *Store) hour(t time.Time) *Hour {
	start := t.Truncate(time.Hour).Unix()
	if n := len(s.Hours); n > 0 && s.Hours[n-1].Start == start {
		return s.Hours[n-1]
	}
	// Lines come in order; one from an earlier hour (a clock stepped
	// back) goes in the newest.
	if n := len(s.Hours); n > 0 && s.Hours[n-1].Start > start {
		return s.Hours[n-1]
	}
	h := &Hour{Start: start}
	s.Hours = append(s.Hours, h)
	return h
}

func midnight(t time.Time) time.Time {
	y, m, d := t.Date()
	return time.Date(y, m, d, 0, 0, 0, 0, t.Location())
}

func (s *Store) day(t time.Time) *Day {
	start := midnight(t).Unix()
	if n := len(s.Days); n > 0 && s.Days[n-1].Start >= start {
		return s.Days[n-1]
	}
	d := &Day{Start: start, Names: newTopK(NetworkTop), Blocked: newTopK(NetworkTop), Missing: newTopK(NetworkTop)}
	s.Days = append(s.Days, d)
	return d
}

// device is a device's place in a day, or Other's once the day has
// MaxDevices.
func (d *Day) device(key string) *DeviceDay {
	if d.Devices == nil {
		d.Devices = map[string]*DeviceDay{}
	}
	if dd := d.Devices[key]; dd != nil {
		return dd
	}
	if len(d.Devices) >= MaxDevices {
		key = Other
		if dd := d.Devices[key]; dd != nil {
			return dd
		}
	}
	dd := &DeviceDay{Names: newTopK(DeviceTop), Blocked: newTopK(DeviceTop), Missing: newTopK(DeviceTop)}
	d.Devices[key] = dd
	return dd
}

// seen notes the device asked at at, from address when it's known.
func (dd *DeviceDay) seen(address string, at int64) {
	if at >= dd.Last {
		dd.Last = at
		if address != "" {
			dd.Address = address
		}
	}
}

// deviceKey is the key a device's counts go under in h: Other once the
// day has no room for it.
func deviceKey(day *Day, key string) string {
	if _, ok := day.Devices[key]; ok || len(day.Devices) < MaxDevices {
		return key
	}
	return Other
}

func (h *Hour) addDevice(key string, c Counts) {
	if h.Devices == nil {
		h.Devices = map[string]Counts{}
	}
	d := h.Devices[key]
	d.add(c)
	h.Devices[key] = d
}

// AddAnswer counts an answer. Blocked says it was one a block just
// answered: counted as a query, not as a name looked up or a failure.
func (s *Store) AddAnswer(a Answer, blocked bool) {
	c := Counts{Queries: 1}
	switch {
	case blocked:
	case a.Rcode == "NXDOMAIN":
		c.NXDomain = 1
	case a.Rcode == "SERVFAIL":
		c.ServFail = 1
	}
	if a.Cached {
		c.Cached = 1
	}
	h, d, at := s.hour(a.Time), s.day(a.Time), a.Time.Unix()
	h.Total.add(c)
	top := func(names, missing *TopK) {
		switch {
		case blocked:
		case a.Rcode == "NOERROR":
			names.Add(a.Name, at, "", "")
		case a.Rcode == "NXDOMAIN":
			missing.Add(a.Name, at, "", "")
		}
	}
	top(&d.Names, &d.Missing)
	if a.Device == "" {
		return
	}
	key := deviceKey(d, a.Device)
	h.addDevice(key, c)
	dd := d.device(key)
	top(&dd.Names, &dd.Missing)
	dd.seen(a.Address, at)
}

// AddBlock counts a block, or a name let through.
func (s *Store) AddBlock(b Block) {
	c := Counts{Blocked: 1}
	if b.Pass {
		c = Counts{Allowed: 1}
	}
	h, d, at := s.hour(b.Time), s.day(b.Time), b.Time.Unix()
	h.Total.add(c)
	if !b.Pass {
		if h.ByList == nil {
			h.ByList = map[string]int64{}
		}
		h.ByList[b.List]++
		d.Blocked.Add(b.Name, at, b.List, b.Entry)
	}
	if b.Device == "" {
		return
	}
	key := deviceKey(d, b.Device)
	h.addDevice(key, c)
	dd := d.device(key)
	if !b.Pass {
		dd.Blocked.Add(b.Name, at, b.List, b.Entry)
	}
	dd.seen(b.Address, at)
}

// Prune drops what's older than days days before now (today counts as
// one), and every device's when devices aren't kept.
func (s *Store) Prune(now time.Time, days int, devices bool) {
	cut := midnight(now).AddDate(0, 0, 1-days).Unix()
	for len(s.Hours) > 0 && s.Hours[0].Start < cut {
		s.Hours = s.Hours[1:]
	}
	for len(s.Days) > 0 && s.Days[0].Start < cut {
		s.Days = s.Days[1:]
	}
	if !devices {
		s.ForgetDevice("")
	}
}

// ForgetDevice drops a device's history; "" drops every device's.
func (s *Store) ForgetDevice(key string) {
	for _, h := range s.Hours {
		if key == "" {
			h.Devices = nil
		} else {
			delete(h.Devices, key)
		}
	}
	for _, d := range s.Days {
		if key == "" {
			d.Devices = nil
		} else {
			delete(d.Devices, key)
		}
	}
}

// Save writes the store as JSON.
func (s *Store) Save(w io.Writer) error { return json.NewEncoder(w).Encode(s) }

// Load reads a saved store, checking it's in order.
func Load(r io.Reader) (*Store, error) {
	var s Store
	data, err := io.ReadAll(io.LimitReader(r, maxFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxFileSize {
		return nil, fmt.Errorf("activity: the saved file is over %d bytes", maxFileSize)
	}
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	for i := 1; i < len(s.Hours); i++ {
		if s.Hours[i] == nil || s.Hours[i-1] == nil || s.Hours[i].Start <= s.Hours[i-1].Start {
			return nil, fmt.Errorf("activity: the saved hours are out of order")
		}
	}
	for i := 1; i < len(s.Days); i++ {
		if s.Days[i] == nil || s.Days[i-1] == nil || s.Days[i].Start <= s.Days[i-1].Start {
			return nil, fmt.Errorf("activity: the saved days are out of order")
		}
	}
	for _, d := range s.Days {
		if d == nil {
			return nil, fmt.Errorf("activity: a saved day is empty")
		}
		// Caps from the code, not the file: a damaged one can't make a
		// list grow without end.
		d.Names.Cap, d.Blocked.Cap, d.Missing.Cap = NetworkTop, NetworkTop, NetworkTop
		for k, dd := range d.Devices {
			if dd == nil {
				delete(d.Devices, k)
				continue
			}
			dd.Names.Cap, dd.Blocked.Cap, dd.Missing.Cap = DeviceTop, DeviceTop, DeviceTop
		}
	}
	for _, h := range s.Hours {
		if h == nil {
			return nil, fmt.Errorf("activity: a saved hour is empty")
		}
	}
	return &s, nil
}

// Summary is what the network did since Since.
type Summary struct {
	Since   time.Time        `json:"since"`
	Total   Counts           `json:"total"`
	Hours   []HourCounts     `json:"hours"`
	ByList  map[string]int64 `json:"byList"`
	Names   []Item           `json:"names"`
	Blocked []Item           `json:"blocked"`
	Missing []Item           `json:"missing"`
	Devices []DeviceSummary  `json:"devices"`
}

// HourCounts is an hour's counts.
type HourCounts struct {
	Start time.Time `json:"start"`
	Counts
}

// DeviceSummary is a device's counts since the summary's Since.
type DeviceSummary struct {
	Key     string    `json:"key"`
	Address string    `json:"address"`
	Last    time.Time `json:"last"`
	Counts
}

// Summary is the last days days (today counts as one), with the n
// names seen and blocked most.
func (s *Store) Summary(now time.Time, days, n int) Summary {
	since := midnight(now).AddDate(0, 0, 1-days)
	out := Summary{Since: since, Hours: []HourCounts{}, ByList: map[string]int64{}, Devices: []DeviceSummary{}}
	devs := map[string]*DeviceSummary{}
	for _, h := range s.Hours {
		if h.Start < since.Unix() {
			continue
		}
		out.Total.add(h.Total)
		out.Hours = append(out.Hours, HourCounts{Start: time.Unix(h.Start, 0), Counts: h.Total})
		for l, c := range h.ByList {
			out.ByList[l] += c
		}
		for k, c := range h.Devices {
			d := devs[k]
			if d == nil {
				d = &DeviceSummary{Key: k}
				devs[k] = d
			}
			d.add(c)
		}
	}
	var names, blocked, missing []*TopK
	for _, d := range s.Days {
		if d.Start < since.Unix() {
			continue
		}
		names, blocked, missing = append(names, &d.Names), append(blocked, &d.Blocked), append(missing, &d.Missing)
		for k, dd := range d.Devices {
			if ds := devs[k]; ds != nil && dd.Last >= ds.Last.Unix() {
				ds.Address, ds.Last = dd.Address, time.Unix(dd.Last, 0)
			}
		}
	}
	out.Names, out.Blocked, out.Missing = Top(names, n), Top(blocked, n), Top(missing, n)
	for _, d := range devs {
		out.Devices = append(out.Devices, *d)
	}
	sort.Slice(out.Devices, func(i, j int) bool {
		a, b := out.Devices[i], out.Devices[j]
		if a.Queries != b.Queries {
			return a.Queries > b.Queries
		}
		return a.Key < b.Key
	})
	return out
}

// DeviceActivity is one device's last days.
type DeviceActivity struct {
	Key     string       `json:"key"`
	Since   time.Time    `json:"since"`
	Address string       `json:"address"`
	Last    time.Time    `json:"last"`
	Total   Counts       `json:"total"`
	Hours   []HourCounts `json:"hours"`
	Names   []Item       `json:"names"`
	Blocked []Item       `json:"blocked"`
	Missing []Item       `json:"missing"`
}

// Device is a device's last days days, with its n names seen and
// blocked most; false when nothing of it is kept.
func (s *Store) Device(key string, now time.Time, days, n int) (DeviceActivity, bool) {
	since := midnight(now).AddDate(0, 0, 1-days)
	out := DeviceActivity{Key: key, Since: since, Hours: []HourCounts{}}
	found := false
	for _, h := range s.Hours {
		c, ok := h.Devices[key]
		if h.Start < since.Unix() || !ok {
			continue
		}
		found = true
		out.Total.add(c)
		out.Hours = append(out.Hours, HourCounts{Start: time.Unix(h.Start, 0), Counts: c})
	}
	var names, blocked, missing []*TopK
	for _, d := range s.Days {
		dd := d.Devices[key]
		if d.Start < since.Unix() || dd == nil {
			continue
		}
		found = true
		names, blocked, missing = append(names, &dd.Names), append(blocked, &dd.Blocked), append(missing, &dd.Missing)
		if dd.Last >= out.Last.Unix() {
			out.Address, out.Last = dd.Address, time.Unix(dd.Last, 0)
		}
	}
	out.Names, out.Blocked, out.Missing = Top(names, n), Top(blocked, n), Top(missing, n)
	return out, found
}
