// Package activity keeps what the resolver answered, for the network
// and for each device: counts by hour, and the names looked up and
// blocked most by day. It keeps counts only, never the queries, and
// everything in it is bounded, so a device asking for a million random
// names costs what one asking for ten does.
package activity

import "sort"

// TopK keeps the names seen most, in at most Cap entries, by the
// Space-Saving algorithm: a name not yet kept, when it's full, takes
// the place of the least-seen one and its count, plus one. A count is
// then at most Err more than the true one, and a name seen more often
// than 1/Cap of the time is always kept.
type TopK struct {
	Cap   int    `json:"cap"`
	Items []Item `json:"items"`
	index map[string]int
}

// Item is a name and how often it was seen.
type Item struct {
	Name  string `json:"name"`
	Count int64  `json:"count"`
	// Err is how much of Count may be another name's, from when this
	// one took its place.
	Err  int64 `json:"err,omitempty"`
	Last int64 `json:"last"` // Unix seconds
	// What blocked it last, for blocked names: a list's id (empty for
	// your own names) and the entry that matched.
	List  string `json:"list,omitempty"`
	Entry string `json:"entry,omitempty"`
	// For the network's lists, when and who: how often in each hour of
	// the day (local time), and the devices that asked most, at most
	// ItemDevices of them, Space-Saving again. Both count from when the
	// name took its place in the list, so with Err they add up to less
	// than Count.
	Hours   []int64       `json:"hours,omitempty"`
	Devices []DeviceCount `json:"devices,omitempty"`
}

// DeviceCount is how often a device asked for a name.
type DeviceCount struct {
	Key   string `json:"key"`
	Count int64  `json:"count"`
	Err   int64  `json:"err,omitempty"`
}

// ItemDevices is how many devices a name in the network's lists keeps.
const ItemDevices = 10

// note counts the name once in hour (0-23), asked by device ("" when
// devices aren't kept).
func (it *Item) note(hour int, device string) {
	if hour < 0 || hour > 23 {
		return
	}
	if it.Hours == nil {
		it.Hours = make([]int64, 24)
	}
	it.Hours[hour]++
	if device == "" {
		return
	}
	for i := range it.Devices {
		if it.Devices[i].Key == device {
			it.Devices[i].Count++
			return
		}
	}
	if len(it.Devices) < ItemDevices {
		it.Devices = append(it.Devices, DeviceCount{Key: device, Count: 1})
		return
	}
	low := 0
	for i := range it.Devices {
		if it.Devices[i].Count < it.Devices[low].Count {
			low = i
		}
	}
	c := it.Devices[low].Count
	it.Devices[low] = DeviceCount{Key: device, Count: c + 1, Err: c}
}

func newTopK(capacity int) TopK { return TopK{Cap: capacity} }

func (t *TopK) find(name string) (int, bool) {
	if t.index == nil {
		t.index = make(map[string]int, len(t.Items))
		for i, it := range t.Items {
			t.index[it.Name] = i
		}
	}
	i, ok := t.index[name]
	return i, ok
}

// Add counts name once, at unix time at, and returns its place, nil
// when the list keeps nothing.
func (t *TopK) Add(name string, at int64, list, entry string) *Item {
	i, ok := t.find(name)
	switch {
	case ok:
	case len(t.Items) < t.Cap:
		t.Items = append(t.Items, Item{Name: name})
		i = len(t.Items) - 1
		t.index[name] = i
	default:
		if t.Cap <= 0 {
			return nil
		}
		i = 0
		for j := range t.Items {
			if t.Items[j].Count < t.Items[i].Count {
				i = j
			}
		}
		delete(t.index, t.Items[i].Name)
		t.Items[i] = Item{Name: name, Count: t.Items[i].Count, Err: t.Items[i].Count}
		t.index[name] = i
	}
	it := &t.Items[i]
	it.Count++
	if at >= it.Last {
		it.Last, it.List, it.Entry = at, list, entry
	}
	return it
}

// Get is name's place in the list, if it has one.
func (t *TopK) Get(name string) (Item, bool) {
	if i, ok := t.find(name); ok {
		return t.Items[i], true
	}
	return Item{}, false
}

// Top merges lists, adding up each name's counts, and returns the n
// seen most, most first.
func Top(lists []*TopK, n int) []Item {
	sum := map[string]*Item{}
	for _, l := range lists {
		for _, it := range l.Items {
			s := sum[it.Name]
			if s == nil {
				// The lists' when and who are for one name at a time
				// (Store.Name), not every list's.
				c := it
				c.Hours, c.Devices = nil, nil
				sum[it.Name] = &c
				continue
			}
			s.Count += it.Count
			s.Err += it.Err
			if it.Last >= s.Last {
				s.Last, s.List, s.Entry = it.Last, it.List, it.Entry
			}
		}
	}
	out := make([]Item, 0, len(sum))
	for _, it := range sum {
		out = append(out, *it)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Name < out[j].Name
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}
