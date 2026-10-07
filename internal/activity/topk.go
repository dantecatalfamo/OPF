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

// Add counts name once, at unix time at.
func (t *TopK) Add(name string, at int64, list, entry string) {
	i, ok := t.find(name)
	switch {
	case ok:
	case len(t.Items) < t.Cap:
		t.Items = append(t.Items, Item{Name: name})
		i = len(t.Items) - 1
		t.index[name] = i
	default:
		if t.Cap <= 0 {
			return
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
}

// Top merges lists, adding up each name's counts, and returns the n
// seen most, most first.
func Top(lists []*TopK, n int) []Item {
	sum := map[string]*Item{}
	for _, l := range lists {
		for _, it := range l.Items {
			s := sum[it.Name]
			if s == nil {
				c := it
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
