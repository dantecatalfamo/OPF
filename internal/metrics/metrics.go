// Package metrics keeps time series of the system's numbers (traffic,
// CPU, pf, DNS) in a fixed amount of memory and disk, like RRD: each
// series has rings of time buckets at a few resolutions, recent ones
// fine and old ones coarse, and a sample goes into every ring at once.
// A ring's buckets are aligned to its step, so a bucket's average is
// exact rather than an average of averages. Nothing grows: a new sample
// replaces the bucket a ring's length ago.
//
// Series belong to groups (interfaces, rules...), each with its own
// rings and its own cap on the things it keeps (an interface, a rule),
// so one kind filling up never crowds out another.
package metrics

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"sort"
	"sync"
	"time"
	"unsafe"
)

// Tier is one ring: buckets of Step, Slots of them.
type Tier struct {
	Step  time.Duration
	Slots int
}

// FineTiers are rings for what's sampled every few seconds, finest
// first: an hour of 10 s, a day of minutes, a week of 10 minutes and a
// month of hours. About 110 KB a series.
var FineTiers = []Tier{
	{10 * time.Second, 360},
	{time.Minute, 1440},
	{10 * time.Minute, 1008},
	{time.Hour, 24 * 31},
}

// CoarseTiers are for what's many and graphed small: a week of 10
// minutes and a month of hours. About 55 KB a series.
var CoarseTiers = []Tier{
	{10 * time.Minute, 1008},
	{time.Hour, 24 * 31},
}

func span(ts []Tier) time.Duration {
	t := ts[len(ts)-1]
	return t.Step * time.Duration(t.Slots)
}

// slot is one bucket: which one it is (the time divided by the step;
// 0 is empty) and what went into it.
type slot struct {
	B   int64
	Sum float64
	N   uint32
	Max float64
}

// SeriesBytes is what a series with these rings takes in memory.
func SeriesBytes(ts []Tier) int {
	n := 0
	for _, t := range ts {
		n += t.Slots
	}
	return n * int(unsafe.Sizeof(slot{}))
}

// Group is a kind of series: which keys are its and the thing each
// belongs to (Item: "if.em0" for "if.em0.rx"), its rings, how many
// series a thing has at most (PerItem: an interface's in and out), and
// how many things it keeps.
type Group struct {
	Name    string
	Item    func(key string) (item string, ok bool)
	Tiers   []Tier
	PerItem int
	Max     int
}

// room says whether a thing with n series may have another: under its
// own limit, and a new thing only under the group's cap.
func (g *Group) room(n, items int) bool {
	if n > 0 {
		return n < max(1, g.PerItem)
	}
	return items < g.Max
}

type group struct {
	Group
	items   map[string]int // series by thing
	refused bool           // a new thing was turned away at the cap
}

type series struct {
	g     int
	item  string
	tiers [][]slot
	last  int64 // unix time of the last sample
}

func (s *Store) newSeries(g int, item string) *series {
	ts := s.groups[g].Tiers
	se := &series{g: g, item: item, tiers: make([][]slot, len(ts))}
	for i, t := range ts {
		se.tiers[i] = make([]slot, t.Slots)
	}
	return se
}

// KeyRE is what a series' name may be: "if.em0.rx", "gw.g1.rtt",
// "pf.rule.R12" (model ids keep their case).
var KeyRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$`)

// Store holds the series. It's safe for concurrent use.
type Store struct {
	mu     sync.Mutex
	groups []*group
	series map[string]*series
}

// New returns an empty store with these groups. A key belongs to the
// first group whose Item takes it; one no group takes isn't kept.
func New(groups ...Group) *Store {
	s := &Store{series: map[string]*series{}}
	for _, g := range groups {
		s.groups = append(s.groups, &group{Group: g, items: map[string]int{}})
	}
	return s
}

func (s *Store) groupOf(key string) (int, string, bool) {
	for i, g := range s.groups {
		if item, ok := g.Item(key); ok {
			return i, item, true
		}
	}
	return 0, "", false
}

// Span is how far back the longest group's rings go.
func (s *Store) Span() time.Duration {
	var d time.Duration
	for _, g := range s.groups {
		d = max(d, span(g.Tiers))
	}
	return d
}

// Add records a sample. It's refused (false) for a name that isn't a
// KeyRE or no group's, a value that isn't a number, or a new thing past
// its group's cap.
func (s *Store) Add(key string, t time.Time, v float64) bool {
	if !KeyRE.MatchString(key) || math.IsNaN(v) || math.IsInf(v, 0) {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	se := s.series[key]
	if se == nil {
		gi, item, ok := s.groupOf(key)
		if !ok {
			return false
		}
		g := s.groups[gi]
		if !g.room(g.items[item], len(g.items)) {
			if g.items[item] == 0 {
				g.refused = true
			}
			return false
		}
		se = s.newSeries(gi, item)
		s.series[key] = se
		g.items[item]++
	}
	u := t.Unix()
	for i, tier := range s.groups[se.g].Tiers {
		b := u / int64(tier.Step/time.Second)
		sl := &se.tiers[i][b%int64(tier.Slots)]
		if sl.B != b {
			*sl = slot{B: b, Sum: v, N: 1, Max: v}
			continue
		}
		sl.Sum += v
		sl.N++
		sl.Max = max(sl.Max, v)
	}
	se.last = max(se.last, u)
	return true
}

// SetMax changes how many things a group keeps. Lowered, it forgets the
// things updated least recently beyond the new cap.
func (s *Store) SetMax(name string, n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for gi, g := range s.groups {
		if g.Name != name || g.Max == n {
			continue
		}
		if n > g.Max {
			g.refused = false
		}
		g.Max = n
		s.prune(gi)
	}
}

func (s *Store) prune(gi int) {
	g := s.groups[gi]
	if len(g.items) <= g.Max {
		return
	}
	last := map[string]int64{}
	for _, se := range s.series {
		if se.g == gi {
			last[se.item] = max(last[se.item], se.last)
		}
	}
	items := make([]string, 0, len(last))
	for it := range last {
		items = append(items, it)
	}
	sort.Slice(items, func(i, j int) bool {
		if last[items[i]] != last[items[j]] {
			return last[items[i]] > last[items[j]]
		}
		return items[i] < items[j]
	})
	drop := map[string]bool{}
	for _, it := range items[max(0, g.Max):] {
		drop[it] = true
		delete(g.items, it)
	}
	for k, se := range s.series {
		if se.g == gi && drop[se.item] {
			delete(s.series, k)
		}
	}
	g.refused = true
}

// GroupUse is how full a group is.
type GroupUse struct {
	Name   string `json:"name"`
	Items  int    `json:"items"`
	Max    int    `json:"max"`
	Series int    `json:"series"`
	// SeriesBytes is what one of its series takes in memory.
	SeriesBytes int `json:"seriesBytes"`
	// Refused: something new was turned away because it's full, or
	// forgotten when its cap was lowered.
	Refused bool `json:"refused,omitempty"`
}

// Use reports each group's things and series.
func (s *Store) Use() []GroupUse {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]GroupUse, len(s.groups))
	for i, g := range s.groups {
		out[i] = GroupUse{Name: g.Name, Items: len(g.items), Max: g.Max, SeriesBytes: SeriesBytes(g.Tiers), Refused: g.refused}
	}
	for _, se := range s.series {
		out[se.g].Series++
	}
	return out
}

// Keys lists the series' names, sorted.
func (s *Store) Keys() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	keys := make([]string, 0, len(s.series))
	for k := range s.series {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Result is a series over a time range: point i is at Start + i*Step
// seconds, nil where nothing was recorded.
type Result struct {
	Start int64      `json:"start"`
	Step  int64      `json:"step"`
	Avg   []*float64 `json:"avg"`
	Max   []*float64 `json:"max"`
}

// MaxPoints bounds a Result: a longer range gets a coarser step.
const MaxPoints = 1500

// Query returns a series from from to to, with points at least step
// apart. It reads the finest of its rings that reaches back to from,
// and merges its buckets when step is coarser than the ring's.
func (s *Store) Query(key string, from, to time.Time, step time.Duration) (*Result, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	se := s.series[key]
	if se == nil || !to.After(from) {
		return nil, false
	}
	tiers := s.groups[se.g].Tiers
	now := time.Now()
	ti := len(tiers) - 1
	for i, t := range tiers {
		// A ring reaches back its length; a step more is let in so a
		// range of exactly its length (an hour of 10 s) uses it, less
		// its oldest point, which the newest has taken over.
		if t.Step >= step && !from.Before(now.Add(-t.Step*time.Duration(t.Slots+1))) {
			ti = i
			break
		}
	}
	tier := tiers[ti]
	base := int64(tier.Step / time.Second)
	per := max(1, int64(step/tier.Step)) // ring buckets a point
	if span := to.Unix() - from.Unix(); span/(base*per) > MaxPoints {
		per = (span/MaxPoints + base - 1) / base
	}
	first, last := from.Unix()/base, to.Unix()/base
	first -= first % per
	res := &Result{Start: first * base, Step: base * per}
	ring := se.tiers[ti]
	for b := first; b <= last; b += per {
		var sum, mx float64
		var n uint32
		for j := b; j < b+per && j <= last; j++ {
			sl := ring[j%int64(tier.Slots)]
			if sl.B != j || sl.N == 0 {
				continue
			}
			if n == 0 || sl.Max > mx {
				mx = sl.Max
			}
			sum += sl.Sum
			n += sl.N
		}
		if n == 0 {
			res.Avg, res.Max = append(res.Avg, nil), append(res.Max, nil)
			continue
		}
		a, m := sum/float64(n), mx
		res.Avg, res.Max = append(res.Avg, &a), append(res.Max, &m)
	}
	return res, true
}

// The saved file: "OPFM", a version, then each series: its name, its
// last sample, and its rings, each with its step, its size and its
// buckets that aren't empty. A series is read back only if its rings
// are still its group's (a new OPF may keep a group differently), and
// every count is checked against fixed limits before it's used, so a
// file cut short or damaged is refused rather than read into a loop or
// a huge allocation.
const (
	fileMagic   = "OPFM"
	fileVersion = 2
	maxTiers    = 8
	maxSlots    = 1 << 20
)

// Save writes every series that has had a sample within its rings'
// reach.
func (s *Store) Save(w io.Writer) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	keys := make([]string, 0, len(s.series))
	for k, se := range s.series {
		if se.last >= now.Add(-span(s.groups[se.g].Tiers)).Unix() {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	bw := bufio.NewWriter(w)
	put := func(v any) { binary.Write(bw, binary.LittleEndian, v) }
	bw.WriteString(fileMagic)
	put(uint32(fileVersion))
	put(uint32(len(keys)))
	for _, k := range keys {
		se := s.series[k]
		bw.WriteByte(byte(len(k)))
		bw.WriteString(k)
		put(se.last)
		tiers := s.groups[se.g].Tiers
		bw.WriteByte(byte(len(tiers)))
		for ti, ring := range se.tiers {
			put(uint32(tiers[ti].Step / time.Second))
			put(uint32(tiers[ti].Slots))
			n := 0
			for _, sl := range ring {
				if sl.N > 0 {
					n++
				}
			}
			put(uint32(n))
			for i, sl := range ring {
				if sl.N > 0 {
					put(uint32(i))
					put(sl.B)
					put(sl.Sum)
					put(sl.N)
					put(sl.Max)
				}
			}
		}
	}
	return bw.Flush()
}

// MaxFileBytes bounds what Load reads.
const MaxFileBytes = 64 << 20

// ErrLayout is a saved file from a different version.
var ErrLayout = errors.New("metrics: the saved series are from another version")

// Load replaces the store's series with a saved file's. Series no group
// keeps now, or with other rings than their group's, are left out, and
// so are things past a group's cap (the first by name are kept).
func (s *Store) Load(r io.Reader) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	loaded, items, err := s.read(bufio.NewReader(io.LimitReader(r, MaxFileBytes)))
	if err != nil {
		return err
	}
	s.series = loaded
	for i, g := range s.groups {
		g.items = items[i]
		g.refused = false
	}
	return nil
}

func (s *Store) read(br *bufio.Reader) (map[string]*series, []map[string]int, error) {
	bad := func(what string) error { return fmt.Errorf("metrics: the saved series are damaged (%s)", what) }
	var err error
	get := func(v any) bool {
		if err == nil {
			err = binary.Read(br, binary.LittleEndian, v)
		}
		return err == nil
	}
	magic := make([]byte, len(fileMagic))
	if _, err := io.ReadFull(br, magic); err != nil || string(magic) != fileMagic {
		return nil, nil, bad("not a metrics file")
	}
	var version, count uint32
	if !get(&version) {
		return nil, nil, bad("header")
	}
	if version != fileVersion {
		return nil, nil, ErrLayout
	}
	if !get(&count) {
		return nil, nil, bad("header")
	}
	loaded := map[string]*series{}
	items := make([]map[string]int, len(s.groups))
	for i := range items {
		items[i] = map[string]int{}
	}
	prev := ""
	for range count {
		kl, e := br.ReadByte()
		if e != nil {
			return nil, nil, bad("truncated")
		}
		kb := make([]byte, kl)
		if _, e := io.ReadFull(br, kb); e != nil {
			return nil, nil, bad("truncated")
		}
		k := string(kb)
		if !KeyRE.MatchString(k) || k <= prev {
			return nil, nil, bad("a series' name")
		}
		prev = k
		var last int64
		if !get(&last) {
			return nil, nil, bad("truncated")
		}
		nt, e := br.ReadByte()
		if e != nil {
			return nil, nil, bad("truncated")
		}
		// Kept if a group takes it, with the same rings, under its cap.
		gi, item, keep := s.groupOf(k)
		var tiers []Tier
		if keep {
			tiers = s.groups[gi].Tiers
			keep = int(nt) == len(tiers) && s.groups[gi].room(items[gi][item], len(items[gi]))
		}
		if nt > maxTiers {
			return nil, nil, bad("a series' rings")
		}
		var se *series
		for ti := range int(nt) {
			var step, slots, n uint32
			if !get(&step) || !get(&slots) || !get(&n) {
				return nil, nil, bad("truncated")
			}
			if slots == 0 || slots > maxSlots || n > slots {
				return nil, nil, bad("a ring's size")
			}
			if keep && (time.Duration(step)*time.Second != tiers[ti].Step || int(slots) != tiers[ti].Slots) {
				keep, se = false, nil
			}
			if keep && se == nil {
				se = s.newSeries(gi, item)
				se.last = last
			}
			for range n {
				var i uint32
				var sl slot
				if !get(&i) || !get(&sl.B) || !get(&sl.Sum) || !get(&sl.N) || !get(&sl.Max) {
					return nil, nil, bad("truncated")
				}
				if i >= slots || sl.N == 0 || math.IsNaN(sl.Sum) || math.IsInf(sl.Sum, 0) || math.IsNaN(sl.Max) || math.IsInf(sl.Max, 0) {
					return nil, nil, bad("a bucket")
				}
				if keep {
					se.tiers[ti][i] = sl
				}
			}
		}
		if keep && se != nil {
			loaded[k] = se
			items[gi][item]++
		}
	}
	return loaded, items, nil
}
