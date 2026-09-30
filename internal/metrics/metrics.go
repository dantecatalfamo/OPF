// Package metrics keeps time series of the system's numbers (traffic,
// CPU, pf, DNS) in a fixed amount of memory and disk, like RRD: each
// series has rings of time buckets at a few resolutions, recent ones
// fine and old ones coarse, and a sample goes into every ring at once.
// A ring's buckets are aligned to its step, so a bucket's average is
// exact rather than an average of averages. Nothing grows: a new sample
// replaces the bucket a ring's length ago, and there's a cap on how
// many series there are.
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
)

// Tier is one ring: buckets of Step, Slots of them.
type Tier struct {
	Step  time.Duration
	Slots int
}

// Tiers are every series' rings, finest first: an hour of 10 s, a day
// of minutes, a week of 10 minutes and a month of hours. About 110 KB
// a series.
var Tiers = []Tier{
	{10 * time.Second, 360},
	{time.Minute, 1440},
	{10 * time.Minute, 1008},
	{time.Hour, 24 * 31},
}

// Span is how far back the coarsest ring goes.
func Span() time.Duration {
	t := Tiers[len(Tiers)-1]
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

type series struct {
	Tiers [][]slot
	Last  int64 // unix time of the last sample
}

func newSeries() *series {
	s := &series{Tiers: make([][]slot, len(Tiers))}
	for i, t := range Tiers {
		s.Tiers[i] = make([]slot, t.Slots)
	}
	return s
}

// KeyRE is what a series' name may be: "if.em0.rx", "gw.g1.rtt".
var KeyRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,63}$`)

// Store holds the series. It's safe for concurrent use.
type Store struct {
	mu        sync.Mutex
	series    map[string]*series
	maxSeries int
}

// New returns an empty store that keeps at most maxSeries series.
func New(maxSeries int) *Store {
	return &Store{series: map[string]*series{}, maxSeries: maxSeries}
}

// Add records a sample. It's refused (false) for a name that isn't a
// KeyRE, a value that isn't a number, or a new series past the cap.
func (s *Store) Add(key string, t time.Time, v float64) bool {
	if !KeyRE.MatchString(key) || math.IsNaN(v) || math.IsInf(v, 0) {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	se := s.series[key]
	if se == nil {
		if len(s.series) >= s.maxSeries {
			return false
		}
		se = newSeries()
		s.series[key] = se
	}
	u := t.Unix()
	for i, tier := range Tiers {
		b := u / int64(tier.Step/time.Second)
		sl := &se.Tiers[i][b%int64(tier.Slots)]
		if sl.B != b {
			*sl = slot{B: b, Sum: v, N: 1, Max: v}
			continue
		}
		sl.Sum += v
		sl.N++
		sl.Max = max(sl.Max, v)
	}
	se.Last = max(se.Last, u)
	return true
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
// apart. It reads the finest ring that reaches back to from, and
// merges its buckets when step is coarser than the ring's.
func (s *Store) Query(key string, from, to time.Time, step time.Duration) (*Result, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	se := s.series[key]
	if se == nil || !to.After(from) {
		return nil, false
	}
	now := time.Now()
	ti := len(Tiers) - 1
	for i, t := range Tiers {
		// A ring reaches back its length; a step more is let in so a
		// range of exactly its length (an hour of 10 s) uses it, less
		// its oldest point, which the newest has taken over.
		if t.Step >= step && !from.Before(now.Add(-t.Step*time.Duration(t.Slots+1))) {
			ti = i
			break
		}
	}
	tier := Tiers[ti]
	base := int64(tier.Step / time.Second)
	per := max(1, int64(step/tier.Step)) // ring buckets a point
	if span := to.Unix() - from.Unix(); span/(base*per) > MaxPoints {
		per = (span/MaxPoints + base - 1) / base
	}
	first, last := from.Unix()/base, to.Unix()/base
	first -= first % per
	res := &Result{Start: first * base, Step: base * per}
	ring := se.Tiers[ti]
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

// The saved file: "OPFM", a version, the rings' layout, then each
// series with its name, its last sample and its buckets that aren't
// empty. Every count is checked against the rings' fixed sizes before
// it's used, so a file cut short or damaged is refused rather than
// read into a loop or a huge allocation.
const (
	fileMagic   = "OPFM"
	fileVersion = 1
)

// Save writes every series that has had a sample within Span.
func (s *Store) Save(w io.Writer) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old := time.Now().Add(-Span()).Unix()
	keys := make([]string, 0, len(s.series))
	for k, se := range s.series {
		if se.Last >= old {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	bw := bufio.NewWriter(w)
	put := func(v any) { binary.Write(bw, binary.LittleEndian, v) }
	bw.WriteString(fileMagic)
	put(uint32(fileVersion))
	put(uint32(len(Tiers)))
	for _, t := range Tiers {
		put(uint32(t.Step / time.Second))
		put(uint32(t.Slots))
	}
	put(uint32(len(keys)))
	for _, k := range keys {
		se := s.series[k]
		bw.WriteByte(byte(len(k)))
		bw.WriteString(k)
		put(se.Last)
		for _, ring := range se.Tiers {
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

// ErrLayout is a saved file from a different version or set of rings.
var ErrLayout = errors.New("metrics: the saved series have another layout")

// Load replaces the store's series with a saved file's. Series past the
// cap are left out, the first by name kept.
func (s *Store) Load(r io.Reader) error {
	loaded, err := s.read(bufio.NewReader(io.LimitReader(r, MaxFileBytes)))
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.series = loaded
	s.mu.Unlock()
	return nil
}

func (s *Store) read(br *bufio.Reader) (map[string]*series, error) {
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
		return nil, bad("not a metrics file")
	}
	var version, tiers uint32
	if !get(&version) || !get(&tiers) {
		return nil, bad("header")
	}
	if version != fileVersion || tiers != uint32(len(Tiers)) {
		return nil, ErrLayout
	}
	for _, t := range Tiers {
		var step, slots uint32
		if !get(&step) || !get(&slots) {
			return nil, bad("header")
		}
		if time.Duration(step)*time.Second != t.Step || int(slots) != t.Slots {
			return nil, ErrLayout
		}
	}
	var count uint32
	if !get(&count) {
		return nil, bad("header")
	}
	loaded := map[string]*series{}
	prev := ""
	for range count {
		kl, e := br.ReadByte()
		if e != nil {
			return nil, bad("truncated")
		}
		kb := make([]byte, kl)
		if _, e := io.ReadFull(br, kb); e != nil {
			return nil, bad("truncated")
		}
		k := string(kb)
		if !KeyRE.MatchString(k) || k <= prev {
			return nil, bad("a series' name")
		}
		prev = k
		se := newSeries()
		if !get(&se.Last) {
			return nil, bad("truncated")
		}
		for ti, t := range Tiers {
			var n uint32
			if !get(&n) || n > uint32(t.Slots) {
				return nil, bad("a ring's size")
			}
			for range n {
				var i uint32
				var sl slot
				if !get(&i) || !get(&sl.B) || !get(&sl.Sum) || !get(&sl.N) || !get(&sl.Max) {
					return nil, bad("truncated")
				}
				if i >= uint32(t.Slots) || sl.N == 0 || math.IsNaN(sl.Sum) || math.IsInf(sl.Sum, 0) || math.IsNaN(sl.Max) || math.IsInf(sl.Max, 0) {
					return nil, bad("a bucket")
				}
				se.Tiers[ti][i] = sl
			}
		}
		if len(loaded) < s.maxSeries {
			loaded[k] = se
		}
	}
	return loaded, nil
}
