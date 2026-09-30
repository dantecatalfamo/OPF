package metrics

import (
	"bytes"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"
)

func vals(ps []*float64) []float64 {
	out := make([]float64, len(ps))
	for i, p := range ps {
		if p == nil {
			out[i] = -1
		} else {
			out[i] = *p
		}
	}
	return out
}

func TestAddAndQuery(t *testing.T) {
	s := all(10)
	now := time.Now().Truncate(time.Minute)
	// Two samples a bucket for the last five minutes, 10 s apart: 1, 3.
	start := now.Add(-5 * time.Minute)
	for tt := start; tt.Before(now); tt = tt.Add(5 * time.Second) {
		v := 1.0
		if tt.Unix()%10 >= 5 {
			v = 3
		}
		s.Add("if.em0.rx", tt, v)
	}
	r, ok := s.Query("if.em0.rx", start, now.Add(-time.Second), 10*time.Second)
	if !ok || r.Step != 10 || len(r.Avg) != 30 {
		t.Fatalf("got %+v %v", r, ok)
	}
	for i, v := range vals(r.Avg) {
		if v != 2 || *r.Max[i] != 3 {
			t.Fatalf("point %d: avg %v max %v", i, v, *r.Max[i])
		}
	}
	// A minute a point, from the same ring.
	r, _ = s.Query("if.em0.rx", start, now.Add(-time.Second), time.Minute)
	if r.Step != 60 || len(r.Avg) != 5 || *r.Avg[0] != 2 {
		t.Errorf("minutes: step %d, %v", r.Step, vals(r.Avg))
	}
	// Exactly an hour, as the UI asks for it: still the 10 s ring.
	if r, _ := s.Query("if.em0.rx", time.Now().Add(-time.Hour), time.Now(), 0); r.Step != 10 {
		t.Errorf("an hour: step %d", r.Step)
	}
	// Further back than the 10 s ring reaches: the minute ring.
	r, _ = s.Query("if.em0.rx", now.Add(-3*time.Hour), now, 0)
	if r.Step != 60 || len(r.Avg) != 181 {
		t.Fatalf("3 h: step %d, %d points", r.Step, len(r.Avg))
	}
	if v := vals(r.Avg); v[0] != -1 || v[len(v)-6] != 2 {
		t.Errorf("3 h: gaps where nothing was recorded, then the samples: %v", v[len(v)-8:])
	}
	// A month at most MaxPoints points.
	r, _ = s.Query("if.em0.rx", now.Add(-31*24*time.Hour), now, 0)
	if len(r.Avg) > MaxPoints+1 || r.Step%3600 != 0 {
		t.Errorf("month: step %d, %d points", r.Step, len(r.Avg))
	}
	if _, ok := s.Query("nope", start, now, 0); ok {
		t.Error("a series that isn't there")
	}
}

func TestOldBucketsDontComeBack(t *testing.T) {
	s := all(10)
	now := time.Now()
	// A sample an hour and a bit ago lands in the slot the current one
	// would use in the 10 s ring; it mustn't show up as now.
	s.Add("cpu.busy", now.Add(-time.Duration(FineTiers[0].Slots)*FineTiers[0].Step), 50)
	r, _ := s.Query("cpu.busy", now.Add(-time.Minute), now, 0)
	for _, v := range vals(r.Avg) {
		if v != -1 {
			t.Fatalf("an old sample came back: %v", vals(r.Avg))
		}
	}
}

func TestRefused(t *testing.T) {
	s := all(2)
	now := time.Now()
	for _, bad := range []string{"", "-dash", "a b", "a,b", "../x", "x\x00", string(make([]byte, 70))} {
		if s.Add(bad, now, 1) {
			t.Errorf("took name %q", bad)
		}
	}
	if s.Add("a", now, math.NaN()) || s.Add("a", now, math.Inf(1)) {
		t.Error("took a value that isn't a number")
	}
	if !s.Add("a", now, 1) || !s.Add("b", now, 1) || s.Add("c", now, 1) {
		t.Error("the cap")
	}
	if !s.Add("a", now, 2) {
		t.Error("refused an existing series at the cap")
	}
}

func TestSaveLoad(t *testing.T) {
	s := all(10)
	now := time.Now()
	s.Add("pf.states", now, 42)
	s.Add("dns.queries", now.Add(-2*s.Span()), 1) // older than every ring: not saved
	var buf bytes.Buffer
	if err := s.Save(&buf); err != nil {
		t.Fatal(err)
	}
	l := all(10)
	if err := l.Load(bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatal(err)
	}
	if k := l.Keys(); len(k) != 1 || k[0] != "pf.states" {
		t.Fatalf("keys %v", k)
	}
	r, _ := l.Query("pf.states", now.Add(-time.Minute), now, 0)
	if v := vals(r.Avg); v[len(v)-1] != 42 {
		t.Errorf("got %v", v)
	}
	// A cap lower than what was saved keeps the first ones by name.
	s.Add("a.first", now, 1)
	buf.Reset()
	s.Save(&buf)
	small := all(1)
	small.Load(bytes.NewReader(buf.Bytes()))
	if k := small.Keys(); len(k) != 1 || k[0] != "a.first" {
		t.Errorf("capped load: %v", k)
	}
	if err := all(1).Load(bytes.NewReader([]byte("not a gob"))); err == nil {
		t.Error("read garbage")
	}
}

func FuzzLoad(f *testing.F) {
	s := all(4)
	s.Add("x", time.Now(), 1)
	var buf bytes.Buffer
	s.Save(&buf)
	f.Add(buf.Bytes())
	f.Fuzz(func(t *testing.T, b []byte) {
		l := all(4)
		if l.Load(bytes.NewReader(b)) == nil {
			for _, k := range l.Keys() {
				l.Query(k, time.Now().Add(-time.Hour), time.Now(), 0)
				l.Add(k, time.Now(), 1)
			}
		}
	})
}

// all is a store with one group that takes every key.
func all(n int) *Store {
	return New(Group{Name: "all", Item: func(k string) (string, bool) { return k, true }, Tiers: FineTiers, PerItem: 1, Max: n})
}

// grouped has interfaces (two series each, fine rings) and rules (one
// each, coarse rings).
func grouped(ifaces, rules int) *Store {
	prefix := func(p string) func(string) (string, bool) {
		return func(k string) (string, bool) {
			if !strings.HasPrefix(k, p) {
				return "", false
			}
			if i := strings.LastIndex(k, "."); i > len(p) && p == "if." {
				return k[:i], true
			}
			return k, true
		}
	}
	return New(
		Group{Name: "interfaces", Item: prefix("if."), Tiers: FineTiers, PerItem: 2, Max: ifaces},
		Group{Name: "rules", Item: prefix("pf.rule."), Tiers: CoarseTiers, PerItem: 1, Max: rules},
	)
}

func TestGroups(t *testing.T) {
	s := grouped(2, 3)
	now := time.Now()
	for _, k := range []string{"if.em0.rx", "if.em0.tx", "if.em1.rx", "if.em1.tx"} {
		if !s.Add(k, now, 1) {
			t.Errorf("refused %s", k)
		}
	}
	// A third series for an interface, and a third interface: no room.
	if s.Add("if.em0.extra", now, 1) || s.Add("if.em2.rx", now, 1) {
		t.Error("past the interfaces' limits")
	}
	// Rules have their own room, whatever interfaces use.
	for i := range 3 {
		if !s.Add(fmt.Sprintf("pf.rule.r%d", i), now, 1) {
			t.Errorf("refused rule %d", i)
		}
	}
	if s.Add("pf.rule.r9", now, 1) || s.Add("other", now, 1) {
		t.Error("past the rules' cap, or a key no group takes")
	}
	use := s.Use()
	if use[0].Items != 2 || use[0].Series != 4 || !use[0].Refused || use[1].Items != 3 || use[1].SeriesBytes >= use[0].SeriesBytes {
		t.Errorf("use %+v", use)
	}
	// Rules keep coarse rings: an hour comes back in 10-minute points.
	if r, _ := s.Query("pf.rule.r0", now.Add(-time.Hour), now, 0); r.Step != 600 {
		t.Errorf("rule step %d", r.Step)
	}

	// Lowering a cap forgets what was updated least recently.
	s.Add("pf.rule.r0", now.Add(time.Minute), 2)
	s.SetMax("rules", 1)
	if k := s.Keys(); len(k) != 5 || k[4] != "pf.rule.r0" {
		t.Errorf("after lowering: %v", k)
	}
	// Raising it lets new ones in again.
	s.SetMax("rules", 5)
	if !s.Add("pf.rule.r7", now, 1) || s.Use()[1].Refused {
		t.Error("raised cap")
	}
}

func TestLoadKeepsGroupsRings(t *testing.T) {
	s := grouped(4, 4)
	now := time.Now()
	s.Add("if.em0.rx", now, 1)
	s.Add("pf.rule.r1", now, 1)
	var buf bytes.Buffer
	if err := s.Save(&buf); err != nil {
		t.Fatal(err)
	}
	// A newer OPF keeping rules in fine rings drops the old rule series,
	// not the file.
	l := New(
		Group{Name: "interfaces", Item: func(k string) (string, bool) { return k[:7], strings.HasPrefix(k, "if.") }, Tiers: FineTiers, PerItem: 2, Max: 4},
		Group{Name: "rules", Item: func(k string) (string, bool) { return k, strings.HasPrefix(k, "pf.rule.") }, Tiers: FineTiers, PerItem: 1, Max: 4},
	)
	if err := l.Load(bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatal(err)
	}
	if k := l.Keys(); len(k) != 1 || k[0] != "if.em0.rx" {
		t.Errorf("keys %v", k)
	}
	if u := l.Use(); u[0].Items != 1 || u[1].Items != 0 {
		t.Errorf("use %+v", u)
	}
	// And the cap holds when loading: one interface kept of two.
	s.Add("if.em1.rx", now, 1)
	buf.Reset()
	s.Save(&buf)
	one := grouped(1, 4)
	one.Load(bytes.NewReader(buf.Bytes()))
	if u := one.Use(); u[0].Items != 1 || u[0].Series != 1 {
		t.Errorf("capped load %+v", u)
	}
}
