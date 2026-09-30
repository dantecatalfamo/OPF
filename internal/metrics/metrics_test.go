package metrics

import (
	"bytes"
	"math"
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
	s := New(10)
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
	s := New(10)
	now := time.Now()
	// A sample an hour and a bit ago lands in the slot the current one
	// would use in the 10 s ring; it mustn't show up as now.
	s.Add("cpu.busy", now.Add(-time.Duration(Tiers[0].Slots)*Tiers[0].Step), 50)
	r, _ := s.Query("cpu.busy", now.Add(-time.Minute), now, 0)
	for _, v := range vals(r.Avg) {
		if v != -1 {
			t.Fatalf("an old sample came back: %v", vals(r.Avg))
		}
	}
}

func TestRefused(t *testing.T) {
	s := New(2)
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
	s := New(10)
	now := time.Now()
	s.Add("pf.states", now, 42)
	s.Add("dns.queries", now.Add(-2*Span()), 1) // older than every ring: not saved
	var buf bytes.Buffer
	if err := s.Save(&buf); err != nil {
		t.Fatal(err)
	}
	l := New(10)
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
	small := New(1)
	small.Load(bytes.NewReader(buf.Bytes()))
	if k := small.Keys(); len(k) != 1 || k[0] != "a.first" {
		t.Errorf("capped load: %v", k)
	}
	if err := New(1).Load(bytes.NewReader([]byte("not a gob"))); err == nil {
		t.Error("read garbage")
	}
}

func FuzzLoad(f *testing.F) {
	s := New(4)
	s.Add("x", time.Now(), 1)
	var buf bytes.Buffer
	s.Save(&buf)
	f.Add(buf.Bytes())
	f.Fuzz(func(t *testing.T, b []byte) {
		l := New(4)
		if l.Load(bytes.NewReader(b)) == nil {
			for _, k := range l.Keys() {
				l.Query(k, time.Now().Add(-time.Hour), time.Now(), 0)
				l.Add(k, time.Now(), 1)
			}
		}
	})
}
