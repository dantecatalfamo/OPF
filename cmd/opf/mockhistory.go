package main

import (
	"hash/fnv"
	"math"
	"strings"
	"time"

	"github.com/dantecatalfamo/OPF/internal/appliance"
	"github.com/dantecatalfamo/OPF/internal/metrics"
	"github.com/dantecatalfamo/OPF/internal/pf"
)

// seedHistory gives the mock a month of graphs before it started, at
// the levels the mock's live numbers run at, busier in the evening
// than at night, with an afternoon three days ago when the internet
// went down for twenty minutes. Each span is sampled at its ring's
// resolution: every 10 s for the last hour, every minute for the day,
// and so on.
func seedHistory(st *metrics.Store, m *pf.Model, now time.Time) {
	type level struct {
		key   string
		v     float64
		daily bool // follows the day
	}
	var ls []level
	for _, i := range m.Interfaces {
		if !i.Enabled {
			continue
		}
		rx, tx := mockTraffic(i)
		ls = append(ls, level{"if." + i.Device + ".rx", rx * 8, true}, level{"if." + i.Device + ".tx", tx * 8, true})
	}
	ls = append(ls,
		level{appliance.SeriesCPU, 15, true},
		level{appliance.SeriesMemory, 1.6e9, false},
		level{appliance.SeriesLoad, 0.3, true},
		level{appliance.SeriesPfStates, 70, true},
		level{appliance.SeriesPfBlocked, 4, false},
	)
	if m.DNS.Enabled {
		ls = append(ls, level{appliance.SeriesDNSQueries, 24, true}, level{appliance.SeriesDNSCacheHit, 78, false})
		if _, blocking := mockBlocking(m); blocking {
			ls = append(ls, level{appliance.SeriesDNSBlocked, 24 * mockBlockShare, true})
		}
	}
	for _, g := range m.Routing.Gateways {
		rtt := 23.1
		if strings.HasPrefix(g.Address, "203.0.113.") { // as mockPing answers
			rtt = 8.4
		}
		ls = append(ls, level{"gw." + g.ID + ".rtt", rtt, false}, level{"gw." + g.ID + ".loss", 0, false})
	}

	down := now.Add(-3 * 24 * time.Hour).Truncate(24 * time.Hour).Add(15 * time.Hour)
	spans := []struct{ back, step time.Duration }{
		{31 * 24 * time.Hour, time.Hour}, {7 * 24 * time.Hour, 10 * time.Minute}, {24 * time.Hour, time.Minute}, {time.Hour, 10 * time.Second},
	}
	for si, sp := range spans {
		end := now
		if si+1 < len(spans) {
			end = now.Add(-spans[si+1].back)
		}
		for t := now.Add(-sp.back).Truncate(sp.step); t.Before(end); t = t.Add(sp.step) {
			outage := !t.Before(down) && t.Before(down.Add(20*time.Minute))
			for _, l := range ls {
				v := l.v * noise(l.key, t)
				if l.daily {
					// Busiest at 9 pm, quietest at 9 am, and the level
					// the live numbers run at now, so the two meet.
					v *= daily(t) / daily(now)
				}
				switch {
				case outage && strings.HasSuffix(l.key, ".loss"):
					v = 100
				case outage && (strings.HasPrefix(l.key, "if.") || strings.HasSuffix(l.key, ".rtt") || strings.HasPrefix(l.key, "dns.")):
					continue // nothing answered
				case strings.HasSuffix(l.key, ".loss"):
					v = 0
					if jitter(l.key, t) > 0.995 {
						v = 33.3 // a ping lost now and then
					}
				}
				st.Add(l.key, t, v)
			}
		}
	}
}

func daily(t time.Time) float64 {
	h := float64(t.Hour()) + float64(t.Minute())/60
	return 1 + 0.35*math.Sin(2*math.Pi*(h-15)/24)
}

// noise wobbles around 1 for a series: slow swings of a few percent
// and a little jitter, the same each run.
func noise(key string, t time.Time) float64 {
	h := fnv.New32a()
	h.Write([]byte(key))
	p := float64(h.Sum32()%1000) / 1000 * 2 * math.Pi
	s := float64(t.Unix())
	return 1 + 0.08*math.Sin(s/1900+p) + 0.05*math.Sin(s/310+2*p) + 0.06*(jitter(key, t)-0.5)
}

// jitter is 0 to 1, a different one for each series and time.
func jitter(key string, t time.Time) float64 {
	h := fnv.New32a()
	h.Write([]byte(key))
	h.Write([]byte(t.Format(time.RFC3339)))
	return float64(h.Sum32()%1000) / 1000
}
