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
// leases is how many DHCP leases each network has now.
func seedHistory(st *metrics.Store, m *pf.Model, leases map[string]int, now time.Time) {
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
	for _, i := range m.Interfaces {
		if i.WireGuard == nil || !i.Enabled {
			continue
		}
		// As mockIfconfig has them: the first device online, carrying
		// all of the tunnel's traffic; the others idle, the last never
		// connected.
		in, out := mockTraffic(i)
		for k, p := range i.WireGuard.Peers {
			switch {
			case k == 0:
				ls = append(ls, level{"wg." + p.ID + ".rx", in * 8, true}, level{"wg." + p.ID + ".tx", out * 8, true}, level{"wg." + p.ID + ".handshake", 60, false})
			case k < len(i.WireGuard.Peers)-1:
				ls = append(ls, level{"wg." + p.ID + ".rx", 0, false}, level{"wg." + p.ID + ".tx", 0, false})
			}
		}
	}
	// Rules match at the rates mockPf counts them at.
	rules := map[string]float64{}
	for _, r := range mockRules(m) {
		if kind, id, ok := pf.ParseLabel(r.label); ok {
			k := float64(seed(r.label+r.text)%1000) / 1000
			rules["pf."+kind+"."+id] += 400 * k * k
		}
	}
	for key, v := range rules {
		ls = append(ls, level{key, v, true})
	}
	for iface, n := range leases {
		ls = append(ls, level{"dhcp." + iface + ".leases", float64(n), false})
	}
	ls = append(ls, level{appliance.SeriesTimeOffset, 0.4, false})
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
				case strings.HasPrefix(l.key, "dhcp."):
					v = math.Round(l.v * noise(l.key, t)) // whole leases
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

// seedEvents gives the mock's event log what its graphs show: the
// afternoon three days ago when the internet went down, and the odd
// thing since.
func seedEvents(api *appliance.Manager, m *pf.Model, now time.Time) {
	down := now.Add(-3 * 24 * time.Hour).Truncate(24 * time.Hour).Add(15 * time.Hour)
	var es []appliance.Event
	add := func(t time.Time, kind, subject, msg string, warn bool) {
		es = append(es, appliance.Event{Time: t, Kind: kind, Subject: subject, Message: msg, Warning: warn})
	}
	add(now.Add(-6*24*time.Hour), appliance.EventOPF, "", "OPF started", false)
	for _, g := range m.Routing.Gateways {
		if strings.HasPrefix(g.Address, "203.0.113.") || g.Address == "dhcp" {
			add(down.Add(40*time.Second), appliance.EventGateway, g.ID, "Gateway "+g.Name+" stopped answering (9.9.9.9)", true)
			add(down.Add(20*time.Minute+30*time.Second), appliance.EventGateway, g.ID, "Gateway "+g.Name+" is answering again", false)
		}
	}
	for _, i := range m.Interfaces {
		if i.Role == pf.RoleWAN {
			add(down.Add(21*time.Minute), appliance.EventAddress, i.ID, i.Name+" ("+i.Device+") has a new address from DHCP: 203.0.113.24 (was 203.0.113.61)", false)
		}
	}
	add(now.Add(-26*time.Hour), appliance.EventDevice, "8c:85:90:4b:77:02", "New device 8c:85:90:4b:77:02 at 192.168.1.131 on LAN (calls itself “reception-pc”)", false)
	add(now.Add(-2*24*time.Hour-3*time.Hour), appliance.EventVPN, "p1", "Priya phone (Remote access) connected from 198.51.100.70 (was 192.0.2.44)", false)
	add(now.Add(-9*time.Hour), appliance.EventList, "blocklist", "Couldn't download the list for alias blocklist: ftp: connect: Connection timed out", true)
	add(now.Add(-9*time.Hour+time.Hour), appliance.EventList, "blocklist", "Downloaded the list for alias blocklist again", false)
	api.SeedEvents(es)
}
