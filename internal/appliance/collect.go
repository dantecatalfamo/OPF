package appliance

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/dantecatalfamo/OPF/internal/metrics"
	"github.com/dantecatalfamo/OPF/internal/pf"
	"github.com/dantecatalfamo/OPF/internal/sysinfo"
)

// The collector: every CollectInterval it reads what the pages show
// now (the same commands and parsers) and keeps it as time series
// (package metrics), so the pages can show it over hours and days.
// Counters are kept as rates. A counter that went backwards (pf or
// unbound reloaded, the machine restarted) or a gap longer than a few
// intervals gives no rate rather than a spike; the next sample starts
// over. Series are saved in the state directory every saveEvery and
// when OPF stops.

// CollectInterval is how often the collector samples.
const CollectInterval = 10 * time.Second

const (
	// gatewayEvery: gateways are pinged less often than the rest.
	gatewayEvery = 30 * time.Second
	saveEvery    = 5 * time.Minute
	metricsFile  = "metrics.bin"
)

// Series' names. Interfaces and gateways are by device and id.
const (
	SeriesCPU         = "cpu.busy"    // percent
	SeriesMemory      = "mem.used"    // bytes
	SeriesLoad        = "load.1"      // one-minute load average
	SeriesPfStates    = "pf.states"   // states
	SeriesPfBlocked   = "pf.blocked"  // packets a second, statistics interface
	SeriesDNSQueries  = "dns.queries" // a second
	SeriesDNSBlocked  = "dns.blocked" // a second
	SeriesDNSCacheHit = "dns.cachehit"
	SeriesTimeOffset  = "time.offset" // ms from the peer ntpd follows
)

func ifaceSeries(dev, dir string) string   { return "if." + dev + "." + dir } // bits a second, rx or tx
func gatewaySeries(id, what string) string { return "gw." + id + "." + what } // rtt (ms) or loss (percent)

// peerSeries is a WireGuard peer's rx or tx (bits a second) or
// handshake (seconds since); ruleSeries a labelled rule's packets a
// second (pf.rule.R12, pf.builtin.anti-lockout); dhcpSeries a network's
// leases in use.
func peerSeries(id, what string) string { return "wg." + id + "." + what }
func ruleSeries(kind, id string) string { return "pf." + kind + "." + id }
func dhcpSeries(iface string) string    { return "dhcp." + iface + ".leases" }

// pseudoIface is an interface whose traffic isn't worth a series:
// loopback, IPsec's enc and pflog's copies of logged packets.
func pseudoIface(name string) bool {
	for _, p := range []string{"lo", "enc", "pflog", "pfsync"} {
		if rest, ok := strings.CutPrefix(name, p); ok && rest != "" && strings.Trim(rest, "0123456789") == "" {
			return true
		}
	}
	return false
}

// The graphs' groups: each kind of thing has its own cap, so a firewall
// with a thousand rules doesn't crowd out its interfaces. Caps count
// things (an interface is two series, in and out); the model can change
// them (system.graphs), at the cost of memory, which Metrics reports.
const (
	GroupSystem     = "system"
	GroupInterfaces = "interfaces"
	GroupGateways   = "gateways"
	GroupVPN        = "vpnDevices"
	GroupDHCP       = "dhcpNetworks"
	GroupRules      = "rules"
)

// groupWords are the groups as a sentence says them.
var groupWords = map[string]string{
	GroupSystem: "system graphs", GroupInterfaces: "interfaces", GroupGateways: "gateways",
	GroupVPN: "VPN devices", GroupDHCP: "DHCP networks", GroupRules: "firewall rules",
}

// GraphDefaults are the caps when the model doesn't set them: at most
// about 70 MB in all, and far less for a typical firewall.
var GraphDefaults = map[string]int{
	GroupInterfaces: 32,
	GroupGateways:   16,
	GroupVPN:        64,
	GroupDHCP:       32,
	GroupRules:      500,
}

// systemSeries are the fixed series: one of each, whatever the model.
var systemSeries = map[string]bool{
	SeriesCPU: true, SeriesMemory: true, SeriesLoad: true, SeriesPfStates: true, SeriesPfBlocked: true,
	SeriesDNSQueries: true, SeriesDNSBlocked: true, SeriesDNSCacheHit: true, SeriesTimeOffset: true,
}

// under takes the keys "<prefix><id>.<what>" and says their thing is
// "<prefix><id>".
func under(prefix string) func(string) (string, bool) {
	return func(k string) (string, bool) {
		rest, ok := strings.CutPrefix(k, prefix)
		i := strings.LastIndex(rest, ".")
		if !ok || i <= 0 {
			return "", false
		}
		return prefix + rest[:i], true
	}
}

func graphGroups() []metrics.Group {
	return []metrics.Group{
		{Name: GroupSystem, Item: func(k string) (string, bool) { return k, systemSeries[k] }, Tiers: metrics.FineTiers, PerItem: 1, Max: len(systemSeries)},
		{Name: GroupInterfaces, Item: under("if."), Tiers: metrics.FineTiers, PerItem: 2, Max: GraphDefaults[GroupInterfaces]},
		{Name: GroupGateways, Item: under("gw."), Tiers: metrics.FineTiers, PerItem: 2, Max: GraphDefaults[GroupGateways]},
		{Name: GroupVPN, Item: under("wg."), Tiers: metrics.FineTiers, PerItem: 3, Max: GraphDefaults[GroupVPN]},
		{Name: GroupDHCP, Item: under("dhcp."), Tiers: metrics.FineTiers, PerItem: 1, Max: GraphDefaults[GroupDHCP]},
		// Rules are many, sampled every 30 s and mostly graphed small:
		// coarse rings, half the memory. pf.<kind>.<id>, one each.
		{Name: GroupRules, Item: func(k string) (string, bool) {
			rest, ok := strings.CutPrefix(k, "pf.")
			return k, ok && strings.Count(rest, ".") == 1
		}, Tiers: metrics.CoarseTiers, PerItem: 1, Max: GraphDefaults[GroupRules]},
	}
}

// graphLimits are the caps the model asks for, the defaults for the
// rest.
func graphLimits(m *pf.Model) map[string]int {
	out := map[string]int{}
	for k, v := range GraphDefaults {
		out[k] = v
	}
	if m == nil || m.System.Graphs == nil {
		return out
	}
	g := m.System.Graphs
	for name, n := range map[string]*int{GroupInterfaces: g.Interfaces, GroupGateways: g.Gateways, GroupVPN: g.VPNDevices, GroupDHCP: g.DHCPNetworks, GroupRules: g.Rules} {
		if n != nil {
			out[name] = *n
		}
	}
	return out
}

func (m *Manager) applyGraphLimits(model *pf.Model) {
	st := m.metricsStore()
	for name, n := range graphLimits(model) {
		st.SetMax(name, n)
	}
}

// collector is the collector's state: the store and the last reading
// of each counter.
type collector struct {
	store *metrics.Store
	prev  map[string]reading
	cpu   sysinfo.CPUTicks
	cpuAt time.Time
	gwAt  time.Time
	full  map[string]bool // groups the log has said are full
	watch *watch          // what the last sample saw, for events (eventwatch.go)
}

// add stores a point, and says once a group in the log when something
// new was turned away because the group keeps as many as it may.
func (c *collector) add(key string, t time.Time, v float64) {
	if c.store.Add(key, t, v) {
		return
	}
	for _, u := range c.store.Use() {
		if u.Refused && !c.full[u.Name] {
			c.full[u.Name] = true
			log.Printf("graphs: the %s kept are at their cap (%d); %s and any more aren't recorded (System › General raises it)", groupWords[u.Name], u.Max, key)
		}
	}
}

type reading struct {
	v float64
	t time.Time
}

func (m *Manager) metricsStore() *metrics.Store {
	m.collectOnce.Do(func() {
		m.collect = &collector{store: metrics.New(graphGroups()...), prev: map[string]reading{}, full: map[string]bool{}, watch: newWatch()}
	})
	return m.collect.store
}

// MetricsStore is the series, for the mock to fill with history.
func (m *Manager) MetricsStore() *metrics.Store { return m.metricsStore() }

// rate is how fast a counter grew since its last reading, if there's
// one close enough in time and it didn't go backwards.
func (c *collector) rate(key string, v float64, t time.Time) (float64, bool) {
	p, ok := c.prev[key]
	c.prev[key] = reading{v, t}
	dt := t.Sub(p.t).Seconds()
	if !ok || v < p.v || dt <= 0 || dt > (4*CollectInterval).Seconds() {
		return 0, false
	}
	return (v - p.v) / dt, true
}

func (c *collector) addRate(key string, v float64, t time.Time, scale float64) {
	if r, ok := c.rate(key, v, t); ok {
		c.add(key, t, r*scale)
	}
}

// RunCollector samples until ctx is done, loading the saved series
// first. SaveMetrics saves them; call it when OPF stops.
func (m *Manager) RunCollector(ctx context.Context) {
	st := m.metricsStore()
	// The caps first, so loading keeps no more than they allow.
	if model, _, err := m.live(); err == nil {
		m.applyGraphLimits(model)
	}
	path := m.store.StatePath(metricsFile)
	if f, err := os.Open(path); err == nil {
		if err := st.Load(f); err != nil {
			log.Printf("starting the graphs over: %v", err)
		}
		f.Close()
	}
	m.loadEvents()
	m.eventLog().record(Event{Time: time.Now(), Kind: EventOPF, Message: "OPF started"})
	tick := time.NewTicker(CollectInterval)
	defer tick.Stop()
	lastSave := time.Now()
	m.sample(time.Now())
	for {
		select {
		case <-ctx.Done():
			return
		case t := <-tick.C:
			m.sample(t)
			if time.Since(lastSave) >= saveEvery {
				if err := m.SaveMetrics(); err != nil {
					log.Printf("saving the graphs: %v", err)
				}
				lastSave = time.Now()
			}
		}
	}
}

// SaveMetrics writes the series, the event log and the DNS activity to
// the state directory, replacing each last copy only once the new one
// is complete.
func (m *Manager) SaveMetrics() error {
	if err := m.saveEvents(); err != nil {
		log.Printf("saving the event log: %v", err)
	}
	if err := m.SaveDNSActivity(); err != nil {
		log.Printf("saving the DNS activity: %v", err)
	}
	if err := m.SaveTraffic(); err != nil {
		log.Printf("saving the traffic: %v", err)
	}
	path := m.store.StatePath(metricsFile)
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+metricsFile+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := m.metricsStore().Save(tmp); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// sample reads everything once. A command that fails leaves its series
// without a point.
func (m *Manager) sample(now time.Time) {
	m.metricsStore()
	c := m.collect
	model, _, _ := m.live()
	m.applyGraphLimits(model) // a commit may have changed them
	m.readDNSActivity(model, now)
	m.readTraffic(model, now)
	m.applySystemDNS(model) // resolvd forgets it when it restarts

	// Interfaces: bits a second in and out.
	if b, err := m.read("netstat", "-ibn"); err == nil {
		if p, err := m.read("netstat", "-in"); err == nil {
			t := time.Now()
			for dev, cn := range sysinfo.ParseNetstatIfaces(b, p) {
				if pseudoIface(dev) {
					continue
				}
				c.addRate(ifaceSeries(dev, "rx"), float64(cn.RxBytes), t, 8)
				c.addRate(ifaceSeries(dev, "tx"), float64(cn.TxBytes), t, 8)
			}
		}
	}

	// CPU, memory and load.
	if out, err := m.read("sysctl", "kern.cp_time", "vm.loadavg", "hw.physmem"); err == nil {
		t := time.Now()
		vals := sysinfo.ParseSysctl(out)
		if ticks, err := sysinfo.ParseCPUTicks(vals["kern.cp_time"]); err == nil {
			if p, ok := c.cpuPrev(ticks); ok {
				if u, ok := ticks.Usage(p); ok {
					c.add(SeriesCPU, t, u.Busy())
				}
			}
		}
		if l, err := sysinfo.ParseLoadavg(vals["vm.loadavg"]); err == nil {
			c.add(SeriesLoad, t, l[0])
		}
		physmem, _ := strconv.ParseUint(vals["hw.physmem"], 10, 64)
		if out, err := m.read("vmstat", "-s"); err == nil {
			if mem, err := sysinfo.ParseVmstatMemory(out, physmem); err == nil && mem.Total >= mem.Free {
				c.add(SeriesMemory, time.Now(), float64(mem.Total-mem.Free))
			}
		}
	}

	// pf: states, and packets blocked on the statistics interface.
	if out, err := m.read("pfctl", "-v", "-s", "info"); err == nil {
		if info, ok := sysinfo.ParsePfInfo(out); ok {
			t := time.Now()
			c.add(SeriesPfStates, t, float64(info.States))
			if i := info.Iface; i != nil {
				// The counter is the interface's, so a new statistics
				// interface starts over rather than looking like a jump.
				if r, ok := c.rate("pf.blocked@"+i.Name, float64(i.PacketsInBlocked+i.PacketsOutBlocked), t); ok {
					c.add(SeriesPfBlocked, t, r)
				}
			}
		}
	}

	// DNS, when the resolver runs.
	if model != nil && model.DNS.Enabled {
		if out, err := m.read("unbound-control", "-c", unboundConf, "stats_noreset"); err == nil {
			if s, ok := sysinfo.ParseUnboundStats(out); ok {
				t := time.Now()
				// unbound's counters start again when it reloads: uptime
				// going backwards says so even when the counts don't.
				if p, ok := c.prev["dns.uptime"]; ok && s.Uptime < p.v {
					for _, k := range []string{SeriesDNSQueries, SeriesDNSBlocked, "dns.hits", "dns.misses"} {
						delete(c.prev, k)
					}
				}
				c.prev["dns.uptime"] = reading{s.Uptime, t}
				c.addRate(SeriesDNSQueries, float64(s.Queries), t, 1)
				c.addRate(SeriesDNSBlocked, float64(s.Blocked()), t, 1)
				h, hok := c.rate("dns.hits", float64(s.CacheHits), t)
				mi, mok := c.rate("dns.misses", float64(s.CacheMisses), t)
				if hok && mok && h+mi > 0 {
					c.add(SeriesDNSCacheHit, t, 100*h/(h+mi))
				}
			}
		}
	}

	// Interfaces' links and addresses, for events, and WireGuard peers
	// by the model's ids: traffic and how long since the last handshake
	// (a site link that's quietly down).
	if model != nil {
		if out, err := m.read("ifconfig", "-A"); err == nil {
			t := time.Now()
			ids := tunnelPeers(model)
			ifs := sysinfo.ParseIfconfig(out)
			m.watchInterfaces(model, ifs, t)
			for _, i := range ifs {
				if i.WireGuard == nil {
					continue
				}
				for _, p := range i.WireGuard.Peers {
					id, ok := ids[p.PublicKey]
					if !ok {
						continue
					}
					c.addRate(peerSeries(id, "rx"), float64(p.RxBytes), t, 8)
					c.addRate(peerSeries(id, "tx"), float64(p.TxBytes), t, 8)
					if p.HandshakeAgo != nil {
						c.add(peerSeries(id, "handshake"), t, float64(*p.HandshakeAgo))
					}
				}
			}
		}
	}

	// Less often: gateways (each is a ping), rules' counters, DHCP
	// leases and the clock.
	if now.Sub(c.gwAt) >= gatewayEvery {
		c.gwAt = now
		m.sampleSlow(c)
	}
	// The first sample is how things are; from the next, changes are
	// events.
	c.watch.started = true
}

func (m *Manager) sampleSlow(c *collector) {
	if out, err := m.read("pfctl", "-vv", "-s", "rules"); err == nil {
		t := time.Now()
		packets := map[string]uint64{}
		for _, r := range sysinfo.ParsePfRules(out) {
			if kind, id, ok := pf.ParseLabel(r.Label); ok {
				packets[ruleSeries(kind, id)] += r.Packets
			}
		}
		// A ruleset reload zeroes the counters; rate starts over.
		for k, n := range packets {
			c.addRate(k, float64(n), t, 1)
		}
	}
	if l, err := m.DHCPLeases(); err == nil && l.Error == "" {
		t := time.Now()
		inUse := map[string]int{}
		if model, _, err := m.live(); err == nil && model != nil {
			for _, s := range model.DHCP {
				if s.Enabled {
					inUse[s.Iface] = 0
				}
			}
		}
		for _, le := range l.Leases {
			if _, ok := inUse[le.Iface]; ok && (le.Ends == nil || le.Ends.After(t)) {
				inUse[le.Iface]++
			}
		}
		for iface, n := range inUse {
			c.add(dhcpSeries(iface), t, float64(n))
		}
	}
	if out, err := m.read("ntpctl", "-s", "all"); err == nil {
		if ts, ok := sysinfo.ParseNtpctl(out); ok && ts.OffsetMs != nil {
			c.add(SeriesTimeOffset, time.Now(), *ts.OffsetMs)
		}
	}
	gws, err := m.Gateways()
	if err == nil {
		t := time.Now()
		for id, h := range gws.Gateways {
			if h.Error != "" && h.Address == "" {
				continue // nothing to ping yet
			}
			c.add(gatewaySeries(id, "loss"), t, h.LossPct)
			if h.RttMs != nil {
				c.add(gatewaySeries(id, "rtt"), t, *h.RttMs)
			}
		}
	}
	model, _, _ := m.live()
	m.watchSlow(model, gws, time.Now())
}

// cpuPrev swaps in the latest CPU ticks and returns the previous ones,
// if they're recent enough.
func (c *collector) cpuPrev(t sysinfo.CPUTicks) (sysinfo.CPUTicks, bool) {
	p, at := c.cpu, c.cpuAt
	c.cpu, c.cpuAt = t, time.Now()
	return p, !at.IsZero() && time.Since(at) <= 4*CollectInterval
}

// MetricsRequest asks for series over the last Range seconds.
type MetricsRequest struct {
	Series []string `json:"series"`
	// Range is how far back, in seconds; Step, if set, the least time
	// between points.
	Range int `json:"range"`
	Step  int `json:"step,omitempty"`
}

// MaxMetricsSeries bounds the series one request asks for.
const MaxMetricsSeries = 32

// Metrics are the series asked for, by name (a series with nothing
// recorded yet is left out), the names of every series kept, and how
// full each group is.
type Metrics struct {
	Series map[string]*metrics.Result `json:"series"`
	Known  []string                   `json:"known"`
	Groups []GraphGroup               `json:"groups"`
}

// GraphGroup is a group's use, its default cap, and what one of its
// things takes in memory (ItemBytes: its series together).
type GraphGroup struct {
	metrics.GroupUse
	Default   int `json:"default,omitempty"` // absent for the fixed system group
	ItemBytes int `json:"itemBytes"`
}

func (m *Manager) graphUse() []GraphGroup {
	per := map[string]int{}
	for _, g := range graphGroups() {
		per[g.Name] = g.PerItem
	}
	var out []GraphGroup
	for _, u := range m.metricsStore().Use() {
		out = append(out, GraphGroup{GroupUse: u, Default: GraphDefaults[u.Name], ItemBytes: u.SeriesBytes * per[u.Name]})
	}
	return out
}

// Metrics returns series over a time range.
func (m *Manager) Metrics(req MetricsRequest) (*Metrics, error) {
	if len(req.Series) > MaxMetricsSeries {
		return nil, errorf(CodeInvalid, "ask for at most %d series at once", MaxMetricsSeries)
	}
	st := m.metricsStore()
	span := st.Span()
	if req.Range <= 0 || time.Duration(req.Range)*time.Second > span {
		return nil, errorf(CodeInvalid, "range: 1 to %d seconds", int(span.Seconds()))
	}
	if req.Step < 0 || req.Step > req.Range {
		return nil, errorf(CodeInvalid, "step: 0 to the range")
	}
	res := &Metrics{Series: map[string]*metrics.Result{}, Known: st.Keys(), Groups: m.graphUse()}
	to := time.Now()
	from := to.Add(-time.Duration(req.Range) * time.Second)
	for _, k := range req.Series {
		if !metrics.KeyRE.MatchString(k) {
			return nil, errorf(CodeInvalid, "%q isn't a series name", printable(k, 70))
		}
		if r, ok := st.Query(k, from, to, time.Duration(req.Step)*time.Second); ok {
			res.Series[k] = r
		}
	}
	return res, nil
}

// tunnelPeers maps the model's WireGuard peers' public keys to their ids.
func tunnelPeers(m *pf.Model) map[string]string {
	ids := map[string]string{}
	for _, i := range m.Interfaces {
		if i.WireGuard != nil {
			for _, p := range i.WireGuard.Peers {
				ids[p.PublicKey] = p.ID
			}
		}
	}
	return ids
}
