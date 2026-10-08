package appliance

import (
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/dantecatalfamo/OPF/internal/activity"
	"github.com/dantecatalfamo/OPF/internal/pf"
	"github.com/dantecatalfamo/OPF/internal/sysinfo"
)

// System › Storage: everything that fills up as the firewall runs,
// what it holds now and the most it can: OPF's own records, pf's tables
// in the kernel, the logs OPF reads, and the disk they're on.

// StorageItem is one thing that fills up.
type StorageItem struct {
	ID    string `json:"id"`
	Group string `json:"group"` // StorageOPF, StoragePf, StorageLogs, StorageDisk
	Name  string `json:"name"`
	Desc  string `json:"desc"`
	// Unit is "bytes" or "entries".
	Unit string `json:"unit"`
	// Where it's kept: "memory", "disk" or "kernel".
	Where string `json:"where"`
	// Current is what it holds now; nil when it couldn't be read, or
	// it's off (Off).
	Current *int64 `json:"current,omitempty"`
	// Max is the most it can hold; nil when nothing limits it (Unbounded
	// says what then).
	Max       *int64 `json:"max,omitempty"`
	Unbounded string `json:"unbounded,omitempty"`
	// Note says more: how the most is reached, what happens then.
	Note string `json:"note,omitempty"`
	Off  bool   `json:"off,omitempty"`
	// Link is the UI page that shows what it holds.
	Link string `json:"link,omitempty"`
	// Settings are where its limit, or what fills it, is set; Fixed
	// says why there's nowhere when there isn't.
	Settings []StorageLink `json:"settings,omitempty"`
	Fixed    string        `json:"fixed,omitempty"`
}

// StorageLink is a UI page, and a card on it (#id), with its name.
type StorageLink struct {
	Label string `json:"label"`
	To    string `json:"to"`
}

// Where the settings are.
var (
	setGraphs      = StorageLink{"System › General › Graphs", "/system/general#graphs"}
	setTraffic     = StorageLink{"Firewall › Settings › Traffic per device", "/firewall/settings#traffic"}
	setActivity    = StorageLink{"DNS resolver › Settings › Activity", "/services/dns?tab=settings#activity"}
	setBlocklists  = StorageLink{"DNS resolver › Blocking", "/services/dns?tab=blocking"}
	setAliases     = StorageLink{"Firewall › Aliases", "/firewall/aliases"}
	setMaxStates   = StorageLink{"Firewall › Settings › Connection tracking", "/firewall/settings#connections"}
	setPfLimits    = StorageLink{"Firewall › Settings › Limits", "/firewall/settings#limits"}
	setLogBlocked  = StorageLink{"Firewall › Settings › Blocking", "/firewall/settings#blocking"}
	setRules       = StorageLink{"Firewall › Rules (each rule’s log)", "/firewall/rules"}
	newsyslogFixed = "Rotated by newsyslog, set in /etc/newsyslog.conf, which OPF doesn’t manage."
)

const (
	StorageOPF    = "opf"
	StorageGraphs = "graphs"
	StoragePf     = "pf"
	StorageLogs   = "logs"
	StorageDisk   = "disk"
)

// Storage is every StorageItem, and what couldn't be read.
type Storage struct {
	Items  []StorageItem `json:"items"`
	Errors []string      `json:"errors"`
}

func ptr(n int64) *int64 { return &n }

// treeSize is the bytes of the files under dir, and how many there are.
func treeSize(dir string) (bytes, files int64) {
	filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			if fi, err := d.Info(); err == nil {
				bytes += fi.Size()
				files++
			}
		}
		return nil
	})
	return bytes, files
}

func fileSize(path string) *int64 {
	if fi, err := os.Stat(path); err == nil {
		return ptr(fi.Size())
	}
	return nil
}

// Storage gathers it all.
func (m *Manager) Storage() (*Storage, error) {
	res := &Storage{Items: []StorageItem{}, Errors: []string{}}
	add := func(it StorageItem) { res.Items = append(res.Items, it) }
	model, err := m.liveOrEmpty()
	if err != nil {
		return nil, apiError(err)
	}

	// OPF's own records.
	memMax := m.graphStorage(add)
	saved := StorageItem{ID: "graphs-saved", Group: StorageOPF, Name: "Graphs, saved", Desc: "The same, saved every few minutes and when OPF stops",
		Unit: "bytes", Where: "disk", Current: fileSize(m.store.StatePath(metricsFile)), Max: ptr(memMax), Link: "/monitoring/graphs", Settings: []StorageLink{setGraphs}}
	if saved.Current == nil {
		saved.Note = "Not saved yet."
	}
	add(saved)
	events := int64(m.eventLog().count())
	add(StorageItem{ID: "events", Group: StorageOPF, Name: "Event log", Desc: "Links, addresses, gateways, devices and commits as they happen",
		Unit: "entries", Where: "memory", Current: ptr(events), Max: ptr(MaxEvents), Link: "/monitoring/events",
		Note: "The newest are kept, none older than 90 days.", Fixed: "Fixed in OPF."})
	if model.DNS.Activity != nil && pf.KeepsDNSActivity(model) {
		set := model.DNS.Activity
		days, devDays, detailDays := set.Retention()
		worst := activity.WorstCase(activity.Retention{Days: days, DeviceDays: devDays, DetailDays: detailDays, Devices: set.Devices, MaxDevices: set.DeviceCap()}, set.DeviceCap())
		add(StorageItem{ID: "dns-activity", Group: StorageOPF, Name: "DNS activity", Desc: "Counts and top names, for the network and each device",
			Unit: "bytes", Where: "memory and disk", Current: ptr(m.activitySize()), Max: ptr(worst), Link: "/services/dns?tab=settings",
			Note: "Saved, about what it takes in memory too. The most is if every list fills every day with " + strconv.Itoa(set.DeviceCap()) + " devices, the most it keeps apart a day.", Settings: []StorageLink{setActivity}})
		add(StorageItem{ID: "dns-log", Group: StorageOPF, Name: "Resolver's answers, not yet counted", Desc: "unbound's log of every answer, which OPF reads and empties",
			Unit: "bytes", Where: "disk", Current: fileSize(m.dnsLogPath()), Max: ptr(truncateAt),
			Note: "Emptied once it passes this and OPF has read it all; it can pass it by what arrives in one collector tick.", Settings: []StorageLink{setActivity}})
	} else {
		add(StorageItem{ID: "dns-activity", Group: StorageOPF, Name: "DNS activity", Desc: "Counts and top names, for the network and each device",
			Unit: "bytes", Where: "memory and disk", Off: true, Note: "Not kept.", Settings: []StorageLink{setActivity}})
	}
	if pf.KeepsTraffic(model) {
		var saved int64
		if n := fileSize(m.store.StatePath(trafficFile)); n != nil {
			saved = *n
		}
		add(StorageItem{ID: "traffic", Group: StorageOPF, Name: "Traffic per device", Desc: "What each device sent and received, by hour",
			Unit: "bytes", Where: "memory and disk", Current: ptr(saved), Max: ptr(activity.WorstTraffic(model.Firewall.Traffic.Days, model.Firewall.Traffic.DeviceCap())), Link: "/devices/traffic",
			Note: "As last saved. The most is " + strconv.Itoa(model.Firewall.Traffic.DeviceCap()) + " devices, the most it keeps apart, every hour.", Settings: []StorageLink{setTraffic}})
	} else {
		add(StorageItem{ID: "traffic", Group: StorageOPF, Name: "Traffic per device", Desc: "What each device sent and received, by hour",
			Unit: "bytes", Where: "memory and disk", Off: true, Note: "Not kept.", Settings: []StorageLink{setTraffic}})
	}
	entries, _ := m.store.History()
	hist, _ := treeSize(m.store.StatePath("history"))
	add(StorageItem{ID: "history-entries", Group: StorageOPF, Name: "Change history", Desc: "Every commit, with every file before and after",
		Unit: "entries", Where: "disk", Current: ptr(int64(len(entries))), Unbounded: "Every commit is kept: nothing prunes the history yet.", Link: "/system/history",
		Fixed: "There's no setting yet: nothing prunes it."})
	add(StorageItem{ID: "history-bytes", Group: StorageOPF, Name: "Change history, on disk", Desc: "The commits' files",
		Unit: "bytes", Where: "disk", Current: ptr(hist), Unbounded: "Grows with every commit.", Link: "/system/history",
		Fixed: "There's no setting yet: nothing prunes it."})
	var lists int64
	for _, a := range model.Firewall.Aliases {
		if a.Type == pf.AliasURL {
			lists++
		}
	}
	for _, l := range model.DNS.Blocklists {
		if l.Enabled {
			lists++
		}
	}
	tables, _ := treeSize(m.store.SystemPath(filepath.Dir(pf.TablePath("x"))))
	dnsLists, _ := treeSize(m.store.SystemPath(pf.DNSListsDir))
	listsItem := StorageItem{ID: "lists", Group: StorageOPF, Name: "Downloaded lists", Desc: "Address lists for aliases and DNS blocklists, as OPF keeps them",
		Unit: "bytes", Where: "disk", Current: ptr(tables + dnsLists), Max: ptr(lists * maxListBytes), Settings: []StorageLink{setBlocklists, setAliases},
		Note: "A download over " + formatMB(maxListBytes) + " is refused; the most is that for each list in use (" + strconv.FormatInt(lists, 10) + ")."}
	if lists == 0 && tables+dnsLists == 0 {
		listsItem.Current, listsItem.Max, listsItem.Off, listsItem.Note = nil, nil, true, "No lists in use."
	}
	add(listsItem)

	// pf, in the kernel.
	limits := map[string]uint64{}
	if out, err := m.read("pfctl", "-s", "memory"); err == nil {
		limits = sysinfo.ParsePfMemory(out)
	}
	if len(limits) == 0 {
		res.Errors = append(res.Errors, "couldn't read pf's limits (pfctl -s memory)")
	}
	limit := func(name string) *int64 {
		if n, ok := limits[name]; ok {
			return ptr(int64(n))
		}
		return nil
	}
	var states *int64
	if out, err := m.read("pfctl", "-v", "-s", "info"); err == nil {
		if info, ok := sysinfo.ParsePfInfo(out); ok {
			states = ptr(int64(info.States))
		}
	}
	add(StorageItem{ID: "pf-states", Group: StoragePf, Name: "Connections", Desc: "pf's state table: one entry for each connection through or to the firewall",
		Unit: "entries", Where: "kernel", Current: states, Max: limit("states"), Link: "/firewall/connections",
		Note: "Full, new connections are refused until old ones end.", Settings: []StorageLink{setMaxStates}})
	var tableCount, addrs *int64
	if out, err := m.read("pfctl", "-vvs", "Tables"); err == nil {
		n, a := sysinfo.ParsePfTables(out)
		tableCount, addrs = ptr(int64(n)), ptr(int64(a))
	}
	add(StorageItem{ID: "pf-tables", Group: StoragePf, Name: "Tables", Desc: "Address tables: aliases, blocklists, OPF's own",
		Unit: "entries", Where: "kernel", Current: tableCount, Max: limit("tables"), Link: "/firewall/aliases", Settings: []StorageLink{setPfLimits}})
	add(StorageItem{ID: "pf-table-entries", Group: StoragePf, Name: "Table entries", Desc: "Addresses and networks in all the tables together",
		Unit: "entries", Where: "kernel", Current: addrs, Max: limit("table-entries"), Link: "/firewall/aliases",
		Note: "Full, a list too big to load fails the commit or refresh that loads it.", Settings: []StorageLink{setPfLimits}})

	// The logs OPF reads, as newsyslog rotates them.
	m.logSizes(res, add)

	// OPF itself, and the disk the state directory is on.
	if out, err := m.read("ps", "-A", "-o", "rss=,comm="); err == nil {
		if rss, ok := sysinfo.ParseProcessRSS(out, "opf"); ok {
			add(StorageItem{ID: "opf-memory", Group: StorageDisk, Name: "OPF's memory", Desc: "OPF's processes, everything above that's in memory included",
				Unit: "bytes", Where: "memory", Current: ptr(int64(rss)), Note: "Bounded by what it keeps, above."})
		}
	}
	if out, err := m.read("df", "-kPl"); err == nil {
		disks := sysinfo.ParseDf(out)
		// The longest mount the state directory is under.
		best := -1
		for i, d := range disks {
			if strings.HasPrefix(m.store.StatePath("")+"/", strings.TrimSuffix(d.Mount, "/")+"/") && (best < 0 || len(d.Mount) > len(disks[best].Mount)) {
				best = i
			}
		}
		if best >= 0 {
			d := disks[best]
			add(StorageItem{ID: "disk", Group: StorageDisk, Name: "Disk (" + d.Mount + ")", Desc: "Where OPF keeps its records",
				Unit: "bytes", Where: "disk", Current: ptr(int64(d.Used)), Max: ptr(int64(d.Total))})
		}
	}
	return res, nil
}

// activitySize is the DNS activity's size as saved: the saved file's,
// or what saving it now would write before it's been saved.
func (m *Manager) activitySize() int64 {
	if n := fileSize(m.store.StatePath(activityFile)); n != nil {
		return *n
	}
	m.activity.mu.Lock()
	defer m.activity.mu.Unlock()
	var c countWriter
	m.activityStore().Save(&c)
	return int64(c)
}

type countWriter int64

func (c *countWriter) Write(p []byte) (int, error) { *c += countWriter(len(p)); return len(p), nil }

// graphStorage adds a row for each kind of graph: the system's own
// series by what they're about (the firewall's states and blocks, DNS,
// the machine), each fixed, and each capped group against its cap.
// It returns the most they can all take.
func (m *Manager) graphStorage(add func(StorageItem)) int64 {
	keys := map[string]bool{}
	for _, k := range m.metricsStore().Keys() {
		keys[k] = true
	}
	var total int64
	fixed := []struct {
		id, name, desc, link string
		series               []string
	}{
		{"graphs-firewall", "Firewall", "Connections (pf’s states) and blocked packets", "/monitoring/graphs", []string{SeriesPfStates, SeriesPfBlocked}},
		{"graphs-dns", "DNS", "Queries, blocks and cache hits, a second", "/services/dns", []string{SeriesDNSQueries, SeriesDNSBlocked, SeriesDNSCacheHit}},
		{"graphs-system", "System", "CPU, memory, load and the clock’s offset", "/monitoring/graphs", []string{SeriesCPU, SeriesMemory, SeriesLoad, SeriesTimeOffset}},
	}
	names := map[string]string{
		GroupInterfaces: "Interfaces", GroupGateways: "Gateways", GroupVPN: "VPN devices", GroupDHCP: "DHCP networks", GroupRules: "Firewall rules",
	}
	descs := map[string]string{
		GroupInterfaces: "Traffic in and out of each", GroupGateways: "Each one’s latency and loss", GroupVPN: "Each device’s traffic and handshakes",
		GroupDHCP: "Leases in use on each", GroupRules: "Packets each rule matched",
	}
	for _, g := range m.graphUse() {
		if g.Name == GroupSystem {
			for _, f := range fixed {
				var have int64
				for _, s := range f.series {
					if keys[s] {
						have++
					}
				}
				max := int64(len(f.series) * g.SeriesBytes)
				total += max
				// Their rings are made full size, so there's no filling up
				// to show: just the size.
				add(StorageItem{ID: f.id, Group: StorageGraphs, Name: f.name, Desc: f.desc, Unit: "bytes", Where: "memory", Link: f.link,
					Current: ptr(have * int64(g.SeriesBytes)),
					Note:    strconv.Itoa(len(f.series)) + " series, a month each.", Fixed: "Always kept, at this size."})
			}
			continue
		}
		max := int64(g.Max * g.ItemBytes)
		total += max
		note := strconv.Itoa(g.Items) + " of at most " + strconv.Itoa(g.Max) + " recorded, a month each."
		if g.Refused {
			note += " It’s full: more aren’t recorded."
		}
		add(StorageItem{ID: "graphs-" + g.Name, Group: StorageGraphs, Name: names[g.Name], Desc: descs[g.Name], Unit: "bytes", Where: "memory",
			Link: "/monitoring/graphs", Current: ptr(int64(g.Series * g.SeriesBytes)), Max: ptr(max), Note: note, Settings: []StorageLink{setGraphs}})
	}
	return total
}

func formatMB(n int64) string { return strconv.FormatInt(n>>20, 10) + " MB" }

// logSizes adds each log OPF reads: its size and its old copies', and
// the most newsyslog lets them reach.
func (m *Manager) logSizes(res *Storage, add func(StorageItem)) {
	conf, err := m.read("cat", "/etc/newsyslog.conf")
	if err != nil {
		res.Errors = append(res.Errors, "couldn't read /etc/newsyslog.conf")
	}
	rot := sysinfo.ParseNewsyslog(conf)
	logs := []struct{ path, name, desc, link string }{
		{pflogPath, "Firewall log", "Packets pf logged: blocked ones, and rules set to log", "/firewall/log"},
		{"/var/log/daemon", "Daemon log", "unbound, dhcpd, ntpd and OPF's own messages", "/system/logs"},
		{"/var/log/messages", "System log", "The kernel and most of the system", "/system/logs"},
		{"/var/log/authlog", "Logins", "SSH and other logins", "/system/logs"},
	}
	var paths []string
	for _, l := range logs {
		paths = append(paths, l.path)
		if r, ok := rot[l.path]; ok {
			for i := 0; i < r.Count; i++ {
				paths = append(paths, r.Archive(l.path, i))
			}
		}
	}
	// Some old copies may not be there yet: ls says so and lists the rest.
	out, _ := m.read(append([]string{"ls", "-ln"}, paths...)...)
	sizes := sysinfo.ParseLsSizes(out)
	for _, l := range logs {
		it := StorageItem{ID: "log-" + filepath.Base(l.path), Group: StorageLogs, Name: l.name, Desc: l.desc, Unit: "bytes", Where: "disk", Link: l.link, Fixed: newsyslogFixed}
		if l.path == pflogPath {
			// What fills it is OPF's to set.
			it.Settings = []StorageLink{setLogBlocked, setRules}
		}
		r, rotated := rot[l.path]
		if n, ok := sizes[l.path]; ok {
			total := n
			if rotated {
				for i := 0; i < r.Count; i++ {
					total += sizes[r.Archive(l.path, i)]
				}
			}
			it.Current = ptr(total)
		}
		switch {
		case rotated && r.SizeKB > 0:
			it.Max = ptr(int64(r.SizeKB) * 1024 * int64(r.Count+1))
			it.Note = "With its " + strconv.Itoa(r.Count) + " old copies, rotated at " + strconv.Itoa(r.SizeKB) + " KB (newsyslog). They're compressed, so they take less."
		case rotated:
			it.Unbounded = "Rotated by time, not size (newsyslog), so a busy day can make it large."
		default:
			it.Unbounded = "newsyslog doesn't rotate it."
		}
		add(it)
	}
}
