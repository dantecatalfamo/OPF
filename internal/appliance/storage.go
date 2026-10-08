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

// Diagnostics › Storage: everything that fills up as the firewall runs,
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
	// Link is the UI page that shows or sets it.
	Link string `json:"link,omitempty"`
}

const (
	StorageOPF  = "opf"
	StoragePf   = "pf"
	StorageLogs = "logs"
	StorageDisk = "disk"
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
	var mem, memMax int64
	for _, g := range m.graphUse() {
		mem += int64(g.Series * g.SeriesBytes)
		memMax += int64(g.Max * g.ItemBytes)
	}
	add(StorageItem{ID: "graphs", Group: StorageOPF, Name: "Graphs", Desc: "A month of history for each interface, gateway, VPN device, DHCP network and rule, and the system",
		Unit: "bytes", Where: "memory", Current: ptr(mem), Max: ptr(memMax), Link: "/system/general",
		Note: "Each kind has its own cap, set on System › General; past it, new ones aren't recorded."})
	saved := StorageItem{ID: "graphs-saved", Group: StorageOPF, Name: "Graphs, saved", Desc: "The same, saved every few minutes and when OPF stops",
		Unit: "bytes", Where: "disk", Current: fileSize(m.store.StatePath(metricsFile)), Max: ptr(memMax), Link: "/diagnostics/graphs"}
	if saved.Current == nil {
		saved.Note = "Not saved yet."
	}
	add(saved)
	events := int64(m.eventLog().count())
	add(StorageItem{ID: "events", Group: StorageOPF, Name: "Event log", Desc: "Links, addresses, gateways, devices and commits as they happen",
		Unit: "entries", Where: "memory", Current: ptr(events), Max: ptr(MaxEvents), Link: "/diagnostics/events",
		Note: "The newest are kept, none older than 90 days."})
	if model.DNS.Activity != nil && pf.KeepsDNSActivity(model) {
		set := model.DNS.Activity
		days, devDays, detailDays := set.Retention()
		worst := activity.WorstCase(activity.Retention{Days: days, DeviceDays: devDays, DetailDays: detailDays, Devices: set.Devices}, activity.MaxDevices)
		add(StorageItem{ID: "dns-activity", Group: StorageOPF, Name: "DNS activity", Desc: "Counts and top names, for the network and each device",
			Unit: "bytes", Where: "memory and disk", Current: ptr(m.activitySize()), Max: ptr(worst), Link: "/services/dns?tab=settings",
			Note: "Saved, about what it takes in memory too. The most is if every list fills every day with " + strconv.Itoa(activity.MaxDevices) + " devices; how long each kind is kept is set under DNS resolver › Settings."})
		add(StorageItem{ID: "dns-log", Group: StorageOPF, Name: "Resolver's answers, not yet counted", Desc: "unbound's log of every answer, which OPF reads and empties",
			Unit: "bytes", Where: "disk", Current: fileSize(m.dnsLogPath()), Max: ptr(truncateAt),
			Note: "Emptied once it passes this and OPF has read it all; it can pass it by what arrives in one collector tick."})
	} else {
		add(StorageItem{ID: "dns-activity", Group: StorageOPF, Name: "DNS activity", Desc: "Counts and top names, for the network and each device",
			Unit: "bytes", Where: "memory and disk", Off: true, Link: "/services/dns?tab=settings", Note: "Not kept."})
	}
	entries, _ := m.store.History()
	hist, _ := treeSize(m.store.StatePath("history"))
	add(StorageItem{ID: "history-entries", Group: StorageOPF, Name: "Change history", Desc: "Every commit, with every file before and after",
		Unit: "entries", Where: "disk", Current: ptr(int64(len(entries))), Unbounded: "Every commit is kept: nothing prunes the history yet.", Link: "/system/history"})
	add(StorageItem{ID: "history-bytes", Group: StorageOPF, Name: "Change history, on disk", Desc: "The commits' files",
		Unit: "bytes", Where: "disk", Current: ptr(hist), Unbounded: "Grows with every commit."})
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
		Unit: "bytes", Where: "disk", Current: ptr(tables + dnsLists), Max: ptr(lists * maxListBytes), Link: "/services/dns?tab=blocking",
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
		Unit: "entries", Where: "kernel", Current: states, Max: limit("states"), Link: "/diagnostics/connections",
		Note: "Full, new connections are refused until old ones end."})
	var tableCount, addrs *int64
	if out, err := m.read("pfctl", "-vvs", "Tables"); err == nil {
		n, a := sysinfo.ParsePfTables(out)
		tableCount, addrs = ptr(int64(n)), ptr(int64(a))
	}
	add(StorageItem{ID: "pf-tables", Group: StoragePf, Name: "Tables", Desc: "Address tables: aliases, blocklists, OPF's own",
		Unit: "entries", Where: "kernel", Current: tableCount, Max: limit("tables"), Link: "/firewall/aliases"})
	add(StorageItem{ID: "pf-table-entries", Group: StoragePf, Name: "Table entries", Desc: "Addresses and networks in all the tables together",
		Unit: "entries", Where: "kernel", Current: addrs, Max: limit("table-entries"), Link: "/firewall/aliases",
		Note: "Full, a list too big to load fails the commit or refresh that loads it."})

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
		{pflogPath, "Firewall log", "Packets pf logged: blocked ones, and rules set to log", "/diagnostics/log"},
		{"/var/log/daemon", "Daemon log", "unbound, dhcpd, ntpd and OPF's own messages", "/diagnostics/system-logs"},
		{"/var/log/messages", "System log", "The kernel and most of the system", "/diagnostics/system-logs"},
		{"/var/log/authlog", "Logins", "SSH and other logins", "/diagnostics/system-logs"},
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
		it := StorageItem{ID: "log-" + filepath.Base(l.path), Group: StorageLogs, Name: l.name, Desc: l.desc, Unit: "bytes", Where: "disk", Link: l.link}
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
