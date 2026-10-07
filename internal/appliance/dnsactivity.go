package appliance

import (
	"bufio"
	"errors"
	"io"
	"io/fs"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/dantecatalfamo/OPF/internal/activity"
	"github.com/dantecatalfamo/OPF/internal/leases"
	"github.com/dantecatalfamo/OPF/internal/pf"
	"github.com/dantecatalfamo/OPF/internal/sysinfo"
)

// DNS activity (pf.DNSActivity): while it's on, unbound logs every
// answer to its own file (pf.DNSLogPath), and every collector tick
// reads what's new there into the counts package activity keeps. The
// file is emptied once it's large and read to its end, so it holds
// minutes of queries, not days. Turning it off deletes the counts and
// the file; turning devices off deletes theirs.

const (
	activityFile = "dns-activity.json"
	// The log is emptied past truncateAt, once it's all read; a tick
	// reads at most readMax of it (a backlog takes a few).
	truncateAt = 4 << 20
	readMax    = 8 << 20
	// relayMax is how many of unbound's other lines (warnings, errors)
	// a tick passes on to OPF's log, which goes to syslog.
	relayMax = 50
	// devicesEvery is how often the addresses' devices are looked up
	// again (leases, ARP); an address not found is looked up again
	// sooner, at most every missEvery, so a device that has only just
	// asked isn't kept under its address.
	devicesEvery = time.Minute
	missEvery    = 10 * time.Second
)

type dnsActivity struct {
	mu     sync.Mutex
	loaded bool
	store  *activity.Store
	// devices maps an address to who it is, from the last look.
	devices   map[netip.Addr]string
	devicesAt time.Time
	// The model and time of the read under way, for looking again.
	model *pf.Model
	now   time.Time
}

// dnsLogPath is unbound's log file: DNSLog, or where unbound writes it.
func (m *Manager) dnsLogPath() string {
	if m.DNSLog != "" {
		return m.DNSLog
	}
	return pf.DNSLogPath
}

// activityStore is the store, loaded from the state directory the
// first time. Call it with a.mu held.
func (m *Manager) activityStore() *activity.Store {
	a := &m.activity
	if !a.loaded {
		a.loaded = true
		a.store = &activity.Store{}
		if f, err := os.Open(m.store.StatePath(activityFile)); err == nil {
			if s, err := activity.Load(f); err == nil {
				a.store = s
			} else {
				log.Printf("starting DNS activity over: %v", err)
			}
			f.Close()
		}
	}
	return a.store
}

// saveActivity writes the store, replacing the last copy only once the
// new one is complete. Call it with a.mu held.
func (m *Manager) saveActivity() error {
	if !m.activity.loaded {
		return nil
	}
	path := m.store.StatePath(activityFile)
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+activityFile+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := m.activity.store.Save(tmp); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// SaveDNSActivity saves the counts; the collector calls it with the
// graphs, and OPF when it stops.
func (m *Manager) SaveDNSActivity() error {
	m.activity.mu.Lock()
	defer m.activity.mu.Unlock()
	return m.saveActivity()
}

// readDNSActivity reads what unbound logged since the last time.
func (m *Manager) readDNSActivity(model *pf.Model, now time.Time) {
	a := &m.activity
	a.mu.Lock()
	defer a.mu.Unlock()
	if model == nil || !pf.KeepsDNSActivity(model) {
		m.dropDNSActivity()
		return
	}
	set := model.DNS.Activity
	s := m.activityStore()
	s.Prune(now, set.Days, set.Devices)
	if err := m.readDNSLog(model, s, set.Devices, now); err != nil && !errors.Is(err, fs.ErrNotExist) {
		log.Printf("reading the resolver's log: %v", err)
	}
}

// dropDNSActivity deletes what was kept and unbound's file, once DNS
// activity is off. Call it with a.mu held.
func (m *Manager) dropDNSActivity() {
	a := &m.activity
	path := m.store.StatePath(activityFile)
	if _, err := os.Stat(path); err == nil || (a.loaded && (len(a.store.Hours) > 0 || len(a.store.Days) > 0)) {
		a.store, a.loaded = &activity.Store{}, true
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			log.Printf("deleting the DNS activity: %v", err)
		}
	}
	// unbound has stopped writing it once the commit that turned it off
	// reloaded unbound; until then it may write a line or two more.
	if err := os.Remove(m.dnsLogPath()); err != nil && !errors.Is(err, fs.ErrNotExist) {
		log.Printf("deleting the resolver's log: %v", err)
	}
}

func inode(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Ino)
	}
	return 0
}

func (m *Manager) readDNSLog(model *pf.Model, s *activity.Store, devices bool, now time.Time) error {
	path := m.dnsLogPath()
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	// unbound makes it readable by everyone (its umask), in a directory
	// anyone can list: it holds every query, so only its owner reads it.
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		if err := os.Chmod(path, perm&^0o077); err != nil {
			log.Printf("making the resolver's log private: %v", err)
		}
	}
	// Another file (unbound made it again), or one emptied by someone
	// else: from its start.
	pos := &s.Log
	if ino := inode(fi); ino != pos.Inode || fi.Size() < pos.Offset {
		*pos = activity.LogPosition{Inode: ino}
	}
	if fi.Size() == pos.Offset {
		return nil
	}
	if _, err := f.Seek(pos.Offset, io.SeekStart); err != nil {
		return err
	}
	if devices {
		m.activity.model, m.activity.now = model, now
		m.lookUpDevices(model, now, devicesEvery)
	}
	r := bufio.NewReaderSize(io.LimitReader(f, readMax), 64<<10)
	// A block's own answer comes right after it: it's counted as a
	// block, not as a name looked up.
	blocked := map[string]int{}
	relayed := 0
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			break // the end, or a line unbound is still writing
		}
		pos.Offset += int64(len(line))
		u, ok := sysinfo.ParseUnboundLogLine(strings.TrimSuffix(line, "\n"))
		switch {
		case !ok:
		case u.Reply != nil:
			key := u.Reply.Client + " " + strings.ToLower(u.Reply.Name)
			wasBlocked := blocked[key] > 0
			if wasBlocked {
				blocked[key]--
			}
			s.AddAnswer(activity.Answer{
				Time: u.Time, Device: m.deviceOf(u.Reply.Client, devices), Address: u.Reply.Client,
				Name: strings.ToLower(u.Reply.Name), Rcode: u.Reply.Rcode, Cached: u.Reply.Cached,
			}, wasBlocked)
		case u.RPZ != nil:
			list, own := "", u.RPZ.Zone == pf.OwnLogName
			if !own {
				id, ok := strings.CutPrefix(u.RPZ.Zone, pf.DNSListLogName(""))
				if !ok {
					continue // not one of OPF's zones
				}
				list = id
			}
			name := strings.ToLower(u.RPZ.Name)
			pass := sysinfo.RPZPass[u.RPZ.Action]
			if !pass {
				blocked[u.RPZ.Client+" "+name]++
			}
			s.AddBlock(activity.Block{
				Time: u.Time, Device: m.deviceOf(u.RPZ.Client, devices), Address: u.RPZ.Client,
				Name: name, List: list, Entry: displayable(u.RPZ.Trigger), Pass: pass,
			})
		case relayed < relayMax:
			// unbound's own messages would have gone to the daemon log;
			// they still do, through OPF's.
			relayed++
			log.Printf("unbound %s: %s", u.Level, displayable(u.Message))
		}
	}
	// Emptied once it's large and all read, so it stays small. A line
	// unbound writes between the read and here is lost; checking the
	// size again keeps that to a moment.
	if pos.Offset >= truncateAt {
		if fi, err := os.Stat(path); err == nil && fi.Size() == pos.Offset && inode(fi) == pos.Inode {
			if err := os.Truncate(path, 0); err != nil {
				return err
			}
			pos.Offset = 0
			// Saved now: after a crash, the old offset would be past the
			// end and the lines since the last save counted again.
			if err := m.saveActivity(); err != nil {
				log.Printf("saving the DNS activity: %v", err)
			}
		}
	}
	return nil
}

// Who an address is, as a key the counts are kept under: a MAC address
// from the DHCP leases or the ARP table ("mac:..."), a VPN device
// ("vpn:<peer id>"), the firewall itself, or else the address.
const (
	deviceMAC      = "mac:"
	deviceVPN      = "vpn:"
	deviceAddress  = "ip:"
	deviceFirewall = "firewall"
)

func (m *Manager) deviceOf(client string, devices bool) string {
	if !devices {
		return ""
	}
	addr, err := netip.ParseAddr(client)
	if err != nil {
		return deviceAddress + client
	}
	addr = addr.Unmap()
	if addr.IsLoopback() {
		return deviceFirewall
	}
	a := &m.activity
	if k, ok := a.devices[addr]; ok {
		return k
	}
	if a.model != nil && m.lookUpDevices(a.model, a.now, missEvery) {
		if k, ok := a.devices[addr]; ok {
			return k
		}
	}
	return deviceAddress + addr.String()
}

// lookUpDevices refreshes who each address is unless it was looked up
// less than every ago, and says whether it did. Call it with a.mu held.
func (m *Manager) lookUpDevices(model *pf.Model, now time.Time, every time.Duration) bool {
	a := &m.activity
	if a.devices != nil && now.Sub(a.devicesAt) < every {
		return false
	}
	a.devicesAt = now
	a.devices = map[netip.Addr]string{}
	// The ARP table first: the leases' say who has an address now, so
	// they win.
	if t, err := m.ARPTable(); err == nil {
		for _, e := range t.Entries {
			addr, err1 := netip.ParseAddr(e.IP)
			if err1 == nil && validMAC(e.MAC) {
				a.devices[addr] = deviceMAC + strings.ToLower(e.MAC)
			}
		}
	}
	if m.leases != nil {
		if all, err := leases.Read(m.leases.File); err == nil {
			for _, l := range leases.Current(all, now) {
				if l.MAC != "" {
					a.devices[l.IP] = deviceMAC + strings.ToLower(l.MAC)
				}
			}
		}
	}
	for _, i := range model.Interfaces {
		if i.WireGuard == nil {
			continue
		}
		for _, p := range i.WireGuard.Peers {
			// A tunnel address is the device's own: 10.8.0.2/32.
			if pre, err := netip.ParsePrefix(p.Address); err == nil {
				a.devices[pre.Addr()] = deviceVPN + p.ID
			} else if addr, err := netip.ParseAddr(p.Address); err == nil {
				a.devices[addr] = deviceVPN + p.ID
			}
		}
	}
	return true
}

func validMAC(s string) bool {
	if len(s) != 17 {
		return false
	}
	for i, c := range s {
		if i%3 == 2 {
			if c != ':' {
				return false
			}
		} else if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
			return false
		}
	}
	return true
}

// MaxActivityNames is how many names the activity views list.
const MaxActivityNames = 50

// DNSActivityRequest asks for the last Days days (today counts as one;
// 0 is today), or for one device's (DeviceKey).
type DNSActivityRequest struct {
	Days   int    `json:"days"`
	Device string `json:"device,omitempty"`
}

// DNSActivity is what the resolver did over the days asked for, for the
// network and, when they're kept, each device.
type DNSActivity struct {
	// The settings in effect (pf.DNSActivity); when Enabled is false
	// nothing else is set.
	Enabled bool `json:"enabled"`
	// PerDevice: devices are kept too (pf.DNSActivity.Devices).
	PerDevice bool `json:"perDevice"`
	Days      int  `json:"days"`
	*activity.Summary
	// DeviceInfo describes each device in Summary.Devices, by key.
	DeviceInfo map[string]ActivityDevice `json:"deviceInfo,omitempty"`
}

// ActivityDevice is who a device is: its kind ("device", "vpn",
// "firewall", "address", "other"), its name where OPF knows one, and
// its MAC address.
type ActivityDevice struct {
	Kind string `json:"kind"`
	Name string `json:"name,omitempty"`
	MAC  string `json:"mac,omitempty"`
}

// DNSDeviceActivity is one device's days.
type DNSDeviceActivity struct {
	ActivityDevice
	*activity.DeviceActivity
}

func activityDays(req, kept int) int {
	if req < 1 {
		return 1
	}
	return min(req, kept)
}

// DNSActivity is the network's activity over req.Days.
func (m *Manager) DNSActivity(req DNSActivityRequest) (*DNSActivity, error) {
	model, _, err := m.live()
	if err != nil {
		return nil, apiError(err)
	}
	out := &DNSActivity{}
	if model == nil || !pf.KeepsDNSActivity(model) {
		return out, nil
	}
	set := model.DNS.Activity
	out.Enabled, out.PerDevice, out.Days = true, set.Devices, set.Days
	m.activity.mu.Lock()
	sum := m.activityStore().Summary(time.Now(), activityDays(req.Days, set.Days), MaxActivityNames)
	m.activity.mu.Unlock()
	out.Summary = &sum
	if set.Devices {
		names := m.deviceNames(model)
		out.DeviceInfo = map[string]ActivityDevice{}
		for _, d := range sum.Devices {
			out.DeviceInfo[d.Key] = describeDevice(d.Key, names, model)
		}
	}
	return out, nil
}

// DNSDeviceActivity is one device's activity over req.Days.
func (m *Manager) DNSDeviceActivity(req DNSActivityRequest) (*DNSDeviceActivity, error) {
	model, _, err := m.live()
	if err != nil {
		return nil, apiError(err)
	}
	if model == nil || !pf.KeepsDNSActivity(model) || !model.DNS.Activity.Devices {
		return nil, errorf(CodeNotFound, "DNS activity isn't kept for each device")
	}
	m.activity.mu.Lock()
	d, ok := m.activityStore().Device(req.Device, time.Now(), activityDays(req.Days, model.DNS.Activity.Days), MaxActivityNames)
	m.activity.mu.Unlock()
	if !ok {
		return nil, errorf(CodeNotFound, "nothing is kept for that device over those days")
	}
	return &DNSDeviceActivity{ActivityDevice: describeDevice(req.Device, m.deviceNames(model), model), DeviceActivity: &d}, nil
}

// ForgetDNSActivity deletes one device's activity, or with no device
// every device's and the network's.
func (m *Manager) ForgetDNSActivity(req DNSActivityRequest) error {
	m.activity.mu.Lock()
	defer m.activity.mu.Unlock()
	s := m.activityStore()
	if req.Device == "" {
		pos := s.Log
		*s = activity.Store{Log: pos}
	} else {
		s.ForgetDevice(req.Device)
	}
	return apiError(m.saveActivity())
}

// deviceNames are the names OPF knows for MAC addresses: DHCP
// reservations', then the names the leases' devices were given in DNS
// or asked for.
func (m *Manager) deviceNames(model *pf.Model) map[string]string {
	names := map[string]string{}
	if ls, err := m.DHCPLeases(); err == nil {
		for _, l := range ls.Leases {
			n := l.DNSName
			if n == "" {
				n = l.Hostname
			}
			if l.MAC != "" && n != "" {
				names[strings.ToLower(l.MAC)] = n
			}
		}
	}
	for _, s := range model.DHCP {
		for _, r := range s.Reservations {
			if r.MAC != "" && r.Hostname != "" {
				names[strings.ToLower(r.MAC)] = r.Hostname
			}
		}
	}
	return names
}

func describeDevice(key string, names map[string]string, model *pf.Model) ActivityDevice {
	switch {
	case key == deviceFirewall:
		return ActivityDevice{Kind: "firewall", Name: "This firewall"}
	case key == activity.Other:
		return ActivityDevice{Kind: "other", Name: "Other devices"}
	case strings.HasPrefix(key, deviceMAC):
		mac := strings.TrimPrefix(key, deviceMAC)
		return ActivityDevice{Kind: "device", Name: names[mac], MAC: mac}
	case strings.HasPrefix(key, deviceVPN):
		id := strings.TrimPrefix(key, deviceVPN)
		for _, i := range model.Interfaces {
			if i.WireGuard == nil {
				continue
			}
			for _, p := range i.WireGuard.Peers {
				if p.ID == id {
					return ActivityDevice{Kind: "vpn", Name: p.Name}
				}
			}
		}
		return ActivityDevice{Kind: "vpn"}
	}
	return ActivityDevice{Kind: "address"}
}

// blockedFromActivity is DNSBlocked from the counts kept today, while
// unbound logs to OPF's file rather than the daemon log.
func (m *Manager) blockedFromActivity(model *pf.Model) *DNSBlocked {
	m.activity.mu.Lock()
	sum := m.activityStore().Summary(time.Now(), 1, MaxBlockedNames)
	m.activity.mu.Unlock()
	res := &DNSBlocked{ByList: map[string]int{}, Names: []BlockedName{}, Allowed: int(sum.Total.Allowed), Blocked: int(sum.Total.Blocked)}
	if len(sum.Hours) > 0 {
		since := sum.Since
		res.Since = &since
	}
	for l, n := range sum.ByList {
		if l == "" {
			res.Own += int(n)
		} else {
			res.ByList[l] += int(n)
		}
	}
	for _, it := range sum.Blocked {
		// Names come from whoever asked: only ones that are names, so
		// "never block" can take them as they are.
		if !pf.IsBlockName(it.Name) || strings.HasPrefix(it.Name, "*.") {
			continue
		}
		res.Names = append(res.Names, BlockedName{Name: it.Name, Count: int(it.Count), Last: time.Unix(it.Last, 0), List: it.List, Entry: it.Entry})
	}
	return res
}
