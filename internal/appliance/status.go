package appliance

import (
	"context"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dantecatalfamo/OPF/internal/pf"
	"github.com/dantecatalfamo/OPF/internal/sysinfo"
)

// The running system's state, read with OpenBSD's own tools and parsed
// by package sysinfo. Nothing here changes the system. A command that
// fails leaves its part of the answer empty and says so in Errors,
// rather than failing the whole request: the dashboard should still
// show memory when df hangs.

// readTimeout bounds each command that reads state.
const readTimeout = 10 * time.Second

func (m *Manager) read(argv ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), readTimeout)
	defer cancel()
	out, err := m.runner().Run(ctx, argv...)
	return string(out), err
}

// rate keeps the last two readings of a counter so a rate can be
// worked out. Pages poll every few seconds, so the previous poll's
// reading is usually the earlier one; when there isn't one (the first
// request, or after a long gap) it reads twice, a second apart. Requests
// within a second of the last reading share it, so several open pages
// don't shorten the interval to nothing.
type rate[T any] struct {
	mu            sync.Mutex
	then, now     T
	thenAt, nowAt time.Time
}

func (r *rate[T]) sample(read func() (T, error)) (then, now T, dt time.Duration, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	t := time.Now()
	if !r.nowAt.IsZero() && !r.thenAt.IsZero() && t.Sub(r.nowAt) < time.Second {
		return r.then, r.now, r.nowAt.Sub(r.thenAt), nil
	}
	cur, err := read()
	if err != nil {
		return then, now, 0, err
	}
	if r.nowAt.IsZero() || t.Sub(r.nowAt) > time.Minute {
		r.now, r.nowAt = cur, t
		time.Sleep(time.Second)
		t = time.Now()
		if cur, err = read(); err != nil {
			return then, now, 0, err
		}
	}
	r.then, r.thenAt = r.now, r.nowAt
	r.now, r.nowAt = cur, t
	return r.then, r.now, r.nowAt.Sub(r.thenAt), nil
}

// osRelease is kern.osrelease, which only changes with an upgrade and
// a reboot, so it's read once.
func (m *Manager) osRelease() string {
	m.releaseOnce.Do(func() {
		out, err := m.read("sysctl", "kern.osrelease")
		if err == nil {
			m.release = sysinfo.ParseSysctl(out)["kern.osrelease"]
		}
	})
	return m.release
}

// System returns the dashboard's view of the machine.
func (m *Manager) System() (*SystemStatus, error) {
	s := &SystemStatus{Disks: []sysinfo.Disk{}, Sensors: []sysinfo.Sensor{}, Errors: []string{}}
	fail := func(what string) { s.Errors = append(s.Errors, what) }

	out, err := m.read("sysctl", "kern.hostname", "kern.osrelease", "kern.version", "kern.boottime",
		"hw.machine", "hw.model", "hw.vendor", "hw.product", "hw.ncpuonline", "hw.physmem", "vm.loadavg")
	vals := sysinfo.ParseSysctl(out)
	if err != nil && len(vals) == 0 {
		fail("couldn't read the system's details (sysctl)")
	}
	s.Hostname = vals["kern.hostname"]
	s.Release = vals["kern.osrelease"]
	s.Version, _, _ = strings.Cut(vals["kern.version"], "\n")
	s.Machine = vals["hw.machine"]
	s.CPUModel = vals["hw.model"]
	s.Vendor = vals["hw.vendor"]
	s.Product = vals["hw.product"]
	s.CPUs, _ = strconv.Atoi(vals["hw.ncpuonline"])
	if b, err := sysinfo.ParseBoottime(vals["kern.boottime"], time.Local); err == nil {
		s.BootedAt = &b
	}
	if l, err := sysinfo.ParseLoadavg(vals["vm.loadavg"]); err == nil {
		s.Load = &l
	}
	physmem, _ := strconv.ParseUint(vals["hw.physmem"], 10, 64)

	then, now, _, err := m.cpu.sample(func() (sysinfo.CPUTicks, error) {
		out, err := m.read("sysctl", "kern.cp_time")
		if err != nil {
			return sysinfo.CPUTicks{}, err
		}
		return sysinfo.ParseCPUTicks(sysinfo.ParseSysctl(out)["kern.cp_time"])
	})
	if err != nil {
		fail("couldn't read CPU use (kern.cp_time)")
	} else if u, ok := now.Usage(then); ok {
		s.CPU = &u
	}

	if out, err := m.read("vmstat", "-s"); err != nil {
		fail("couldn't read memory use (vmstat)")
	} else if mem, err := sysinfo.ParseVmstatMemory(out, physmem); err != nil {
		fail("couldn't read memory use (vmstat)")
	} else {
		s.Memory = &mem
	}
	// swapctl exits 1 when there's no swap, which is no swap, not an
	// error.
	out, _ = m.read("swapctl", "-lk")
	sw := sysinfo.ParseSwapctl(out)
	s.Swap = &sw
	// Local filesystems only: a hung NFS server mustn't hang the page.
	if out, err := m.read("df", "-kPl"); err != nil && out == "" {
		fail("couldn't read disk use (df)")
	} else {
		s.Disks = sysinfo.ParseDf(out)
	}
	if out, err := m.read("sysctl", "hw.sensors"); err == nil {
		s.Sensors = sysinfo.ParseSensors(out)
	}
	// ntpctl fails when ntpd isn't running, which the page shows as
	// "not running" rather than an error.
	out, _ = m.read("ntpctl", "-s", "all")
	if ts, ok := sysinfo.ParseNtpctl(out); ok {
		s.Time = &ts
	}
	return s, nil
}

// Interfaces returns every interface as ifconfig shows it, with its
// counters and current rates.
func (m *Manager) Interfaces() (*InterfacesStatus, error) {
	res := &InterfacesStatus{Interfaces: []InterfaceState{}, Errors: []string{}}
	out, err := m.read("ifconfig", "-A")
	ifs := sysinfo.ParseIfconfig(out)
	if err != nil && len(ifs) == 0 {
		res.Errors = append(res.Errors, "couldn't read the interfaces (ifconfig)")
		return res, nil
	}
	then, now, dt, err := m.ifCounters.sample(func() (map[string]sysinfo.Counters, error) {
		b, err := m.read("netstat", "-ibn")
		if err != nil {
			return nil, err
		}
		p, err := m.read("netstat", "-in")
		if err != nil {
			return nil, err
		}
		return sysinfo.ParseNetstatIfaces(b, p), nil
	})
	if err != nil {
		res.Errors = append(res.Errors, "couldn't read the interface counters (netstat)")
	}
	for _, i := range ifs {
		st := InterfaceState{Interface: i}
		if c, ok := now[i.Name]; ok {
			st.Counters = &c
			if p, ok := then[i.Name]; ok && dt > 0 && c.RxBytes >= p.RxBytes && c.TxBytes >= p.TxBytes {
				sec := dt.Seconds()
				rx := float64(c.RxBytes-p.RxBytes) * 8 / sec
				tx := float64(c.TxBytes-p.TxBytes) * 8 / sec
				st.RxBps, st.TxBps = &rx, &tx
			}
		}
		res.Interfaces = append(res.Interfaces, st)
	}
	return res, nil
}

// gatewayCacheFor is how long a gateway's ping result is reused, so
// pages polling don't turn into a ping flood.
const gatewayCacheFor = 10 * time.Second

// Gateways pings each gateway in the live model (its monitor address
// if it has one) and reports whether it answers.
func (m *Manager) Gateways() (*GatewaysStatus, error) {
	m.gwMu.Lock()
	defer m.gwMu.Unlock()
	if m.gwCache != nil && time.Since(m.gwAt) < gatewayCacheFor {
		return m.gwCache, nil
	}
	model, _, err := m.live()
	if err != nil {
		return nil, err
	}
	res := &GatewaysStatus{Gateways: map[string]GatewayHealth{}}
	var dhcpRoutes []RouteEntry // default routes, for DHCP gateways
	for _, g := range model.Routing.Gateways {
		if g.Address == "dhcp" && g.Monitor == "" {
			if t, err := m.RoutingTable(); err == nil {
				dhcpRoutes = append(t.IPv4, t.IPv6...)
			}
			break
		}
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, g := range model.Routing.Gateways {
		addr := gatewayTarget(g, model, dhcpRoutes)
		if !addr.IsValid() {
			res.Gateways[g.ID] = GatewayHealth{Error: "no address yet"}
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			h := m.ping(addr)
			mu.Lock()
			res.Gateways[g.ID] = h
			mu.Unlock()
		}()
	}
	wg.Wait()
	m.gwCache, m.gwAt = res, time.Now()
	return res, nil
}

// gatewayTarget is the address to ping for a gateway: its monitor
// address, its own address, or for a DHCP gateway the default route
// the lease installed on its interface.
func gatewayTarget(g pf.Gateway, m *pf.Model, routes []RouteEntry) netip.Addr {
	for _, s := range []string{g.Monitor, g.Address} {
		if a, err := netip.ParseAddr(s); err == nil {
			return a
		}
	}
	if g.Address != "dhcp" {
		return netip.Addr{}
	}
	dev := ""
	for _, i := range m.Interfaces {
		if i.ID == g.Iface {
			dev = i.Device
		}
	}
	for _, r := range routes {
		if r.Destination == "default" && r.Iface == dev {
			if a, err := netip.ParseAddr(r.Gateway); err == nil {
				return a
			}
		}
	}
	return netip.Addr{}
}

func (m *Manager) ping(a netip.Addr) GatewayHealth {
	h := GatewayHealth{Address: a.String()}
	// Three probes, 0.2 s apart (root may go below a second), each
	// waiting at most a second: under two seconds for one that's down.
	// OpenBSD's ping has no -6; IPv6 is ping6.
	cmd := "ping"
	if a.Is6() {
		cmd = "ping6"
	}
	out, _ := m.read(cmd, "-n", "-q", "-c", "3", "-i", "0.2", "-w", "1", "--", a.String()) // exits 1 when nothing answers
	p, ok := sysinfo.ParsePing(out)
	if !ok {
		h.Error = "couldn't ping it"
		return h
	}
	h.Online = p.Received > 0
	h.LossPct = p.LossPct
	if h.Online {
		h.RttMs = &p.AvgMs
	}
	return h
}

func firstLine(s string) string {
	l, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	return printable(l, maxMessageRunes)
}
