package main

import (
	"context"
	"fmt"
	"hash/fnv"
	"math"
	"net/netip"
	"strings"
	"time"

	"github.com/dantecatalfamo/OPF/internal/pf"
	"github.com/dantecatalfamo/OPF/internal/run"
)

// mockSystem answers the commands OPF reads the system's state with,
// printing what OpenBSD would for the mock's live model, in the formats
// captured in internal/sysinfo/testdata. The real parsers read it, so
// the mock exercises them. Counters grow with time, at rates that
// wander, so the dashboard moves. Every other command goes to next.
type mockSystem struct {
	start time.Time
	model func() (*pf.Model, error)
	pf    *mockPf
	next  run.Runner
}

func (s mockSystem) Run(ctx context.Context, argv ...string) ([]byte, error) {
	cmd := strings.Join(argv, " ")
	t := time.Since(s.start).Seconds()
	var out string
	switch {
	case cmd == "sysctl kern.cp_time":
		out = "kern.cp_time=" + s.cpTime(t)
	case cmd == "sysctl kern.osrelease":
		out = "kern.osrelease=7.9\n"
	case strings.HasPrefix(cmd, "sysctl kern.hostname"):
		out = s.sysctl(t)
	case cmd == "sysctl hw.sensors":
		out = fmt.Sprintf("hw.sensors.km0.temp0=%.2f degC\nhw.sensors.sd0.drive0=online (sd0), OK\n", 51+3*math.Sin(t/40))
	case cmd == "ntpctl -s all":
		out = fmt.Sprintf(`4/4 peers valid, constraint offset 0s, clock synced, stratum 3

peer
   wt tl st  next  poll          offset       delay      jitter
162.159.200.1 from pool pool.ntp.org
 *  1 10  2   25s   31s         %.3fms     7.844ms     0.133ms
`, 0.4+0.1*math.Sin(t/30))
	case cmd == "vmstat -s":
		out = s.vmstat(t)
	case cmd == "swapctl -lk":
		out = "Device      1K-blocks     Used    Avail Capacity  Priority\n/dev/sd0b     4194304        0  4194304     0%    0\n"
	case cmd == "df -kPl":
		out = mockDf
	case cmd == "pfctl -v -s info", cmd == "pfctl -vv -s states", cmd == "pfctl -vv -s rules", strings.HasPrefix(cmd, "tcpdump -n -e -ttt -r "):
		m, err := s.model()
		if err != nil {
			return nil, err
		}
		switch argv[0] + " " + argv[len(argv)-1] {
		case "pfctl info":
			out = s.pf.info(m, t, time.Now())
		case "pfctl states":
			out = s.pf.states(m, time.Now())
		case "pfctl rules":
			out = s.pf.rules(m, t)
		default:
			out = s.pf.pflog(m, time.Now())
		}
	case argv[0] == "ftp":
		// A URL alias's list, as a blocklist publisher serves it.
		select {
		case <-time.After(700 * time.Millisecond):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		out = mockList(argv[len(argv)-1])
	case len(argv) == 7 && argv[0] == "pfctl" && argv[1] == "-t" && argv[3] == "-T" && argv[4] == "replace":
		out = "40 addresses added.\n"
	case cmd == "pfctl -s memory":
		out = "states        hard limit   100000\nsrc-nodes     hard limit    10000\ntables        hard limit     1000\ntable-entries hard limit   200000\n"
	case len(argv) == 5 && strings.HasPrefix(cmd, "pfctl -k id -k "):
		o, err := s.pf.kill(argv[4])
		return []byte(o), err
	case cmd == "ifconfig -A", cmd == "netstat -ibn", cmd == "netstat -in":
		m, err := s.model()
		if err != nil {
			return nil, err
		}
		switch argv[0] + " " + argv[1] {
		case "ifconfig -A":
			out = mockIfconfig(m, t)
		case "netstat -ibn":
			out = mockNetstat(m, t, true)
		default:
			out = mockNetstat(m, t, false)
		}
	case argv[0] == "ping" || argv[0] == "ping6":
		return mockPing(argv[len(argv)-1], t)
	case cmd == "syspatch -c":
		select {
		case <-time.After(2 * time.Second): // it fetches from a mirror
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		out = "001_unbound\n002_libcrypto\n"
	default:
		return s.next.Run(ctx, argv...)
	}
	return []byte(out), nil
}

// wander is a counter that grows at avg per second, give or take a
// share of it, and never goes backwards.
func wander(seed string, avg, t float64) float64 {
	h := fnv.New32a()
	h.Write([]byte(seed))
	phase := float64(h.Sum32()%1000) / 1000 * 2 * math.Pi
	period := 60 + float64(h.Sum32()%90)
	w := 2 * math.Pi / period
	// The integral of avg * (1 + 0.6 sin(wt + phase)).
	return avg*t - avg*0.6*(math.Cos(w*t+phase)-math.Cos(phase))/w
}

func (s mockSystem) cpTime(t float64) string {
	// kern.cp_time counts stathz (100 Hz here) ticks summed over 4 CPUs,
	// since a boot 23 days before the mock started.
	const hz, cpus = 100, 4
	up := t + 23*86400
	total := up * hz * cpus
	user := wander("cpu user", 0.09*hz*cpus, t) + 0.09*23*86400*hz*cpus
	sys := wander("cpu sys", 0.04*hz*cpus, t) + 0.04*23*86400*hz*cpus
	intr := wander("cpu intr", 0.02*hz*cpus, t) + 0.02*23*86400*hz*cpus
	idle := total - user - sys - intr
	return fmt.Sprintf("%d,0,%d,0,%d,%d\n", int64(user), int64(sys), int64(intr), int64(idle))
}

func (s mockSystem) sysctl(t float64) string {
	boot := s.start.Add(-23*24*time.Hour - 5*time.Hour)
	return fmt.Sprintf(`kern.hostname=gw.office.arpa
kern.osrelease=7.9
kern.version=OpenBSD 7.9 (GENERIC.MP) #15: Sun Sep 27 02:47:36 MDT 2026
    root@syspatch-79-amd64.openbsd.org:/usr/src/sys/arch/amd64/compile/GENERIC.MP

kern.boottime=%s
hw.machine=amd64
hw.model=AMD GX-412TC SOC
hw.vendor=PC Engines
hw.product=apu4
hw.ncpuonline=4
hw.physmem=4261412864
vm.loadavg=%.2f %.2f %.2f
`, boot.Format("Mon Jan _2 15:04:05 2006"), 0.3+0.2*math.Sin(t/20), 0.28+0.1*math.Sin(t/60), 0.25)
}

func (s mockSystem) vmstat(t float64) string {
	const total = 1040384 // pages of 4096 bytes: hw.physmem
	active := 160000 + int(12000*math.Sin(t/50))
	inactive := 150000
	free := total - active - inactive - 60000
	return fmt.Sprintf(`       4096 bytes per page
    %d pages managed
     %d pages free
     %d pages active
     %d pages inactive
          0 pages being paged out
         12 pages wired
`, total, free, active, inactive)
}

const mockDf = `Filesystem  1024-blocks       Used   Available Capacity Mounted on
/dev/sd0a       1009422     131042      827910    14%    /
/dev/sd0d       2052542       1224     1948692     0%    /tmp
/dev/sd0e      10319598    1630412     8173206    17%    /var
/dev/sd0f       5159966    1512286     3389682    31%    /usr
/dev/sd0h      12382830    1102210    10661480    10%    /home
`

// mockTraffic is each interface's average traffic, in bytes per second
// received and sent, by role.
func mockTraffic(i pf.Iface) (rx, tx float64) {
	switch i.Role {
	case pf.RoleWAN:
		return 6e6, 0.8e6
	case pf.RoleVPN:
		return 0.05e6, 0.15e6
	}
	if i.VLAN != nil {
		return 0.03e6, 0.06e6
	}
	return 0.7e6, 5.8e6
}

func mockMAC(dev string) string {
	h := fnv.New32a()
	h.Write([]byte(dev))
	n := h.Sum32()
	return fmt.Sprintf("00:0d:b9:%02x:%02x:%02x", byte(n>>16), byte(n>>8), byte(n))
}

func mockNetstat(m *pf.Model, t float64, bytes bool) string {
	var b strings.Builder
	if bytes {
		b.WriteString("Name    Mtu   Network     Address               Ibytes     Obytes\n")
	} else {
		b.WriteString("Name    Mtu   Network     Address              Ipkts Ifail    Opkts Ofail Colls\n")
	}
	b.WriteString("lo0     32768 <Link>                                 0          0\n")
	for _, i := range m.Interfaces {
		rx, tx := mockTraffic(i)
		// A day of traffic before the mock started.
		rb := wander(i.Device+" rx", rx, t) + rx*86400
		tb := wander(i.Device+" tx", tx, t) + tx*86400
		name := i.Device
		if !i.Enabled {
			name += "*"
			rb, tb = 0, 0
		}
		addr := mockMAC(i.Device)
		if i.WireGuard != nil {
			addr = ""
		}
		if bytes {
			fmt.Fprintf(&b, "%-7s %-5d <Link>      %-17s %10d %10d\n", name, 1500, addr, int64(rb), int64(tb))
		} else {
			fmt.Fprintf(&b, "%-7s %-5d <Link>      %-17s %8d %5d %8d %5d %5d\n", name, 1500, addr, int64(rb/900), 0, int64(tb/900), 0, 0)
		}
	}
	b.WriteString("pflog0  33136 <Link>                                 0          0\n")
	return b.String()
}

func mockIfconfig(m *pf.Model, t float64) string {
	var b strings.Builder
	b.WriteString("lo0: flags=2008049<UP,LOOPBACK,RUNNING,MULTICAST,LRO> mtu 32768\n\tindex 3 priority 0 llprio 3\n\tgroups: lo\n\tinet6 ::1 prefixlen 128\n\tinet6 fe80::1%lo0 prefixlen 64 scopeid 0x3\n\tinet 127.0.0.1 netmask 0xff000000\n")
	for n, i := range m.Interfaces {
		flags := "8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST>"
		if i.WireGuard != nil {
			flags = "80c3<UP,BROADCAST,RUNNING,NOARP,MULTICAST>"
		}
		if !i.Enabled {
			flags = "8802<BROADCAST,SIMPLEX,MULTICAST>"
		}
		fmt.Fprintf(&b, "%s: flags=%s mtu %d\n", i.Device, flags, map[bool]int{true: 1420, false: 1500}[i.WireGuard != nil])
		if i.WireGuard == nil {
			fmt.Fprintf(&b, "\tlladdr %s\n", mockMAC(i.Device))
		}
		fmt.Fprintf(&b, "\tdescription: %s\n\tindex %d priority 0 llprio 3\n", i.Name, n+1)
		if i.VLAN != nil {
			fmt.Fprintf(&b, "\tencap: vnetid %d parent %s txprio packet rxprio outer\n", i.VLAN.Tag, i.VLAN.Parent)
		}
		if w := i.WireGuard; w != nil {
			fmt.Fprintf(&b, "\twgport %d\n\twgpubkey %s\n", w.ListenPort, w.PublicKey)
			for k, p := range w.Peers {
				fmt.Fprintf(&b, "\twgpeer %s\n\t\twgdescr %s\n", p.PublicKey, p.Name)
				// The first peer is online; the others were seen a while
				// ago, and the last never.
				if k == len(w.Peers)-1 && k > 0 {
					fmt.Fprintf(&b, "\t\ttx: 0, rx: 0\n")
				} else {
					fmt.Fprintf(&b, "\t\twgendpoint 198.51.100.%d %d\n", 70+k, 40212+k)
					fmt.Fprintf(&b, "\t\ttx: %d, rx: %d\n", int64(wander(p.ID+" tx", 40e3, t)+1.9e9), int64(wander(p.ID+" rx", 4e3, t)+1.8e8))
					ago := int64(t) % 120
					if k > 0 {
						ago = 3900 + int64(t)
					}
					fmt.Fprintf(&b, "\t\tlast handshake: %d seconds ago\n", ago)
				}
				if a, err := netip.ParsePrefix(p.Address); err == nil {
					fmt.Fprintf(&b, "\t\twgaip %s\n", a)
				}
				for _, nw := range p.Networks {
					fmt.Fprintf(&b, "\t\twgaip %s\n", nw)
				}
			}
		}
		switch {
		case i.Role == pf.RoleWAN:
			b.WriteString("\tgroups: egress\n")
		case i.WireGuard != nil:
			b.WriteString("\tgroups: wg\n")
		case i.VLAN != nil:
			b.WriteString("\tgroups: vlan\n")
		}
		if i.WireGuard == nil {
			b.WriteString("\tmedia: Ethernet autoselect (1000baseT full-duplex)\n")
			if i.Enabled {
				b.WriteString("\tstatus: active\n")
			} else {
				b.WriteString("\tstatus: no carrier\n")
			}
		}
		if !i.Enabled {
			continue
		}
		switch {
		case i.IPv4.Mode == pf.IPv4Static && i.IPv4.Address != "" && i.IPv4.Prefix != nil:
			fmt.Fprintf(&b, "\tinet %s netmask 0x%08x\n", i.IPv4.Address, uint32(0xffffffff)<<(32-*i.IPv4.Prefix))
		case i.IPv4.Mode == pf.IPv4DHCP:
			b.WriteString("\tinet 203.0.113.24 netmask 0xffffff00 broadcast 203.0.113.255\n")
		}
	}
	b.WriteString("enc0: flags=0<>\n\tindex 20 priority 0 llprio 3\n\tgroups: enc\n\tstatus: active\n")
	b.WriteString("pflog0: flags=141<UP,RUNNING,PROMISC> mtu 33136\n\tindex 21 priority 0 llprio 3\n\tgroups: pflog\n")
	return b.String()
}

// mockPing answers for any address, a few milliseconds away, with the
// odd lost packet on one that isn't on the WAN.
func mockPing(addr string, t float64) ([]byte, error) {
	rtt := 8.4
	lost := 0
	if !strings.HasPrefix(addr, "203.0.113.") {
		rtt = 23.1
		if int(t)%7 == 0 {
			lost = 1
		}
	}
	got := 3 - lost
	return []byte(fmt.Sprintf(`PING %[1]s (%[1]s): 56 data bytes

--- %[1]s ping statistics ---
3 packets transmitted, %[2]d packets received, %.1[3]f%% packet loss
round-trip min/avg/max/std-dev = %.3[4]f/%.3[5]f/%.3[6]f/0.412 ms
`, addr, got, float64(lost)*100/3, rtt-0.6, rtt, rtt+0.9)), nil
}

// mockList is a list as its publisher would serve it, in the format its
// URL suggests, so every parser gets exercised.
func mockList(url string) string {
	var b strings.Builder
	names := []string{"ads", "tracker", "metrics", "pixel", "beacon", "adserver", "telemetry", "banner"}
	sites := []string{"example.com", "example.net", "example.org", "ads.example", "track.example"}
	switch {
	case strings.Contains(url, "hosts"):
		b.WriteString("# Sample hosts blocklist\n127.0.0.1 localhost\n::1 localhost\n0.0.0.0 0.0.0.0\n")
		for i := range 60 {
			fmt.Fprintf(&b, "0.0.0.0 %s%d.%s\n", names[i%len(names)], i, sites[i%len(sites)])
		}
	case strings.Contains(url, "easylist"), strings.Contains(url, "adblock"), strings.Contains(url, "adguard"):
		b.WriteString("[Adblock Plus 2.0]\n! Title: Sample list\n")
		for i := range 40 {
			fmt.Fprintf(&b, "||%s%d.%s^\n", names[i%len(names)], i, sites[i%len(sites)])
		}
		b.WriteString("@@||cdn.example.com^\n||example.com^$third-party\n/banner/ads/*\nexample.com##.ad-slot\n||example.net/ads/^\n")
	case strings.Contains(url, "rpz"):
		b.WriteString("$TTL 300\n@ SOA localhost. root.localhost. 1 3600 600 86400 300\n  NS localhost.\n")
		for i := range 50 {
			fmt.Fprintf(&b, "%s%d.%s CNAME .\n*.%s%d.%s CNAME .\n", names[i%len(names)], i, sites[i%len(sites)], names[i%len(names)], i, sites[i%len(sites)])
		}
	case strings.Contains(url, "domains"):
		b.WriteString("# Sample domain list\n")
		for i := range 70 {
			fmt.Fprintf(&b, "%s%d.%s\n", names[i%len(names)], i, sites[i%len(sites)])
		}
	default:
		b.WriteString("; Sample DROP list\n; Last-Modified: " + time.Now().UTC().Format(time.RFC1123) + "\n")
		for i := range 40 {
			fmt.Fprintf(&b, "%d.%d.%d.0/24 ; SBL%d\n", 45+i%7, 90+i, (i*37)%250, 100000+i)
		}
	}
	return b.String()
}
