package conformance

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// TestSystemFormats runs the base system's Formats (formats_system.go)
// over the real OpenBSD 7.9 captures in the repository, and over
// samples written as the source prints the variants the captures lack.

// sysRead reads a file under internal/.
func sysRead(t *testing.T, rel string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", rel))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// sysCheck fails on every problem Check finds.
func sysCheck(t *testing.T, command, what, out string) {
	t.Helper()
	f, ok := Formats[command]
	if !ok {
		t.Fatalf("no Format for %q", command)
	}
	for _, p := range f.Check(out) {
		t.Errorf("%s (%s): %s", command, what, p)
	}
}

// sysCheckBad checks out and wants exactly the problems that name the
// given lines: lines a sample wrote that the source can't print.
func sysCheckBad(t *testing.T, command, what, out string, bad ...string) {
	t.Helper()
	var want []string
	for _, b := range bad {
		want = append(want, fmt.Sprintf("%q", b))
	}
	var got []string
	for _, p := range Formats[command].Check(out) {
		i := slices.IndexFunc(want, func(w string) bool { return strings.HasSuffix(p, w) })
		if i < 0 {
			t.Errorf("%s (%s): %s", command, what, p)
			continue
		}
		got = append(got, want[i])
	}
	for _, w := range want {
		if !slices.Contains(got, w) {
			t.Errorf("%s (%s): the Format takes %s, which the source can't print", command, what, w)
		}
	}
}

// sysWithoutExit drops the "exit N" line the capture script appended.
func sysWithoutExit(out string) string {
	return regexp.MustCompile(`(?m)^exit \d+\n?\z`).ReplaceAllString(out, "")
}

// sysSysctlPick keeps the given names' entries (a name's line and the
// lines that continue it) from sysctl captures taken with more names.
func sysSysctlPick(out string, names ...string) string {
	var b strings.Builder
	keep := false
	for _, l := range strings.SplitAfter(out, "\n") {
		if k, _, ok := strings.Cut(l, "="); ok && regexp.MustCompile(`^[a-z]+(\.[a-z0-9_]+)+$`).MatchString(k) {
			keep = slices.Contains(names, k)
		}
		if keep {
			b.WriteString(l)
		}
	}
	return b.String()
}

const sys79 = "sysinfo/testdata/openbsd-7.9/"

func TestSystemFormatsSysctl(t *testing.T) {
	inRepo(t)
	kern := sysRead(t, sys79+"sysctl_kern.txt")
	sysCheck(t, "sysctl kern.osrelease", "capture", sysSysctlPick(kern, "kern.osrelease"))
	// sysctl_hw.txt also has hw.ncpu and hw.cpuspeed, which OPF doesn't
	// ask for; the machine (amd64) isn't in the captures.
	status := kern + sysRead(t, sys79+"sysctl_kern_boottime.txt") +
		sysSysctlPick(sysRead(t, sys79+"sysctl_hw.txt"), "hw.model", "hw.vendor", "hw.product", "hw.ncpuonline") +
		"hw.machine=amd64\n" + sysRead(t, sys79+"sysctl_hw_physmem.txt") + sysRead(t, sys79+"sysctl_vm_loadavg.txt")
	sysCheck(t, "sysctl kern.hostname kern.osrelease kern.version kern.boottime hw.machine hw.model hw.vendor hw.product hw.ncpuonline hw.physmem vm.loadavg", "captures", status)
	// A machine without SMBIOS (sysctl's warnx), a single-digit day, a
	// -current kernel.
	sysCheck(t, "sysctl kern.hostname kern.osrelease kern.version kern.boottime hw.machine hw.model hw.vendor hw.product hw.ncpuonline hw.physmem vm.loadavg", "sample",
		"kern.hostname=gw\nkern.osrelease=7.9\nkern.version=OpenBSD 7.9-current (GENERIC.MP) #102: Fri Oct  2 09:11:04 MDT 2026\n"+
			"    deraadt@amd64.openbsd.org:/usr/src/sys/arch/amd64/compile/GENERIC.MP\n\n"+
			"kern.boottime=Fri Oct  2 09:30:01 2026\nhw.machine=amd64\nhw.model=Intel(R) Celeron(R) N5105 @ 2.00GHz\n"+
			"sysctl: hw.vendor: value is not available\nsysctl: hw.product: value is not available\n"+
			"hw.ncpuonline=4\nhw.physmem=8361398272\nvm.loadavg=1.25 0.90 0.71\n")
	sysCheck(t, "sysctl kern.cp_time", "capture", sysRead(t, sys79+"sysctl_kern_cp_time.txt"))
	sysCheck(t, "sysctl kern.cp_time vm.loadavg hw.physmem", "captures",
		sysRead(t, sys79+"sysctl_kern_cp_time.txt")+sysRead(t, sys79+"sysctl_vm_loadavg.txt")+sysRead(t, sys79+"sysctl_hw_physmem.txt"))

	sysCheck(t, "sysctl hw.sensors", "capture", sysRead(t, sys79+"sysctl_hw_sensors.txt"))
	// One of each type, as print_sensor prints it.
	sysCheck(t, "sysctl hw.sensors", "sample", `hw.sensors.cpu0.temp0=45.00 degC
hw.sensors.acpitz0.temp0=27.80 degC (zone temperature)
hw.sensors.lm0.fan1=2311 RPM
hw.sensors.lm0.volt0=1.18 VDC (VCore A), OK
hw.sensors.upd0.acvolt0=230.00 VAC
hw.sensors.x0.resistance0=120 ohm
hw.sensors.acpibat0.power0=0.00 W (rate)
hw.sensors.x0.current0=1.25 A
hw.sensors.acpibat0.watthour0=47.52 Wh (last full capacity)
hw.sensors.acpibat0.amphour0=3.10 Ah
hw.sensors.acpiac0.indicator0=On (power supply)
hw.sensors.acpibat0.raw0=0 (battery idle), OK
hw.sensors.upd0.percent0=100.00% (RelativeStateOfCharge), OK
hw.sensors.x0.illuminance0=310.00 lx
hw.sensors.softraid0.drive0=online (sd2), OK
hw.sensors.sd0.drive0=degraded, WARNING
hw.sensors.nmea0.timedelta0=-0.000123 secs (GPS), OK, Fri Oct  2 09:30:01.123
hw.sensors.ugold0.humidity0=41.28%
hw.sensors.x0.frequency0=50.00 Hz
hw.sensors.x0.angle0=12.5000 degrees
hw.sensors.nmea0.distance0=104.500 m (Altitude)
hw.sensors.x0.pressure0=101325.00 Pa
hw.sensors.x0.acceleration0=9.8100 m/s^2
hw.sensors.x0.velocity0=1.500 m/s
hw.sensors.x0.energy0=12.00 J
hw.sensors.it0.temp2=unknown, UNKNOWN
hw.sensors.acpitz0.temp0=95.00 degC (zone temperature), CRITICAL
`)
	sysCheck(t, "sysctl hw.sensors", "none", "")
}

func TestSystemFormatsMemoryAndDisks(t *testing.T) {
	inRepo(t)
	sysCheck(t, "vmstat -s", "capture", sysRead(t, sys79+"vmstat_-s.txt"))

	sysCheck(t, "swapctl -lk", "capture", sysRead(t, sys79+"swapctl_-lk.txt"))
	sysCheck(t, "swapctl -lk", "two devices",
		"Device      1K-blocks     Used    Avail Capacity  Priority\n"+
			"/dev/sd0b     2342760    10240  2332520     0%    0\n"+
			"/dev/sd1b     1048576        0  1048576     0%    0\n"+
			"Total         3391336    10240  3381096     0%\n")
	sysCheck(t, "swapctl -lk", "no swap", "swapctl: no swap devices configured\n")

	// df -kP is df -kPl's format: -l only leaves out non-local mounts.
	sysCheck(t, "df -kPl", "capture of df -kP", sysRead(t, sys79+"df_-kP.txt"))
	sysCheck(t, "df -kPl", "full, into the reserve", "Filesystem  1024-blocks       Used   Available Capacity Mounted on\n"+
		fmt.Sprintf("%-*.*s %*d %10d %11d %5d%%   %s\n", 9, 9, "/dev/sd0a", 11, 1009422, 1009422, -50471, 105, "/"))
}

func TestSystemFormatsTimeAndDNS(t *testing.T) {
	inRepo(t)
	sysCheck(t, "ntpctl -s all", "capture", sysRead(t, sys79+"ntpctl_-s_all.txt"))
	sysCheck(t, "ntpctl -s all", "capture of -s status", sysRead(t, sys79+"ntpctl_-s_status.txt"))
	sysCheck(t, "ntpctl -s all", "unsynced", "2/4 peers valid, constraint offset 0s (2 errors), clock unsynced, clock offset is 12.345ms\n\n"+
		"peer\n   wt tl st  next  poll          offset       delay      jitter\n"+
		"not resolved from pool pool.ntp.org\n"+
		fmt.Sprintf(" %1s %2d %2d %2s %4ds %4ds", " ", 1, 2, " -", 5, 15)+"             ---- peer not valid ----\n"+
		"2001:db8::123 ntp.example.org (non-dnssec lookup)\n"+
		fmt.Sprintf(" %1s %2d %2d %2s %4ds %4ds", " ", 1, 10, " 2", 25, 32)+fmt.Sprintf("  %12.3fms %9.3fms  %8.3fms\n", -1.031, 1.486, 0.064)+
		"\nsensor\n   wt gd st  next  poll          offset  correction\n"+
		"nmea0  GPS\n"+fmt.Sprintf(" %1s %2d %2d %2d %4ds %4ds", " ", 1, 0, 0, 3, 15)+"         - sensor not valid -\n")
	sysCheck(t, "ntpctl -s all", "nothing configured", "no peers and no sensors configured\nclock unsynced\nno peers configured\nno sensors configured\n")
	sysCheck(t, "ntpctl -s all", "not running", "ntpctl: connect: /var/run/ntpd.sock: No such file or directory\n")

	sysCheck(t, "cat /etc/resolv.conf", "capture", sysRead(t, sys79+"resolv.conf.txt"))
	// unwind running: resolvd comments its servers out; then lines
	// someone wrote, which resolvd keeps.
	sysCheck(t, "cat /etc/resolv.conf", "sample", "nameserver 127.0.0.1 # resolvd: unwind\n"+
		"#nameserver 192.168.1.1 # resolvd: em0\n#nameserver fe80::1%em0 # resolvd: em0\n"+
		"# kept by hand\nsearch example.org lan\nnameserver 9.9.9.9\nlookup file bind\nfamily inet6 inet4\noptions edns0 ndots:2\n\n")
}

// sysIfconfigExtra has the interface types the captures lack, as
// status and its helpers print them.
const sysIfconfigExtra = `em2: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> rdomain 1 mtu 1500
	lladdr 00:0d:b9:5e:21:a2
	description: Guests
	index 3 priority 0 llprio 3
	groups: guests
	media: Ethernet autoselect (1000baseT full-duplex,rxpause,txpause)
	status: active
	inet 10.0.20.1 netmask 0xffffff00 broadcast 10.0.20.255
	inet6 fe80::20d:b9ff:fe5e:21a2%em2 prefixlen 64 scopeid 0x3
	inet6 2001:db8:20::1 prefixlen 64 autoconf temporary
pfsync0: flags=41<UP,RUNNING> mtu 1500
	index 9 priority 0 llprio 3
	pfsync: syncdev: em2 syncpeer: 10.0.20.2 maxupd: 128 defer: off
	groups: carp pfsync
pflow0: flags=41<UP,RUNNING> mtu 1492
	index 11 priority 0 llprio 3
	pflow: receiver: 127.0.0.1:9995 version: 10
	groups: pflow
pflow1: flags=41<UP,RUNNING> mtu 1492
	index 12 priority 0 llprio 3
	pflow: sender: 192.168.1.1 receiver: 192.0.2.50:2055 version: 5
	groups: pflow
pflow2: flags=0<> mtu 1492
	index 13 priority 0 llprio 3
	pflow: receiver: [2001:db8::5]:2055 version: 10
	groups: pflow
pflow3: flags=1<UP> mtu 1492
	index 14 priority 0 llprio 3
	pflow: receiver: INVALID:INVALID version: 5
	groups: pflow
vether0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	lladdr fe:e1:ba:d0:12:34
	index 10 priority 0 llprio 3
	groups: vether
	media: Ethernet autoselect
	status: active
	inet 10.0.5.1 netmask 0xffffff00 broadcast 10.0.5.255
pair0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	lladdr fe:e1:ba:d0:12:35
	index 11 priority 0 llprio 3
	patch: pair1
	groups: pair
	media: Ethernet autoselect
	status: active
tun0: flags=10<POINTOPOINT> mtu 1500
	index 12 priority 0 llprio 3
	groups: tun
	status: down
bridge0: flags=41<UP,RUNNING>
	index 13 llprio 3
	groups: bridge
	priority 32768 hellotime 2 fwddelay 15 maxage 20 holdcnt 6 proto rstp
	em2 flags=3<LEARNING,DISCOVER>
		port 3 ifpriority 0 ifcost 0
	vether0 flags=ab<LEARNING,DISCOVER,STP,AUTOEDGE,AUTOPTP>
		port 10 ifpriority 128 ifcost 55 forwarding role designated
	Addresses (max cache: 100, timeout: 240):
		fe:e1:ba:d0:12:34 vether0 0 flags=0<>
veb0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST>
	index 14 llprio 3
	groups: veb
	vport0 flags=3<LEARNING,DISCOVER>
		port 15 ifpriority 0 ifcost 0 untagged 10
		tagged: 20,30-32
	Addresses (max cache: 100, timeout: 240):
		fe:e1:ba:d0:12:36@10 vport0 12 flags=0<>
gre0: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1476
	index 16 priority 0 llprio 3
	keepalive: timeout 10 count 3
	encap: vnetid none txprio payload rxprio packet
	groups: gre
	tunnel: inet 192.0.2.1 --> 198.51.100.2 ttl 64 nodf ecn
	inet 10.99.1.1 --> 10.99.1.2 netmask 0xffffffff
gif1: flags=8010<POINTOPOINT,MULTICAST> mtu 1280
	index 19 priority 0 llprio 3
	groups: gif
	tunnel: (unset) ttl 64 nodf noecn
carp1: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	lladdr 00:00:5e:00:01:02
	index 17 priority 15 llprio 3
	carp: carpdev em1 advbase 1 balancing ip carppeer 10.0.20.2
		state MASTER vhid 2 advskew 0
		state BACKUP vhid 3 advskew 100
	groups: carp
	status: master
	inet 192.168.1.2 netmask 0xffffff00 broadcast 192.168.1.255
carp2: flags=8803<UP,BROADCAST,SIMPLEX,MULTICAST> mtu 1500
	lladdr 00:00:5e:00:01:03
	index 20 priority 15 llprio 3
	carp: INIT carpdev none vhid 3 advbase 1 advskew 0
	groups: carp
	status: invalid
wg1: flags=80c3<UP,BROADCAST,RUNNING,NOARP,MULTICAST> mtu 1420
	index 18 priority 0 llprio 3
	wgport 51821
	wgrtable 1
	wgpubkey kq3Xw0pY6m2VhT8cQf1LzR5nB7dJ4sA9gE0uWiOyHl8=
	wgpeer 7fN2cQ1sXbK9mV4pR8tY3wZ6hJ0dL5gE2aU9iO7yHk4=
		wgdescr: laptop
		wgendpoint 2001:db8::7 51820
		tx: 0, rx: 0
		wgaip fd00::2/128
		wgaip 10.8.1.0/24
	groups: wg
	inet6 fd00::1 prefixlen 64
aggr0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	lladdr fe:e1:ba:d0:aa:01
	index 15 priority 0 llprio 7
	trunk: trunkproto lacp
	trunk id: [(8000,fe:e1:ba:d0:aa:01,0007,0000,0000),
		 (FFFF,00:00:00:00:00:00,0000,0000,0000)]
		em4 lacp actor system pri 0x8000 mac fe:e1:ba:d0:aa:01, key 0x7, port pri 0x8000 number 0x2
		em4 lacp actor state activity,aggregation,defaulted
		em4 lacp partner system pri 0xffff mac 00:00:00:00:00:00, key 0x0, port pri 0x0 number 0x0
		em4 lacp partner state aggregation,sync,collecting,distributing,defaulted
		em4 port active,collecting,distributing
		em5 port 
	groups: aggr
	media: Ethernet autoselect
	status: active
em4: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	lladdr fe:e1:ba:d0:aa:01
	index 16 priority 0 llprio 3
	trunk: trunkdev aggr0
	media: Ethernet autoselect (1000baseT full-duplex)
	status: active
trunk0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	lladdr 00:0d:b9:5a:3c:13
	index 17 priority 0 llprio 3
	trunk: trunkproto failover
		em7 port active
		em6 port master,active
	groups: trunk
	media: Ethernet autoselect
	status: active
`

func TestSystemFormatsIfconfig(t *testing.T) {
	inRepo(t)
	sysCheck(t, "ifconfig -A", "capture", sysRead(t, sys79+"ifconfig_-A.txt"))
	sysCheck(t, "ifconfig -A", "sample", sysRead(t, sys79+"ifconfig_-A.txt")+sysIfconfigExtra)
	// The handwritten sample's wg peer description has no colon
	// (wg_status prints "\t\twgdescr: %s"), and its second peer's key
	// has 44 base64 characters before the "=": b64_ntop of a 32-byte key
	// has 43.
	sysCheckBad(t, "ifconfig -A", "handwritten", sysRead(t, "sysinfo/testdata/handwritten/ifconfig_-A.txt"),
		"\t\twgdescr Priya phone", "\twgpeer 3kP8vR2nX6cM1qT9wY4zB7fH0jL5dG2sA8eU3iO6yNm0=")

	// The egress group, without -A: wg_status leaves out the peers,
	// printif the addresses after an interface's first, and
	// bridge_cfg prints the designated and root bridges.
	sysCheck(t, "ifconfig egress", "sample", `vio0: flags=2248843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,AUTOCONF6TEMP,AUTOCONF6,LRO> mtu 1500
	lladdr bc:24:11:f6:5e:bd
	index 1 priority 0 llprio 3
	groups: egress
	media: Ethernet autoselect
	status: active
	inet 192.168.14.11 netmask 0xffffff00 broadcast 192.168.14.255
`)
	sysCheck(t, "ifconfig egress", "a bridge", "bridge1: flags=41<UP,RUNNING>\n\tindex 21 llprio 3\n\tgroups: bridge egress\n"+
		"\tpriority 32768 hellotime 2 fwddelay 15 maxage 20 holdcnt 6 proto rstp\n"+
		"\tdesignated: id 00:0d:b9:5e:21:a0 priority 32768\n\troot: id 00:0d:b9:5e:21:a9 priority 4096 ifcost 20000 port 3\n")
	sysCheck(t, "ifconfig egress", "none", "egress: no such interface\n")
	if p := Formats["ifconfig egress"].Check("\twgpeer 7fN2cQ1sXbK9mV4pR8tY3wZ6hJ0dL5gE2aU9iO7yHk4=\n"); len(p) == 0 {
		t.Error("ifconfig egress takes a wg peer, which only -A prints")
	}
}

// sysRoute is a netstat -r row, as p_rtentry prints it.
func sysRoute(w, gw int, dst, gate, flags string, refs, use int, mtu string, prio int, iface string) string {
	return fmt.Sprintf("%-*s %-*s %-6.6s %5d %8d %5s    %2d %-5.16s\n", w, dst, gw, gate, flags, refs, use, mtu, prio, iface)
}

func TestSystemFormatsNetwork(t *testing.T) {
	inRepo(t)
	sysCheck(t, "netstat -ibn", "capture", sysRead(t, sys79+"netstat_-ibn.txt"))
	sysCheck(t, "netstat -in", "capture", sysRead(t, sys79+"netstat_-in.txt"))

	inet := "Routing tables\n\nInternet:\n" +
		fmt.Sprintf("%-*.*s %-*.*s %-6.6s %5.5s %8.8s %5.5s  %4.4s %s\n", 18, 18, "Destination", 18, 18, "Gateway", "Flags", "Refs", "Use", "Mtu", "Prio", "Iface") +
		sysRoute(18, 18, "default", "192.168.14.1", "UGS", 4, 102, "-", 8, "vio0") +
		sysRoute(18, 18, "224/4", "127.0.0.1", "URS", 0, 0, "32768", 8, "lo0") +
		sysRoute(18, 18, "127/8", "127.0.0.1", "UGRS", 0, 0, "32768", 8, "lo0") +
		sysRoute(18, 18, "127.0.0.1", "127.0.0.1", "UHhl", 1, 2, "32768", 1, "lo0") +
		sysRoute(18, 18, "192.168.14/24", "192.168.14.11", "UCn", 2, 0, "-", 4, "vio0") +
		sysRoute(18, 18, "192.168.14.1", "bc:24:11:00:00:01", "UHLch", 1, 34, "-", 3, "vio0") +
		sysRoute(18, 18, "192.168.14.11", "bc:24:11:f6:5e:bd", "UHLl", 0, 12, "-", 1, "vio0") +
		sysRoute(18, 18, "192.168.14.255", "192.168.14.11", "UHb", 0, 0, "-", 1, "vio0")
	sysCheck(t, "netstat -rnf inet", "sample", inet)
	inet6 := "Routing tables\n\nInternet6:\n" +
		fmt.Sprintf("%-*.*s %-*.*s %-6.6s %5.5s %8.8s %5.5s  %4.4s %s\n", 43, 43, "Destination", 39, 39, "Gateway", "Flags", "Refs", "Use", "Mtu", "Prio", "Iface") +
		sysRoute(43, 39, "::/96", "::1", "UGRS", 0, 0, "32768", 8, "lo0") +
		sysRoute(43, 39, "::1", "::1", "UHhl", 10, 30, "32768", 1, "lo0") +
		sysRoute(43, 39, "fe80::%vio0/64", "fe80::be24:11ff:fef6:5ebd%vio0", "UCn", 0, 0, "-", 4, "vio0") +
		sysRoute(43, 39, "fe80::be24:11ff:fef6:5ebd%vio0", "bc:24:11:f6:5e:bd", "UHLl", 0, 0, "-", 1, "vio0") +
		sysRoute(43, 39, "ff02::%vio0/16", "fe80::be24:11ff:fef6:5ebd%vio0", "Um", 0, 1, "-", 4, "vio0")
	sysCheck(t, "netstat -rnf inet6", "sample", inet6)
	// A locked MTU (route -mtu 1400 -lock): "L" after it.
	sysCheck(t, "netstat -rnf inet", "locked mtu", "Routing tables\n\nInternet:\n"+
		fmt.Sprintf("%-*.*s %-*.*s %-6.6s %5.5s %8.8s %5.5s  %4.4s %s\n", 18, 18, "Destination", 18, 18, "Gateway", "Flags", "Refs", "Use", "Mtu", "Prio", "Iface")+
		fmt.Sprintf("%-*s %-*s %-6.6s %5d %8d %5d %c  %2d %-5.16s\n", 18, "10.9/16", 18, "192.168.14.1", "UGS", 0, 0, 1400, 'L', 8, "vio0"))

	arp := fmt.Sprintf("%-*.*s %-*.*s %*.*s %-9.9s %5s\n", 36, 36, "Host", 17, 17, "Ethernet Address", 7, 7, "Netif", "Expire", "Flags")
	for _, e := range [][]string{
		{"192.168.14.1", "bc:24:11:00:00:01", "vio0", "19m52s", ""},
		{"192.168.14.11", "bc:24:11:f6:5e:bd", "vio0", "permanent", "l"},
		{"192.168.14.40", "(incomplete)", "vio0", "expired", ""},
		{"192.168.14.50", "bc:24:11:00:00:50", "vio0", "static", "p"},
		{"192.168.14.51", "bc:24:11:00:00:51", "?", "1d23h59m5", ""}, // sec2str cut to 9
	} {
		arp += fmt.Sprintf("%-*.*s %-*.*s %*.*s %-9.9s %s\n", 36, 36, e[0], 17, 17, e[1], 7, 7, e[2], e[3], e[4])
	}
	sysCheck(t, "arp -an", "sample", arp)
}

func TestSystemFormatsPing(t *testing.T) {
	inRepo(t)
	for _, f := range []string{"ping_ok.txt", "ping_fast.txt", "ping_lost.txt"} {
		sysCheck(t, "ping -n -q -c 3 -i 0.2 -w 1 -- *", f, sysWithoutExit(sysRead(t, sys79+f)))
	}
	sysCheck(t, "ping6 -n -q -c 3 -i 0.2 -w 1 -- *", "sample",
		"PING ::1 (::1): 56 data bytes\n\n--- ::1 ping statistics ---\n3 packets transmitted, 3 packets received, 0.0% packet loss\n"+
			"round-trip min/avg/max/std-dev = 0.053/0.067/0.090/0.016 ms\n")
	sysCheck(t, "ping6 -n -q -c 3 -i 0.2 -w 1 -- *", "no route",
		"ping6: sendmsg: No route to host\nPING 2001:db8::1 (2001:db8::1): 56 data bytes\nping: wrote 2001:db8::1 64 chars, ret=-1\n\n"+
			"--- 2001:db8::1 ping statistics ---\n3 packets transmitted, 0 packets received, 100.0% packet loss\n")
	sysCheck(t, "ping -n -q -c 3 -i 0.2 -w 1 -- *", "duplicates",
		"PING 192.168.14.1 (192.168.14.1): 56 data bytes\n\n--- 192.168.14.1 ping statistics ---\n"+
			"3 packets transmitted, 3 packets received, 1 duplicates, 0.0% packet loss\n"+
			"round-trip min/avg/max/std-dev = 0.134/0.188/0.230/0.040 ms\n")
}

func TestSystemFormatsProcessesAndFiles(t *testing.T) {
	inRepo(t)
	sysCheck(t, "ps -A -o rss=,comm=", "capture", sysRead(t, sys79+"ps_-A_-o_rss_comm.txt"))
	ps := fmt.Sprintf("%5s %-28s %s\n", "PID", "STARTED", "COMMAND") +
		fmt.Sprintf("%5d %-28s %s\n", 1, "Tue Sep 29 16:09:55 2026", "/sbin/init") +
		fmt.Sprintf("%5d %-28s %s\n", 0, "-", "(swapper)") +
		fmt.Sprintf("%5d %-28s %s\n", 34725, "Thu Oct  8 01:02:42 2026", "-authpf: alice@10.0.0.5 (authpf)") +
		fmt.Sprintf("%5d %-28s %s\n", 123456, "Thu Oct  8 01:02:42 2026", "/usr/sbin/sshd -R")
	sysCheck(t, "ps -axww -o pid,lstart,command", "sample", ps)

	sysCheck(t, "cat /etc/newsyslog.conf", "capture", sysRead(t, sys79+"newsyslog.conf.txt"))
	// Shapes newsyslog takes but ParseNewsyslog misreads.
	sysCheckBad(t, "cat /etc/newsyslog.conf", "owner.group and lower-case flags",
		"/var/log/messages\t\t\t644  5     300  *     Z\n/var/log/a\troot.wheel\t640  7     *    168   Z\n/var/log/b\t\t\t640  7     *    168   z\n",
		"/var/log/a\troot.wheel\t640  7     *    168   Z", "/var/log/b\t\t\t640  7     *    168   z")

	ls := fmt.Sprintf("%s %*d %-*s  %-*s  %*d %s %s\n", "-rw-r----- ", 1, 1, 1, "0", 1, "0", 7, 1234567, "Oct  9 10:00", "/var/log/daemon") +
		fmt.Sprintf("%s %*d %-*s  %-*s  %*d %s %s\n", "-rw------- ", 1, 1, 1, "0", 1, "0", 7, 33124, "Mar  1  2025", "/var/log/pflog") +
		"ls: /var/log/daemon.0.gz: No such file or directory\n"
	sysCheck(t, "ls -ln ...", "sample", ls)

	sysCheck(t, "diff -u -L * -L * * *", "sample", "--- pf.conf (live)\n+++ pf.conf (staged)\n@@ -1,3 +1,4 @@\n set skip on lo\n+block log\n \n"+
		" pass\n@@ -10 +11,0 @@\n-match out on egress nat-to (egress)\n")
	sysCheck(t, "diff -u -L * -L * * *", "same", "")
	sysCheck(t, "dmesg", "sample", "OpenBSD 7.9 (GENERIC.MP) #15: Sun Sep 27 02:47:36 MDT 2026\nvio0 at virtio1: address bc:24:11:f6:5e:bd\n")
}

func TestSystemFormatsSyslog(t *testing.T) {
	inRepo(t)
	sysCheck(t, "tail -n * *", "sample", `2026-10-10T00:00:07.661Z gw newsyslog[44465]: logfile turned over
Oct  9 10:00:00 gw syslogd[43102]: restart
Oct  9 10:00:00 gw /bsd: vio0: link state changed to UP
Oct  9 10:00:01 gw -- MARK --
Oct  9 10:00:02 gw doas: admin ran command rcctl restart unbound as root from /home/admin
Oct  9 10:00:02 gw last message repeated 3 times
Oct  9 10:00:03 gw unbound: [29114:0] notice: init module 0: validator
Oct  9 10:00:04 gw unbound: [29114:1] info: rpz: applied [opf:list:x] clientip 192.168.1.0/24 rpz-drop 192.168.1.23@51932 a.example. A IN
Oct  9 10:00:05 gw unbound: [29114:0] info: rpz: applied [opf:own] nsip 192.0.2.53/32 rpz-nxdomain 192.168.1.23@51933 b.example. AAAA IN
Oct  9 10:00:06 gw unbound: [29114:0] info: rpz: applied [opf:own] c.example. rpz-cname-override 192.168.1.23@51934 c.example. TYPE65 IN
`)
	// The handwritten samples are for the parsers' robustness; these
	// lines are ones syslogd and unbound can't write: no timestamp and
	// host; a continuation (syslogd vis-encodes control characters); a
	// pid that isn't a number (syslogd writes what the client sent, but
	// no OpenBSD program sends that); rpz lines with no query, a port
	// that isn't a number and an action rpz_action_to_string has no
	// name for.
	sysCheckBad(t, "tail -n * *", "handwritten syslog", sysRead(t, "sysinfo/testdata/handwritten/syslog_messages.txt"),
		"not a syslog line", "Sep 30 09:23:00 gw sshd[bad]: odd pid", "\tcontinuation of something")
	sysCheckBad(t, "tail -n * *", "handwritten rpz", sysRead(t, "sysinfo/testdata/handwritten/daemon_rpz.txt"),
		"Sep 29 10:00:08 gw unbound: [29114:0] info: rpz: applied [opf:list:hagezi] broken",
		"Sep 29 10:00:09 gw unbound: [29114:0] info: rpz: applied [opf:list:hagezi] a.example. rpz-local-data 192.168.1.23@notaport a.example. A IN",
		"Sep 29 10:00:10 gw unbound: [29114:0] info: rpz: applied [opf:list:hagezi] a.example. made-up 192.168.1.23@5199 a.example. A IN")
	// syslogd -Z's timestamps, which ParseSyslog skips.
	if len(Formats["tail -n * *"].Check("2026-10-09T10:00:00.123Z gw syslogd[1]: restart\n")) == 0 {
		t.Error("the syslog Format takes an ISO timestamp, which OPF's parser skips")
	}
}

func TestSystemFormatsServicesAndPatches(t *testing.T) {
	inRepo(t)
	sysCheck(t, "rcctl ls all", "sample", "accounting\ncheck_quotas\ncron\ndhcpd\nipsec\nlibrary_aslr\nmulticast\nntpd\npf\nspamd_black\nsshd\nunbound\n")
	sysCheck(t, "rcctl ls on", "sample", "check_quotas\ncron\nlibrary_aslr\nntpd\npf\nsshd\n")
	sysCheck(t, "rcctl ls started", "sample", "cron\nntpd\nsshd\n")
	sysCheck(t, "rcctl get *", "a daemon", "unbound_class=daemon\nunbound_execdir=\nunbound_flags=-c /var/unbound/etc/unbound.conf\n"+
		"unbound_logger=\nunbound_rtable=0\nunbound_timeout=30\nunbound_user=root\n")
	sysCheck(t, "rcctl get *", "a special service", "pf=YES\n")
	sysCheck(t, "rcctl get *", "no such service", "rcctl: service nosuch does not exist\n")
	sysCheck(t, "rcctl check *", "sample", "sshd(ok)\n")
	sysCheck(t, "rcctl check *", "stopped", "unbound(failed)\n")
	sysCheck(t, "rcctl check *", "special", "rcctl: \"pf\" is a special variable, no rc.d(8) script\n")
	sysCheck(t, "rcctl get opf flags", "sample", "-readonly\n")
	sysCheck(t, "getent hosts *", "sample", "192.0.2.81                              vpn.example.net\n2001:db8::81                            vpn.example.net\n")
	if len(Formats["rcctl ls all"].Check("Foo\n")) == 0 {
		t.Error("rcctl ls takes a name services.go's serviceNameRE drops")
	}

	sysCheck(t, "syspatch -c", "capture", sysRead(t, "sysinfo/testdata/openbsd-other/syspatch_-c.txt"))
	sysCheck(t, "syspatch -c", "up to date", "")
	sysCheck(t, "syspatch -c", "-current", "syspatch: Unsupported release: 7.9-current\n")
	sysCheck(t, "syspatch -c", "offline", "ftp: cdn.openbsd.org: no address associated with name\nsignify: unable to open /tmp/syspatch.k2Wl8x1Q/SHA256.sig: No such file or directory\n")

	sysCheck(t, "encrypt", "sample", "$2b$10$"+"Pz3wdG2Lf4Xc9.u/9kQ1ce"+"lZ6TqZ3o8RkM2rN0eYb1Hk7sW5vVa9y\n")
	sysCheck(t, "ftp -V -o - -- *", "404", "ftp: Error retrieving https://example.com/list.txt: 404 Not Found\n")
	sysCheck(t, "ftp -V -o - -- *", "dns", "ftp: nonexistent.invalid: no address associated with name\n")
	sysCheck(t, "ftp -V -o - -- *", "tls", "TLS handshake failure: certificate verification failed: certificate has expired\n")
	sysCheck(t, "ftp -V -o - -- *", "refused", "ftp: connect: Connection refused\n")
}

// TestSystemFormatsTools checks every run in the diagnostics tools'
// capture against its tool's Format.
func TestSystemFormatsTools(t *testing.T) {
	inRepo(t)
	var cmd []string
	var out strings.Builder
	runs := 0
	for _, l := range strings.SplitAfter(sysRead(t, "diag/testdata/openbsd-7.9-tools.txt"), "\n") {
		switch h, ok := strings.CutPrefix(l, "### "); {
		case ok && strings.HasPrefix(h, "exit "):
			sysCheck(t, "tool "+cmd[0], strings.Join(cmd, " "), out.String())
			out.Reset()
			runs++
		case ok:
			cmd = strings.Fields(h)
		default:
			out.WriteString(l)
		}
	}
	if runs < 20 {
		t.Errorf("read %d runs from the tools capture", runs)
	}
	// What the capture lacks: replies with -A and a name, timeouts and
	// unreachables, nc with a name.
	sysCheck(t, "tool traceroute", "sample", "traceroute to example.com (93.184.215.14), 30 hops max, 60 byte packets\n"+
		" 1  192.168.14.1  0.244 ms  0.201 ms  0.198 ms\n 2  * * *\n 3  10.50.48.253  0.261 ms *  0.3 ms\n"+
		" 4  66.70.178.252 (66.70.178.252) [AS16276]  0.853 ms ae1.example.net (198.51.100.1) [AS64500, AS64501]  1.2 ms !H  1.1 ms !H\n"+
		" 5  93.184.215.14  12.5 ms !<13>  12.4 ms (TOS=0!)  12.4 ms [MPLS Label 24005 (Exp 1)]\n")
	sysCheck(t, "tool ping", "replies", "PING example.com (93.184.215.14): 56 data bytes\n64 bytes from 93.184.215.14: icmp_seq=0 ttl=52 time=1.395 ms\n"+
		"64 bytes from 93.184.215.14: icmp_seq=0 ttl=52 time=1.401 ms (DUP!)\n\n--- example.com ping statistics ---\n"+
		"1 packets transmitted, 2 packets received, 1 duplicates, -- somebody's duplicating packets!\n"+
		"round-trip min/avg/max/std-dev = 1.395/1.398/1.401/0.003 ms\n")
	sysCheck(t, "tool ping6", "replies", "PING ::1 (::1): 56 data bytes\n64 bytes from ::1: icmp_seq=0 hlim=64 time=0.065 ms\n\n"+
		"--- ::1 ping statistics ---\n1 packets transmitted, 1 packets received, 0.0% packet loss\nround-trip min/avg/max/std-dev = 0.065/0.065/0.065/0.000 ms\n")
	sysCheck(t, "tool nc", "names", "Connection to example.com (93.184.215.14) 443 port [tcp/https] succeeded!\n"+
		"nc: connect to example.com (93.184.215.14) port 81 (tcp) failed: Connection refused\n")
	sysCheck(t, "tool dig", "trace", "\n; <<>> dig 9.10.8-P1 <<>> example.com +trace +dnssec\n;; global options: +cmd\n"+
		".\t\t\t518400\tIN\tNS\ta.root-servers.net.\n.\t\t\t518400\tIN\tRRSIG\tNS 8 0 518400 20261022050000 20261009040000 61809 . kQ1x\n"+
		";; Received 525 bytes from 127.0.0.1#53(127.0.0.1) in 0 ms\n\n")
}

// TestSystemFormatsReject checks that a renamed or reshaped line fails.
func TestSystemFormatsReject(t *testing.T) {
	inRepo(t)
	for _, c := range []struct{ command, line string }{
		{"vmstat -s", "     668420 pages freed"},
		{"vmstat -s", "668420 pages free"},
		{"sysctl hw.sensors", "hw.sensors.cpu0.temp0=45.00 degF"},
		{"sysctl hw.sensors", "hw.sensors.cpu0.heat0=45.00 degC"},
		{"sysctl kern.cp_time", "kern.cp_time=301,0,217,39,12"},
		{"ifconfig -A", "\tnewthing: x"},
		{"ifconfig -A", "\tstatus: half-up"},
		{"ifconfig -A", "\tpflow: receiver: 127.0.0.1 version: 10"},
		{"ifconfig -A", "\tmedia: Ethernet 800GbaseX"},
		{"ifconfig -A", "vio0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,NEWFLAG> mtu 1500"},
		{"ifconfig -A", "\tcarp: ACTIVE carpdev em1 vhid 1 advbase 1 advskew 0"},
		{"netstat -ibn", "Name    Mtu   Network     Address               Ibytes     Obytes  Drops"},
		{"netstat -in", "vio0    1500  <Link>      bc:24:11:f6:5e:bd      477     0      474     0"},
		{"ntpctl -s all", "5/5 peers valid, clock synchronised, stratum 1"},
		{"df -kPl", "Filesystem  1K-blocks       Used   Available Capacity Mounted on"},
		{"swapctl -lk", "/dev/sd0b     2342760        0  2342760     0%"},
		{"netstat -rnf inet", fmt.Sprintf("%-18s %-18s %-6.6s %5d %8d %5s    %2d %-5.16s", "default", "192.168.14.1", "UGSX", 4, 102, "-", 8, "vio0")},
		{"arp -an", "Host                                 Ethernet Address    Netif Expire    Flags Extra"},
		{"tail -n * *", "Oct  9 10:00:03 gw unbound: started"},
		{"tail -n * *", "Oct  9 10:00:03 gw unbound: [1:0] info: rpz: applied [opf:own] a.example. rpz-blackhole 192.168.1.2@53 a.example. A IN"},
		{"rcctl get *", "unbound_newvar=1"},
		{"ps -axww -o pid,lstart,command", "  PID STARTED                      CMD"},
		{"tool dig", ";; ->>HEADER<<- opcode: QUERY, status: NOPE, id: 1"},
		{"tool nc", "Connection to 9.9.9.9 443 port [tcp/https] open"},
		{"encrypt", "$2a$10$Pz3wdG2Lf4Xc9.u/9kQ1celZ6TqZ3o8RkM2rN0eYb1Hk7sW5vVa9y"},
	} {
		if !slices.ContainsFunc(Formats[c.command].Check(c.line+"\n"), func(p string) bool { return strings.Contains(p, "fits no kind") }) {
			t.Errorf("%s takes %q", c.command, c.line)
		}
	}
}
