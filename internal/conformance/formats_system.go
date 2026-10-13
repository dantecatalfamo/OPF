package conformance

import (
	"fmt"
	"regexp"
	"strings"
)

// The output of the base system's commands that OPF reads (everything
// but pfctl, tcpdump and unbound), line by line, as OpenBSD 7.9's
// source prints it. Each Format names the function that prints its
// lines. OPF runs every command through run.Runner, which gives stdout
// and stderr together, so the error lines a command can print are part
// of its output here too.
//
// Names OPF knows (sysctl names, vmstat's counters, ifconfig's
// keywords, flags, media and link states, rcctl's variables, dig's
// sections) are spelled out, so a new or renamed one fails.

// Pieces of lines many commands print.
const (
	sysIPv4 = `(?:\d{1,3}\.){3}\d{1,3}`
	// sysIPv6 is an address as inet_ntop or getnameinfo(NI_NUMERICHOST)
	// prints it, with a link-local address's zone.
	sysIPv6 = `(?:[0-9a-f]{0,4}:[0-9a-f:.]*(?:%[a-z]+\d+)?)`
	sysIP   = `(?:` + sysIPv4 + `|` + sysIPv6 + `)`
	// sysMAC is ether_ntoa's (libc): %02x:%02x:%02x:%02x:%02x:%02x.
	sysMAC = `(?:[0-9a-f]{2}:){5}[0-9a-f]{2}`
	// sysIf is an interface name, as takeover.go's ifconfigNameRE has it.
	sysIf = `[a-z]+\d+`
)

var (
	// LACP_STATE_BITS and TRUNK_PORT_BITS, as printb_status prints them.
	sysLACPState   = words("activity", "timeout", "aggregation", "sync", "collecting", "distributing", "defaulted", "expired")
	sysTrunkPortFl = words("master", "stack", "active", "collecting", "distributing", "disabled")
	sysDay         = words("Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat")
	sysMon         = words("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
	// sysCtime is ctime(3) without its newline, and strftime's %c in
	// the C locale ("%a %b %e %H:%M:%S %Y"): "Tue Sep 29 16:09:55 2026".
	sysCtime = sysDay + ` ` + sysMon + ` [ \d]\d \d\d:\d\d:\d\d \d{4}`
	// sysDate is date(1)'s default, "%a %b %e %H:%M:%S %Z %Y".
	sysDate = sysDay + ` ` + sysMon + ` [ \d]\d \d\d:\d\d:\d\d [A-Za-z0-9+-]+ \d{4}`
)

// sysRight is a number printed with "%<w>d": right-aligned in w
// columns, or wider when it doesn't fit.
func sysRight(w int) string {
	alts := []string{fmt.Sprintf(`\d{%d,}`, w)}
	for k := 1; k < w; k++ {
		alts = append(alts, fmt.Sprintf(` {%d}\d{%d}`, k, w-k))
	}
	return "(?:" + strings.Join(alts, "|") + ")"
}

// sysNotPrefix matches any text that doesn't start with p.
func sysNotPrefix(p string) string {
	alts := []string{}
	for i := range len(p) {
		alts = append(alts, regexp.QuoteMeta(p[:i])+`(?:[^`+regexp.QuoteMeta(p[i:i+1])+`].*)?`)
	}
	return "(?:" + strings.Join(alts, "|") + ")"
}

// sysNotWord matches a non-empty run of the characters a negated class
// (such as `\s:`) allows, other than w itself.
func sysNotWord(w, class string) string {
	c := `[^` + class + `]`
	alts := []string{regexp.QuoteMeta(w) + c + `+`}
	for i := range len(w) {
		alts = append(alts, regexp.QuoteMeta(w[:i])+`[^`+class+regexp.QuoteMeta(w[i:i+1])+`]`+c+`*`)
		if i > 0 {
			alts = append(alts, regexp.QuoteMeta(w[:i]))
		}
	}
	return "(?:" + strings.Join(alts, "|") + ")"
}

// sysLit is a line printf prints with no value in it, made with the
// source's own format.
func sysLit(format string, a ...any) string {
	return regexp.QuoteMeta(fmt.Sprintf(format, a...))
}

// --- sysctl (sbin/sysctl/sysctl.c) ---

// sysctlValues is the value sysctl prints for each name OPF reads:
// strings with puts, ints and quads with %d/%lld, kern.boottime with
// ctime(3) (BOOTTIME), kern.cp_time as CPUSTATES (6) longs joined by
// "," (LONGARRAY), vm.loadavg with "%.2f %.2f %.2f".
var sysctlValues = map[string]string{
	"kern.osrelease": `\d+\.\d+`,
	"kern.hostname":  `\S*`,
	// The kernel's version string (sys/conf/newvers.sh): "${ost}
	// ${osr}" STATUS " (${id}) #${v}: ${t}\n    ${u}@${h}:${d}\n",
	// where STATUS is "", "-beta", "-current" or "-stable" and ${t} is
	// date(1). Its own newline and puts' make a blank line after it.
	"kern.version":  `OpenBSD \d+\.\d+` + words("", "-beta", "-current", "-stable") + ` \([A-Za-z0-9_.+-]+\) #\d+: ` + sysDate,
	"kern.boottime": sysCtime,
	"kern.cp_time":  `\d+(?:,\d+){5}`,
	"hw.machine":    `[a-z0-9]+`,
	"hw.model":      `\S.*`,
	"hw.vendor":     `.*`,
	"hw.product":    `.*`,
	"hw.ncpuonline": `\d+`,
	"hw.physmem":    `\d+`,
	"vm.loadavg":    `\d+\.\d\d \d+\.\d\d \d+\.\d\d`,
}

// sysctlFormat is the output of sysctl with names OPF reads.
func sysctlFormat(command, fixture string) Format {
	f := Format{Command: command, Fixture: fixture}
	for _, k := range strings.Fields(command)[1:] {
		v, ok := sysctlValues[k]
		if !ok {
			panic("no value pattern for sysctl " + k)
		}
		f.Lines = append(f.Lines, L(k, regexp.QuoteMeta(k)+"="+v))
		f.Need = append(f.Need, k)
		switch k {
		case "kern.version":
			f.Lines = append(f.Lines,
				L("kern.version's build line", `    \S+@\S+:/\S*`),
				L("kern.version's end", ``))
			f.Need = append(f.Need, "kern.version's build line")
		case "hw.vendor", "hw.product":
			// A machine without SMBIOS: sysctl's warnx for EOPNOTSUPP.
			// It counts as the name's line, which OPF then leaves empty.
			f.Lines = append(f.Lines, L(k, `sysctl: `+regexp.QuoteMeta(k)+`: value is not available`))
		}
	}
	return f
}

// sysSensorValues are print_sensor's value formats, by
// sensor_type_s[] name (sys/sys/sensors.h).
var sysSensorValues = []struct{ typ, value string }{
	{"temp", `-?\d+\.\d{2} degC`},
	{"fan", `-?\d+ RPM`},
	{"volt", `-?\d+\.\d{2} VDC`},
	{"acvolt", `-?\d+\.\d{2} VAC`},
	{"resistance", `-?\d+ ohm`},
	{"power", `-?\d+\.\d{2} W`},
	{"current", `-?\d+\.\d{2} A`},
	{"watthour", `-?\d+\.\d{2} Wh`},
	{"amphour", `-?\d+\.\d{2} Ah`},
	{"indicator", words("On", "Off")},
	{"raw", `-?\d+`},
	{"percent", `-?\d+\.\d{2}%`},
	{"illuminance", `-?\d+\.\d{2} lx`},
	{"drive", words("empty", "ready", "powering up", "online", "idle", "active", "rebuilding", "powering down", "failed", "degraded", "unknown")},
	{"timedelta", `-?\d+\.\d{6} secs`},
	{"humidity", `-?\d+\.\d{2}%`},
	{"frequency", `-?\d+\.\d{2} Hz`},
	{"angle", ` *-?\d+\.\d{4} degrees`},
	{"distance", `-?\d+\.\d{3} m`},
	{"pressure", `-?\d+\.\d{2} Pa`},
	{"acceleration", ` *-?\d+\.\d{4} m/s\^2`},
	{"velocity", ` *-?\d+\.\d{3} m/s`},
	{"energy", `-?\d+\.\d{2} J`},
}

// sysctlSensorsFormat is sysctl hw.sensors: print_sensordev and
// print_sensor. After the value: the description in parentheses, the
// status (SENSOR_S_*) and the time of the last change (ctime's first
// 19 characters and milliseconds).
func sysctlSensorsFormat() Format {
	f := Format{Command: "sysctl hw.sensors", Fixture: "sysctl_hw_sensors.txt"}
	tail := `(?: \(.{0,31}\))?(?:, ` + words("OK", "WARNING", "CRITICAL", "UNKNOWN") + `)?` +
		`(?:, (?:` + sysDay + ` ` + sysMon + ` [ \d]\d \d\d:\d\d:\d\d|\d+)\.\d{3})?`
	for _, s := range sysSensorValues {
		f.Lines = append(f.Lines, L(s.typ+" sensor",
			`hw\.sensors\.[a-z][a-z0-9]*\d\.`+s.typ+`\d+=(?:`+s.value+`|unknown)`+tail))
	}
	// A machine with no sensors prints nothing.
	f.Lines = append(f.Lines, L("no sensors", ``))
	return f
}

// --- vmstat -s (usr.bin/vmstat/vmstat.c: dosum) ---

// sysVmstatCounters are dosum's counters, in its order; OPF reads the
// first and the free, active and inactive pages.
var sysVmstatCounters = []string{
	"bytes per page", "pages managed", "pages free", "pages active",
	"pages inactive", "pages being paged out", "pages wired", "pages zeroed",
	"pages reserved for pagedaemon", "pages reserved for kernel",
	"pages in per-cpu caches", "per-cpu cache hits", "per-cpu cache misses",
	"swap pages", "swap pages in use", "page faults", "traps", "interrupts",
	"cpu context switches", "fpu context switches", "software interrupts",
	"syscalls", "pagein operations", "forks", "forks where vmspace is shared",
	"kernel map entries", "zeroed page hits", "zeroed page misses",
	"number of times the pagedaemon woke up",
	"number of times the pagedaemon scanned for free pages",
	"pages freed by pagedaemon", "pages scanned by pagedaemon",
	"pages reactivated by pagedaemon", "busy pages found by pagedaemon",
	"total name lookups",
}

func sysVmstatFormat() Format {
	f := Format{Command: "vmstat -s", Fixture: "vmstat_-s.txt"}
	for _, c := range sysVmstatCounters {
		f.Lines = append(f.Lines, L(c, sysRight(11)+` `+regexp.QuoteMeta(c)))
	}
	f.Lines = append(f.Lines,
		L("name cache hits", ` {11} cache hits \(\d+% pos \+ \d+% neg\) system \d+% per-directory`),
		L("name cache deletions", ` {11} deletions \d+%, falsehits \d+%, toolong \d+%`),
		L("vm.uvmexp unreadable", `vmstat: could not read vm\.uvmexp: .*`),
		L("kern.nchstats unreadable", `vmstat: could not read kern\.nchstats: .*`),
	)
	f.Need = []string{"bytes per page", "pages free", "pages active", "pages inactive"}
	return f
}

// --- swapctl -lk (sbin/swapctl/swaplist.c: list_swap) ---

func sysSwapctlFormat() Format {
	return Format{Command: "swapctl -lk", Fixture: "swapctl_-lk.txt", Lines: []Line{
		// "%-*s %*s %8s %8s %8s  %s", pathmax (at least 11), "Device",
		// strlen("1K-blocks"), ...
		L("header", `Device {6,}1K-blocks     Used    Avail Capacity  Priority`),
		// "%-*s %*ld " then "%8ld %8ld %5.0f%%    %d".
		L("device", `/\S+ +`+sysRight(9)+` `+sysRight(8)+` `+sysRight(8)+` `+sysRight(5)+`%    -?\d+`),
		// More than one device: "%-*s %*ld %8ld %8ld %5.0f%%", "Total".
		L("total", `Total +`+sysRight(9)+` `+sysRight(8)+` `+sysRight(8)+` `+sysRight(5)+`%`),
		// errx when there's none, which OPF reads as no swap.
		L("no swap", `swapctl: no swap devices configured`),
	}}
}

// --- df -kPl (bin/df/df.c: posixprint) ---

func sysDfFormat() Format {
	return Format{Command: "df -kPl", Fixture: "df_-kPl.txt", Lines: []Line{
		// "%-*.*s %s       Used   Available Capacity Mounted on" with
		// "1024-blocks" for -k.
		L("header", `Filesystem +1024-blocks       Used   Available Capacity Mounted on`),
		// "%-*.*s %*lld %10lld %11lld %5d%%   %s": the available blocks
		// go negative when the reserve is in use.
		L("filesystem", `\S.*? +`+sysRight(11)+` `+sysRight(10)+` (?:`+sysRight(11)+`| *-\d+) `+sysRight(5)+`%   /.*`),
	}, Need: []string{"header", "filesystem"}}
}

// --- ntpctl -s all (usr.sbin/ntpd/ntpd.c: show_status_msg,
// show_peer_msg, show_sensor_msg; control.c: build_show_peer,
// build_show_sensor) ---

func sysNtpctlFormat() Format {
	constraint := `(?:constraint offset -?\d+s(?: \(\d+ errors\))?, |constraints configured but none available, )?`
	return Format{Command: "ntpctl -s all", Fixture: "ntpctl_-s_all.txt", Lines: []Line{
		L("status", `(?:\d+/\d+ peers valid, )?(?:\d+/\d+ sensors valid, )?`+constraint+
			`(?:clock synced, stratum \d+|clock unsynced(?:, clock offset is -?\d+\.\d{3}ms)?)`),
		// With neither, the status takes two lines.
		L("nothing configured", `(?:\d+/\d+ peers valid, )?(?:\d+/\d+ sensors valid, )?`+constraint+`no peers and no sensors configured`),
		L("blank", ``),
		L("peer section", `peer`),
		L("peer header", `   wt tl st  next  poll          offset       delay      jitter`),
		// "%s %s%s%s": the address (or "not resolved"), "from pool ",
		// the name when it differs from the address, " (non-dnssec
		// lookup)".
		L("peer", `(?:`+sysIP+`|not resolved) (?:from pool )?\S*(?: \(non-dnssec lookup\))?`),
		// "%s\n %1s %2u %2u %2s %4llds %4llds" then "  %12.3fms
		// %9.3fms  %8.3fms" or the not-valid text.
		L("peer figures", ` [ *] `+sysRight(2)+` `+sysRight(2)+` (?:`+sysRight(2)+`| -) +-?\d+s +-?\d+s`+
			`(?:  +-?\d+\.\d{3}ms +-?\d+\.\d{3}ms  +-?\d+\.\d{3}ms|             ---- peer not valid ----)`),
		L("no peers", `no peers configured`),
		L("sensor section", `sensor`),
		L("sensor header", `   wt gd st  next  poll          offset  correction`),
		// "%s  %.4s": the device and its refid.
		L("sensor", sysIf+`  [\x21-\x7e]{0,4}`),
		L("sensor figures", ` [ *] `+sysRight(2)+` `+sysRight(2)+` `+sysRight(2)+` +-?\d+s +-?\d+s`+
			`(?:   +-?\d+\.\d{3}ms +-?\d+\.\d{3}ms|         - sensor not valid -)`),
		L("no sensors", `no sensors configured`),
		// ntpd isn't running: err(1, "connect: %s", sockname).
		L("not running", `ntpctl: connect: /var/run/ntpd\.sock: .+`),
	}}
}

// --- /etc/resolv.conf (sbin/resolvd/resolvd.c: regen_resolvconf;
// lib/libc/asr/asr.c: pass0 for the lines people write) ---

func sysResolvConfFormat() Format {
	return Format{Command: "cat /etc/resolv.conf", Fixture: "resolv.conf.txt", Lines: []Line{
		// "%snameserver %s # resolvd: %s\n": commented out ("#") while
		// unwind runs; the interface name is empty if it's gone.
		L("resolvd's nameserver", `nameserver `+sysIP+` # resolvd: (?:`+sysIf+`)?`),
		L("resolvd's nameserver, unwind running", `#nameserver `+sysIP+` # resolvd: (?:`+sysIf+`)?`),
		L("unwind", `nameserver 127\.0\.0\.1 # resolvd: unwind`),
		// Lines resolvd replays as they are.
		L("nameserver", `nameserver[ \t]+\S+[ \t]*(?:[#;].*)?`),
		L("lookup", `lookup(?:[ \t]+`+words("file", "bind", "yp")+`)*[ \t]*(?:[#;].*)?`),
		L("domain", `domain[ \t]+\S+[ \t]*(?:[#;].*)?`),
		L("search", `search(?:[ \t]+\S+)+[ \t]*(?:[#;].*)?`),
		L("family", `family(?:[ \t]+`+words("inet4", "inet6")+`){1,2}[ \t]*(?:[#;].*)?`),
		L("options", `options(?:[ \t]+(?:`+words("tcp", "edns0", "trust-ad")+`|ndots:\d+))+[ \t]*(?:[#;].*)?`),
		L("comment", `[ \t]*[#;].*`),
		L("blank", `[ \t]*`),
	}}
}

// --- ifconfig (sbin/ifconfig/ifconfig.c: status and the *_status
// functions it calls; brconfig.c: bridge_status) ---

// sysIfFlags are IFFBITS.
var sysIfFlags = words("UP", "BROADCAST", "DEBUG", "LOOPBACK", "POINTOPOINT", "STATICARP",
	"RUNNING", "NOARP", "PROMISC", "ALLMULTI", "OACTIVE", "SIMPLEX", "LINK0", "LINK1",
	"LINK2", "MULTICAST", "AUTOCONF6TEMP", "MPLS", "WOL", "AUTOCONF6", "INET6_NOSOII",
	"AUTOCONF4", "MONITOR", "LRO")

// sysMediaTypes are the first name of each IFM_TYPE_DESCRIPTIONS type,
// which get_media_type_string prints.
var sysMediaTypes = words("Ethernet", "FDDI", "IEEE802.11", "TDM", "CARP")

// sysMediaSubtypes are get_media_subtype_string's names for the shared
// and Ethernet subtypes of IFM_SUBTYPE_DESCRIPTIONS: the first name of
// each.
var sysMediaSubtypes = words("autoselect", "manual", "none",
	"10baseT", "10base2", "10base5", "100baseTX", "100baseFX", "100baseT4", "100baseVG",
	"100baseT2", "1000baseSX", "10baseSTP", "10baseFL", "1000baseLX", "1000baseCX",
	"1000baseT", "HomePNA1", "10GbaseLR", "10GbaseSR", "10GbaseCX4", "2500baseSX",
	"10GbaseT", "10GSFP+Cu", "10GbaseLRM", "40GbaseCR4", "40GbaseSR4", "40GbaseLR4",
	"1000base-KX", "10GbaseKX4", "10GbaseKR", "10GbaseCR1", "10G-AOC", "20GbaseKR2",
	"2500baseKX", "2500baseT", "5000baseT", "1000base-SGMII", "10GbaseSFI",
	"40GbaseXLPPI", "1000baseCX-SGMII", "40GbaseKR4", "40G-AOC", "10GbaseER",
	"100GbaseCR4", "100GbaseSR4", "100GbaseKR4", "100GbaseLR4", "100G-AOC", "56GbaseR4",
	"25GbaseCR", "25GbaseKR", "25GbaseSR", "25GbaseLR", "25GbaseER", "25G-AOC",
	"50GbaseCR2", "50GbaseKR2")

// sysMediaOptions are IFM_OPTION_DESCRIPTIONS' first names for the
// shared and Ethernet options.
var sysMediaOptions = words("full-duplex", "half-duplex", "flag0", "flag1", "flag2", "loopback", "master", "rxpause", "txpause")

// sysLinkStates are what status prints after "status: ": the
// IFM_STATUS_DESCRIPTIONS for an interface with media, the
// LINK_STATE_DESCRIPTIONS otherwise (get_linkstate), or "[#n]".
var sysLinkStates = `(?:` + words("active", "no carrier", "no network", "backup", "master",
	"unknown", "invalid", "down", "keepalive down", "no ring", "inserted") + `|\[#\d+\])`

var (
	sysCarpStates = words("INIT", "BACKUP", "MASTER", "<UNKNOWN>")                                                                                 // CARP_STATES
	sysCarpBal    = words("none", "ip", "ip-stealth", "ip-unicast", "<UNKNOWN>")                                                                   // CARP_BAL_MODES
	sysWGKey      = `[A-Za-z0-9+/]{43}=`                                                                                                           // b64_ntop of a 32-byte key
	sysBridgeIfFl = words("LEARNING", "DISCOVER", "BLOCKNONIP", "STP", "EDGE", "AUTOEDGE", "PTP", "AUTOPTP", "SPAN", "LOCAL", "LOCKED", "PVPTAGS") // IFBIFBITS
)

// sysIfconfigLines are the lines status prints for the interfaces OPF
// meets: physical ports, vlan, carp, pfsync, pflow, wg, lo, enc, pflog,
// vether, pair, tun, gif and gre, bridge and veb. aliases is ifconfig
// -A (ifaliases): wg's peers, and no designated or root bridge lines.
func sysIfconfigLines(aliases bool) []Line {
	mediaWord := sysMediaSubtypes + `(?: ` + sysMediaOptions + `(?:,` + sysMediaOptions + `)*)?(?: instance \d+)?`
	ls := []Line{
		// printf("%s: ", ifname); printb("flags", ..., IFFBITS); then
		// " rdomain %d", " metric %lu", " mtu %lu" when they aren't 0.
		L("interface", sysIf+`: flags=[0-9a-f]+<(?:`+sysIfFlags+`(?:,`+sysIfFlags+`)*)?>(?: rdomain \d+)?(?: metric \d+)?(?: mtu \d+)?`),
		L("lladdr", `\tlladdr `+sysMAC),
		L("description", `\tdescription: .+`),
		// "%cindex %u", "%cpriority %d" (not for a bridge), "%cllprio %d".
		L("index", `\t(?:index \d+ )?(?:priority \d+ )?llprio \d+`),
		L("keepalive", `\tkeepalive: timeout \d+ count \d+`),
		L("patch", `\tpatch: `+sysIf),
		// getencap.
		L("encap", `\tencap:(?: vnetid (?:none|any|\d+\+?))?(?: parent (?:none|`+sysIf+`))?`+
			`(?: txprio (?:packet|payload|\d+))?(?: rxprio (?:packet|payload|outer|\d+))?`),
		// trunk_status, for aggr(4) and trunk(4): the protocol, LACP's
		// ids, then each port's LACP and trunk flags; a port says its
		// aggregate. The aggregates' ! lines in hostname.if read the
		// port lines and trunkdev (pf.aggregateLines).
		L("trunk", `\ttrunk: trunkproto `+words("roundrobin", "failover", "lacp", "loadbalance", "broadcast", "none", "<unknown>")+`(?: trunkdev `+sysIf+`)?`),
		L("trunk port of", `\ttrunk: trunkdev `+sysIf),
		L("trunk id", `\ttrunk id: \[\([0-9A-F]{4},`+sysMAC+`(?:,[0-9A-F]{4}){3}\),`),
		L("trunk id partner", `\t\t \([0-9A-F]{4},`+sysMAC+`(?:,[0-9A-F]{4}){3}\)\]`),
		L("trunk lacp", `\t\t`+sysIf+` lacp (?:actor|partner) system pri 0x[0-9a-f]+ mac `+sysMAC+`, key 0x[0-9a-f]+, port pri 0x[0-9a-f]+ number 0x[0-9a-f]+`),
		L("trunk lacp state", `\t\t`+sysIf+` lacp (?:actor|partner) state (?:`+sysLACPState+`(?:,`+sysLACPState+`)*)?`),
		L("trunk port", `\t\t`+sysIf+` port (?:`+sysTrunkPortFl+`(?:,`+sysTrunkPortFl+`)*)?`),
		// carp_status: one vhid, or several (balancing) with a line each.
		L("carp", `\tcarp: `+sysCarpStates+` carpdev (?:`+sysIf+`|none) vhid \d+ advbase \d+ advskew \d+(?: carppeer `+sysIPv4+`)?`),
		L("carp balancing", `\tcarp: carpdev (?:`+sysIf+`|none) advbase \d+ balancing `+sysCarpBal+`(?: carppeer `+sysIPv4+`)?`),
		L("carp vhid", `\t\tstate `+sysCarpStates+` vhid \d+ advskew \d+`),
		// pfsync_status.
		L("pfsync", `\tpfsync: syncdev: `+sysIf+` (?:syncpeer: `+sysIPv4+` )?maxupd: \d+ defer: (?:on|off)`),
		// pflow_status: the sender only when one is set; an address or
		// port not set is INVALID.
		L("pflow", `\tpflow: (?:sender: (?:`+sysIPv4+`|\[`+sysIPv6+`\])(?::\d+)? )?`+
			`receiver: (?:(?:`+sysIPv4+`|INVALID):(?:\d+|INVALID)|\[(?:`+sysIPv6+`|INVALID)\]:(?:\d+|INVALID)) version: \d+`),
		// wg_status.
		L("wgport", `\twgport \d+`),
		L("wgrtable", `\twgrtable \d+`),
		L("wgpubkey", `\twgpubkey `+sysWGKey),
		// getifgroups: every group but "all".
		L("groups", `\tgroups:(?: \S+)+`),
		L("media", `\tmedia: `+sysMediaTypes+` `+mediaWord+`(?: \(`+mediaWord+`\))?`),
		L("status", `\tstatus: `+sysLinkStates),
		// phys_status, for tunnels: print_tunnel, then ttl, df, ecn,
		// rdomain.
		L("tunnel", `\ttunnel: (?:\(unset\)|inet6? (?:`+sysIP+`|<error>)(?::\d+)?(?: --> (?:`+sysIP+`|<error>)(?::\d+)?)?)`+
			`(?: ttl (?:copy|\d+))?(?: (?:df|nodf))?(?: (?:ecn|noecn))?(?: rdomain \d+)?`),
		// bridge_status: bridge_cfg, bridge_pvlans, bridge_list (with
		// bridge_vidmap and bridge_rules), then the address cache.
		L("bridge", `\tpriority \d+ hellotime \d+ fwddelay \d+ maxage \d+ holdcnt \d+ proto `+words("stp", "(none)", "rstp")),
		L("bridge pvlan", `\tpvlan \d+ isolated (?:\d+|none)(?: community \d+(?:,\d+)*)?`),
		L("bridge member", `\t`+sysIf+` flags=[0-9a-f]+<(?:`+sysBridgeIfFl+`(?:,`+sysBridgeIfFl+`)*)?>`),
		L("bridge port", `\t\tport \d+ ifpriority \d+ ifcost \d+(?: -untagged| untagged passthrough| untagged \d+)?(?: protected \d+(?:,\d+)*)?`+
			`(?: `+words("disabled", "listening", "learning", "forwarding", "blocking", "discarding")+` role `+words("disabled", "root", "designated", "alternate", "backup")+`)?`),
		L("bridge tagged", `\t\ttagged:(?: none| \d+(?:-\d+)?(?:,\d+(?:-\d+)?)*)`),
		L("bridge rule", `\t(?:block|pass) (?:in/out|in|out) on `+sysIf+`.*`),
		L("bridge addresses", `\tAddresses \(max cache: \d+, timeout: \d+\):`),
		// bridge_vaddrs_try, or bridge_addrs when the kernel lacks it.
		L("bridge address", `\t\t`+sysMAC+`(?:@\d+)?(?: `+sysIf+`)? -?\d+ flags=[0-9a-f]+<(?:STATIC)?>(?: tunnel \S+:\S+)?`),
		// in_status and in6_alias, one line per address (with -A, all of
		// them).
		L("inet", `\tinet `+sysIPv4+`(?: --> `+sysIPv4+`)? netmask 0x[0-9a-f]+(?: broadcast `+sysIPv4+`)?`),
		L("inet6", `\tinet6 `+sysIPv6+`(?: --> `+sysIPv6+`)?(?: prefixlen \d+)?`+
			`(?: `+words("anycast", "tentative", "duplicated", "detached", "deprecated", "autoconf", "temporary")+`)*(?: scopeid 0x[0-9a-f]+)?`),
	}
	if aliases {
		ls = append(ls,
			L("wgpeer", `\twgpeer `+sysWGKey),
			L("wgdescr", `\t\twgdescr: .*`),
			L("wgpsk", `\t\twgpsk \(present\)`),
			L("wgpka", `\t\twgpka \d+ \(sec\)`),
			L("wgendpoint", `\t\twgendpoint (?:`+sysIP+` \d+|unable to print)`),
			L("wg traffic", `\t\ttx: \d+, rx: \d+`),
			L("wg handshake", `\t\tlast handshake: -?\d+ seconds ago`),
			L("wgaip", `\t\twgaip `+sysIP+`/\d+`),
		)
	} else {
		ls = append(ls,
			L("bridge designated", `\tdesignated: id `+sysMAC+` priority \d+`),
			L("bridge root", `\troot: id `+sysMAC+` priority \d+ ifcost \d+ port \d+`),
		)
	}
	return ls
}

// --- netstat (usr.bin/netstat/if.c: intpr, print_addr; show.c:
// p_rttables, pr_family, pr_rthdr, p_rtentry, p_flags) ---

// sysNetstatIfFormat is netstat -i with n numbers after the address:
// a <Link> row per interface ("*" after a down one), then a row per
// address. Network and Address are cut to 11 and 17 columns.
func sysNetstatIfFormat(command, fixture, header string, n int) Format {
	var nums string
	if n == 2 {
		nums = sysRight(10) + ` ` + sysRight(10) // "%10llu %10llu"
	} else {
		nums = sysRight(8) + ` ` + sysRight(5) + ` ` + sysRight(8) + ` ` + sysRight(5) + ` ` + sysRight(5) // "%8llu %5llu %8llu %5llu %5llu"
	}
	name := sysIf + `\*? +\d+ +`
	return Format{Command: command, Fixture: fixture, Lines: []Line{
		L("header", regexp.QuoteMeta(header)),
		// AF_LINK: "<Link>", then the MAC for Ethernet and carp, or
		// padding to 30 columns.
		L("link", name+`<Link> +(?:`+sysMAC+` +)?`+nums),
		L("address", name+`\S{1,11} +\S{1,17} +`+nums),
		L("no address", name+`none +none +`+nums),
	}, Need: []string{"header", "link"}}
}

// sysRouteFlags are the route flag letters, in bits[]' order.
const sysRouteFlags = `[UGHRDMCmLSB321chPTlFbn]`

func sysNetstatRouteFormat(command, fixture, family string, dst, gw int) Format {
	return Format{Command: command, Fixture: fixture, Lines: []Line{
		L("routing tables", `Routing tables`),
		L("blank", ``),
		L("family", family+`:`),
		L("header", sysLit("%-*.*s %-*.*s %-6.6s %5.5s %8.8s %5.5s  %4.4s %s", dst, dst, "Destination", gw, gw, "Gateway", "Flags", "Refs", "Use", "Mtu", "Prio", "Iface")),
		// "%-*s " (-n doesn't cut), "%-6.6s " flags, "%5u %8llu ", mtu
		// "%5u " or "%5s " "-", 'L' when locked, "  %2d %-5.16s".
		L("route", `\S+ +\S+ +`+sysRouteFlags+`{1,6} +`+sysRight(5)+` `+sysRight(8)+` (?:`+sysRight(5)+`| {4}-) [ L]  `+sysRight(2)+` (?:`+sysIf+`|\(null\)) *`),
	}, Need: []string{"routing tables", "family", "header", "route"}}
}

// --- arp -an (usr.sbin/arp/arp.c: dump, print_entry, sec2str) ---

func sysArpFormat() Format {
	return Format{Command: "arp -an", Fixture: "arp_-an.txt", Lines: []Line{
		L("header", sysLit("%-*.*s %-*.*s %*.*s %-9.9s %5s", 36, 36, "Host", 17, 17, "Ethernet Address", 7, 7, "Netif", "Expire", "Flags")),
		// "%-*.*s %-*.*s %*.*s" host, ether_str, interface; " %-9.9s"
		// permanent, static, sec2str's time left (cut to 9) or expired;
		// " %s%s" l (local) and p (published).
		L("entry", sysIPv4+` +(?:`+sysMAC+`|\(incomplete\)) +(?:`+sysIf+`|\?) `+
			`(?:permanent|static|expired|[0-9dhms]{2,9}) +(?:lp|l|p)?`),
	}, Need: []string{"header"}}
}

// --- ping (sbin/ping/ping.c: main, pinger, pr_pack, summary) ---

// sysPingLines are the lines ping and ping6 print (one program; v6flag
// from its name); prog is the name warn and errx use.
func sysPingLines(prog string) []Line {
	p := regexp.QuoteMeta(prog)
	return []Line{
		L("header", `PING \S+ \((?:`+sysIP+` --> )?`+sysIP+`\): \d+ data bytes`),
		// pr_pack, without -q: "%d bytes from %s: icmp_seq=%u", " hlim=%d"
		// or " ttl=%d", " time=%.3f ms", " (DUP!)", " (TRUNC!)".
		L("reply", `\d+ bytes from `+sysIP+`: icmp_seq=\d+ (?:hlim|ttl)=\d+(?: time=\d+\.\d{3} ms)?(?: \(DUP!\))?(?: \(TRUNC!\))?`),
		L("blank", ``),
		L("statistics", `--- \S+ ping statistics ---`),
		L("transmitted", `\d+ packets transmitted, \d+ packets received, (?:\d+ duplicates, )?(?:\d+\.\d% packet loss|-- somebody's duplicating packets!)`),
		L("round-trip", `round-trip min/avg/max/std-dev = \d+\.\d{3}/\d+\.\d{3}/\d+\.\d{3}/\d+\.\d{3} ms`),
		// pinger: warn("sendmsg"), then a line on stdout that says
		// "ping:" whichever the program.
		L("sendmsg failed", p+`: sendmsg: .+`),
		L("short write", `ping: wrote \S+ \d+ chars, ret=-?\d+`),
		// errx(1, "%s", gai_strerror(error)) and the multiple-address
		// warning.
		L("unresolved", p+`: `+words("no address associated with name", "name or service is not known",
			"temporary failure in name resolution", "non-recoverable failure in name resolution")),
		L("several addresses", p+`: Warning: \S+ has multiple addresses; using `+sysIP),
	}
}

func sysGatewayPingFormat(prog string) Format {
	return Format{Command: prog + " -n -q -c 3 -i 0.2 -w 1 -- *", Fixture: prog + "_gateway.txt",
		Lines: sysPingLines(prog), Need: []string{"header", "statistics", "transmitted"}}
}

// --- ps (bin/ps: print.c, keyword.c) ---

func sysPsRSSFormat() Format {
	// Empty headers: no header line. rss is right-aligned ("%*d") in
	// the widest value's width; comm (ucomm) is last, unpadded.
	return Format{Command: "ps -A -o rss=,comm=", Fixture: "ps_-A_-o_rss_comm.txt", Lines: []Line{
		L("process", ` *\d+ \S.*`),
	}, Need: []string{"process"}}
}

func sysPsAuthpfFormat() Format {
	// pid ("%*d", 5 wide), lstart (strftime "%c" left-aligned in 28,
	// or "-"), command (the arguments, and " (comm)" when they don't
	// start with it). authpf's setproctitle("%s@%s") on its login
	// shell's "-authpf" makes "-authpf: user@address (authpf)".
	started := `(?:` + sysCtime + ` {4}|- {27})`
	return Format{Command: "ps -axww -o pid,lstart,command", Fixture: "ps_-axww_-o_pid_lstart_command.txt", Lines: []Line{
		L("header", sysLit("%5s %-28s %s", "PID", "STARTED", "COMMAND")),
		L("authpf session", sysRight(5)+` `+started+` -authpf: \S+@\S+ \(authpf\)`),
		L("process", sysRight(5)+` `+started+` \S.*`),
	}, Need: []string{"header", "process"}}
}

// --- newsyslog.conf (usr.bin/newsyslog/newsyslog.c: parse_file) ---

func sysNewsyslogFormat() Format {
	return Format{Command: "cat /etc/newsyslog.conf", Fixture: "newsyslog.conf.txt", Lines: []Line{
		// Blank and "#" lines are skipped (sob, then '\0' or '#').
		L("comment", `[ \t]*#.*`),
		L("blank", `[ \t]*`),
		// logfile [owner:group] mode count size when [flags]
		// [/pid_file | "command"] [SIGNAL]; size "*" or KB; when "*",
		// hours, hours@ISO8601 or hours$DWM. newsyslog also takes
		// owner.group and lower-case flags, which ParseNewsyslog
		// misreads (it splits only on ":" and looks only for "Z"), so
		// they aren't here: a file that has them fails.
		L("log", `/\S+[ \t]+(?:[^\s:.]*:\S*[ \t]+)?[0-7]{1,4}[ \t]+\d+[ \t]+(?:\*|\d+)[ \t]+(?:\*|\d+|\d*[@$]\S+)`+
			`(?:[ \t]+[ZBMF]+)?(?:[ \t]+(?:/\S+|"[^"]*"|SIG[A-Z0-9]+))*[ \t]*`),
	}, Need: []string{"log"}}
}

// --- ls -ln (bin/ls/print.c: printlong, printtime) ---

func sysLsFormat() Format {
	return Format{Command: "ls -ln ...", Fixture: "ls_-ln.txt", Lines: []Line{
		// strmode, "%*u " links, "%-*s  " uid and gid, "%*lld " size,
		// "%b %e %H:%M" or "%b %e  %Y", the name.
		L("file", `-[-r][-w][-xsS][-r][-w][-xsS][-r][-w][-xtT] +\d+ \d+ +\d+ +\d+ `+sysMon+` [ \d]\d (?:\d\d:\d\d| \d{4}) /.*`),
		// A rotated copy that isn't there yet (fts_open's error).
		L("missing", `ls: /\S+: No such file or directory`),
	}, Need: []string{"file"}}
}

// --- syslogd's files (usr.sbin/syslogd/syslogd.c: fprintlog) ---

// sysSyslogLines are the lines syslogd writes to a file: the
// timestamp ("Mmm dd hh:mm:ss", from ctime(3)+4, or the message's own
// RFC 3164 one), the host, then the message, "last message repeated N
// times" or "-- MARK --". Control characters are vis(3)-encoded, so a
// message is one line. syslogd -Z's ISO timestamps aren't here: OPF's
// ParseSyslog skips them.
func sysSyslogLines() []Line {
	head := sysMon + ` [ \d]\d \d\d:\d\d:\d\d \S+ `
	// Any program but unbound, whose lines are below: so an rpz line
	// ParseRPZLog would skip fails rather than pass as just a line.
	tag := sysNotWord("unbound", `\s:\[\]`)
	unbound := head + `unbound: \[\d+:[0-9a-f]+\] `
	return []Line{
		// unbound's rpz-log through syslog (util/log.c: "[%d:%x] %s: %s"
		// with ident "unbound"; services/rpz.c: log_rpz_apply;
		// util/net_help.c: log_nametypeclass), which ParseRPZLog reads:
		// "rpz: applied [log name] [trigger] dname action [ip@port] "
		// then the query's name, type and class.
		L("unbound rpz", head+`unbound: \[\d+:[0-9a-f]+\] info: rpz: applied (?:\[[^\]]*\] )?(?:`+words("clientip", "nsip", "nsdname")+` )?\S* `+
			words("rpz-nxdomain", "rpz-nodata", "rpz-passthru", "rpz-drop", "rpz-tcp-only", "rpz-invalid",
				"rpz-local-data", "rpz-disabled", "rpz-cname-override", "rpz-no-override", "rpz-unknown-action")+
			` (?:\S+@\d+)? \S+ (?:[A-Z][A-Z0-9-]*|TYPE\d+) (?:IN|CH|HS|NONE|ANY|CLASS\d+)`),
		// Its other lines (util/log.c's types).
		L("unbound", unbound+`(?:`+words("notice", "warning", "error", "fatal error", "debug", "query", "reply")+`: .*|info: `+sysNotPrefix("rpz: applied")+`)`),
		L("last message repeated", head+`last message repeated \d+ times`),
		// newsyslog's first line of a log it turned over (log_trim),
		// stamped in ISO 8601 UTC ("%FT%T.%03ldZ"), which ParseSyslog reads.
		L("newsyslog", `\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z \S+ newsyslog\[\d+\]: logfile turned over`),
		L("mark", head+`-- MARK --`),
		// klog: "%s: " with _PATH_UNIX.
		L("kernel", head+`/bsd: .*`),
		L("program[pid]", head+tag+`\[\d+\]: .*`),
		L("program", head+tag+`: .*`),
	}
}

// --- rcctl (usr.sbin/rcctl/rcctl.sh; etc/rc.d/rc.subr) ---

// sysRcSpecial are rcctl's _special_svcs.
var sysRcSpecial = words("accounting", "check_quotas", "ipsec", "library_aslr", "multicast", "pf", "spamd_black")

func sysRcctlFormats() []Format {
	// ls_rcscripts takes any +([[:alnum:]_]) name; this is the shape
	// services.go's serviceNameRE accepts, so one OPF would drop fails.
	name := `[a-z][a-z0-9_]{0,63}`
	ls := func(arg string) Format {
		return Format{Command: "rcctl ls " + arg, Fixture: "rcctl_ls_" + arg + ".txt", Lines: []Line{
			L("service", name),
		}, Need: []string{"service"}}
	}
	notExist := L("no such service", `rcctl: service \S+ does not exist`)
	return []Format{
		ls("on"), ls("started"), ls("all"),
		// svc_get with no variable: a daemon's seven variables, a special
		// service's one, nothing for a meta script.
		{Command: "rcctl get *", Fixture: "rcctl_get.txt", Lines: []Line{
			L("variable", name+`_`+words("class", "execdir", "flags", "logger", "rtable", "timeout", "user")+`=.*`),
			L("special", sysRcSpecial+`=.*`),
			notExist,
		}},
		// rc.subr's check: _rc_printname, then _rc_exit's "(ok)" or
		// "(failed)". OPF goes by the exit status.
		{Command: "rcctl check *", Fixture: "rcctl_check.txt", Lines: []Line{
			L("checked", `[A-Za-z0-9_]+\((?:ok|failed)\)`),
			notExist,
			L("special", `rcctl: "`+sysRcSpecial+`" is a special variable, no rc\.d\(8\) script`),
		}},
		// svc_get with a variable: print -r of its value, nothing when
		// it's empty.
		{Command: "rcctl get opf flags", Fixture: "rcctl_get_opf_flags.txt", Lines: []Line{
			L("flags", `.*`),
		}},
	}
}

// --- getent hosts (usr.bin/getent/getent.c: hostsaddrinfo) ---

// getaddrinfo(name, AF_UNSPEC, SOCK_DGRAM), as ifconfig's wgendpoint
// asks it, then a "%-39s %s\n" line for each address and the name, the
// address "# unknown" when getnameinfo can't print it. Nothing, and
// exit 2, when getaddrinfo fails: no such name or no answer alike.
func sysGetentFormat() Format {
	return Format{Command: "getent hosts *", Fixture: "getent_hosts.txt", Lines: []Line{
		L("address", `[0-9A-Fa-f.:]{2,39} +\S+`),
		L("unknown", `# unknown +\S+`),
	}}
}

// --- syspatch -c (usr.sbin/syspatch/syspatch.sh: ls_missing, err) ---

func sysSyspatchFormat() Format {
	return Format{Command: "syspatch -c", Fixture: "syspatch_-c.txt", Lines: []Line{
		// grep -Eo "syspatch${_OSrev}-[[:digit:]]{3}_[[:alnum:]_-]+",
		// less the prefix; IsPatchName also caps the length at 64.
		L("patch", `\d{3}_[A-Za-z0-9_-]{1,60}`),
		// Up to date: nothing.
		L("none", ``),
		L("unsupported release", `syspatch: Unsupported release: \S+`),
		L("not root", `syspatch: need root privileges`),
		L("reorder_kernel", `syspatch: cannot apply patches while reorder_kernel is running`),
		// ls_missing's ftp and signify, whose stderr isn't redirected.
		L("ftp error", `ftp: (?:Error retrieving \S+: .+|\S+: `+words("no address associated with name", "name or service is not known", "temporary failure in name resolution")+`|connect: .+|Receiving HTTP reply: .+)`),
		L("tls error", `TLS (?:handshake|connect) failure: .+`),
		L("signify error", `signify: .+`),
	}}
}

// --- ftp -V -o - -- URL (usr.bin/ftp/fetch.c: url_get) ---

// sysFtpFormat is a failed fetch's output: ftp's warnings (ttyout is
// stderr with -o -). OPF shows the last line. A fetch that works prints
// the file, which OPF parses as the list it is.
func sysFtpFormat() Format {
	return Format{Command: "ftp -V -o - -- *", Fixture: "ftp_-V_-o_-_failed.txt", Lines: []Line{
		L("http error", `ftp: Error retrieving \S+: \d{3} .*`),
		L("unresolved", `ftp: \S+: `+words("no address associated with name", "name or service is not known",
			"temporary failure in name resolution", "non-recoverable failure in name resolution")),
		L("connect", `ftp: connect: .+`),
		L("tls", `TLS (?:configuration|connect|handshake) failure: .+`),
		L("tls client", `failed to create SSL client`),
		L("reply", `ftp: (?:Receiving HTTP reply|Writing HTTP request|Reading from socket|Error while reading from socket): .+`),
		L("redirects", `ftp: Too many redirections requested`),
		L("improper response", `ftp: Improper response from \S+`),
		L("chunked", `ftp: Invalid chunked encoding(?:: short read)?|ftp: Invalid chunk size '.*'`),
		L("bad url", `ftp: (?:Invalid URL|No colon in URL|No host name in URL): .+|ftp: \S+: (?:URL not permitted|No HTTPS support)`),
	}}
}

// --- encrypt (usr.bin/encrypt/encrypt.c: print_passwd; lib/libc/
// crypt/bcrypt.c) ---

func sysEncryptFormat() Format {
	return Format{Command: "encrypt", Fixture: "encrypt.txt", Lines: []Line{
		// One hash per line read: "$2b$%2.2u$", 22 salt and 31 hash
		// characters of bcrypt's base64.
		L("hash", `\$2b\$\d\d\$[./A-Za-z0-9]{53}`),
	}, Need: []string{"hash"}}
}

// --- The diagnostics tools, as far as ui/src/lib/toolOutcomes.ts
// reads them (keyed "tool <program>") ---

func sysTracerouteFormat(prog string) Format {
	p := regexp.QuoteMeta(prog)
	// print_result_row: "%2u ", then for each probe " *" (with its
	// icmp code) or the address when it changed (" %s" with -n, " %s
	// (%s)" without, " [AS…]" with -A) and "  %g ms", then " (TOS=%d!)",
	// the icmp code and an MPLS extension.
	code := `(?: !(?:[NHPFSXACUIT]|<\d+>)?)?`
	probe := `(?: \*` + code + `|(?: \S+(?: \(` + sysIP + `\))?(?: \[AS\d+(?:, AS\d+)*\])?)?  \d+(?:\.\d+)?(?:e[+-]\d+)? ms(?: \(TOS=\d+!\))?` + code + `(?: \[MPLS Label [^\]]*\])?)`
	return Format{Command: "tool " + prog, Fixture: "tool_" + prog + ".txt", Lines: []Line{
		// On stderr: "%s to %s (%s)", " from %s", ", %u hops max, %d
		// byte packets".
		L("header", p+` to \S+ \(`+sysIP+`\)(?: from \S+)?, \d+ hops max, \d+ byte packets`),
		L("hop", sysRight(2)+` `+probe+`+`),
		L("unresolved", p+`: `+words("no address associated with name", "name or service is not known",
			"temporary failure in name resolution", "non-recoverable failure in name resolution")),
		L("several addresses", p+`: Warning: \S+ has multiple addresses; using `+sysIP),
		L("connect", p+`: connect: .+`),
		L("sendto", p+`: sendto: .+`),
		L("short write", p+`: wrote \S+ \d+ chars, ret=-?\d+`),
	}}
}

func sysDigFormat() Format {
	rcodes := `(?:` + words("NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED", "YXDOMAIN",
		"YXRRSET", "NXRRSET", "NOTAUTH", "NOTZONE", "RESERVED11", "RESERVED12", "RESERVED13",
		"RESERVED14", "RESERVED15", "BADVERS", "BADCOOKIE") + `|\?\d+)` // dig.c: rcodetext, rcode_totext
	opcodes := words("QUERY", "IQUERY", "STATUS", "RESERVED3", "NOTIFY", "UPDATE", "RESERVED6", "RESERVED7",
		"RESERVED8", "RESERVED9", "RESERVED10", "RESERVED11", "RESERVED12", "RESERVED13", "RESERVED14", "RESERVED15")
	class := `(?:IN|CH|HS|NONE|ANY|CLASS\d+)`
	rrtype := `(?:[A-Z][A-Z0-9-]*|TYPE\d+)`
	return Format{Command: "tool dig", Fixture: "tool_dig.txt", Lines: []Line{
		L("blank", ``),
		// The command line (lookup->cmdline) and the global options.
		L("command", `; <<>> dig \S+ <<>> .*`),
		L("servers found", `; \(\d+ servers? found\)`),
		L("global options", `;; global options:(?: \+short)?(?: \+cmd)?`),
		// printmessage's header.
		L("got answer", `;; Got answer:`),
		L("status", `;; ->>HEADER<<- opcode: `+opcodes+`, status: `+rcodes+`, id: \d+`),
		L("flags", `;; flags:(?: `+words("qr", "aa", "tc", "rd", "ra", "ad", "cd")+`)*(?:; MBZ: 0x4)?; QUERY: \d+, ANSWER: \d+, AUTHORITY: \d+, ADDITIONAL: \d+`),
		L("no recursion", `;; WARNING: recursion requested but not available`),
		L("edns status", `;; WARNING: EDNS query returned status \S+ - retry with '(?:\+nodnssec )?\+noedns'`),
		// lib/dns/message.c: dns_message_pseudosectiontotext and
		// dns_message_sectiontotext.
		L("opt", `;; OPT PSEUDOSECTION:`),
		L("edns", `; EDNS: version: \d+, flags:(?: do)?(?:; MBZ: 0x[0-9a-f]{4}, |; )udp: \d+`),
		L("edns option", `; (?:NSID|COOKIE|CLIENT-SUBNET|EXPIRE|PAD|KEY-TAG|EDE|ZONEVERSION|OPT=\d+)\b.*`),
		L("section", `;; `+words("QUESTION", "ANSWER", "AUTHORITY", "ADDITIONAL")+` SECTION:`),
		L("question", `;\S+\s+`+class+`\s+`+rrtype),
		// A record: name, TTL, class, type, data (what the UI splits).
		L("record", `\S+\s+\d+\s+`+class+`\s+`+rrtype+`(?:\s+.*)?`),
		// dig.c: received.
		L("query time", `;; Query time: \d+ (?:msec|usec)`),
		L("server", `;; SERVER: \S+#\d+\(\S+\)`),
		L("when", `;; WHEN: `+sysDay+` `+sysMon+` \d\d \d\d:\d\d:\d\d \S+ \d{4}`),
		L("size", `;; MSG SIZE  rcvd: \d+`),
		L("received", `;; Received \d+ bytes from \S+#\d+\(\S+\) in \d+ (?:ms|us)`),
		// dighost.c's failures.
		L("timed out", `;; connection timed out; no servers could be reached`),
		L("communications error", `;; communications error(?: to \S+)?: .+`),
		L("connection failed", `;; Connection to \S+\(\S+\) for \S+ failed: .+`),
		L("retrying", `;; (?:Truncated, retrying in TCP mode\.|BADVERS, retrying with EDNS version \d+\.)`),
		L("referral", `;; (?:BAD \(HORIZONTAL\) REFERRAL|BAD REFERRAL|No acceptable nameservers)`),
		L("fatal", `dig: (?:couldn't get address for '\S+': .+|'\S+' is not a legal name .*|.+ is not a legal .+)`),
	}}
}

func sysNcFormat() Format {
	return Format{Command: "tool nc", Fixture: "tool_nc.txt", Lines: []Line{
		// connection_info: "Connection to %s", " (%s)" when the host
		// isn't the address, " %s port [%s/%s] succeeded!".
		L("succeeded", `Connection to \S+(?: \(`+sysIP+`\))? \d+ port \[(?:tcp|udp)/\S+\] succeeded!`),
		// remote_connect: warn("connect to %s port %s (%s) failed") or
		// with the address.
		L("failed", `nc: connect to \S+(?: \(`+sysIP+`\))? port \d+ \((?:tcp|udp)\) failed: .+`),
		L("unresolved", `nc: getaddrinfo for host "\S+" port \d+: .+`),
	}}
}

// --- diff -u -L a -L b (usr.bin/diff/diffreg.c: print_header,
// dump_unified_vec, fetch), which the UI shows line by line by its
// first character (ui/src/components/UnifiedDiff.tsx) ---

func sysDiffFormat() Format {
	return Format{Command: "diff -u -L * -L * * *", Fixture: "diff_-u.txt", Lines: []Line{
		// With -L: "%s %s\n", no time.
		L("old label", `--- .*`),
		L("new label", `\+\+\+ .*`),
		// "@@ -" uni_range " +" uni_range " @@", then -F's match.
		L("hunk", `@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@(?: .*)?`),
		L("context", ` .*`),
		L("added", `\+.*`),
		L("removed", `-.*`),
		L("no newline", `\\ No newline at end of file`),
		L("binary", `Binary files .* and .* differ`),
		// The same files: nothing.
		L("same", ``),
	}}
}

func init() {
	addFormats(sysDiffFormat())
	addFormats(
		sysctlFormat("sysctl kern.osrelease", "sysctl_kern_osrelease.txt"),
		sysctlFormat("sysctl kern.hostname kern.osrelease kern.version kern.boottime hw.machine hw.model hw.vendor hw.product hw.ncpuonline hw.physmem vm.loadavg", "sysctl_status.txt"),
		sysctlFormat("sysctl kern.cp_time", "sysctl_kern_cp_time.txt"),
		sysctlFormat("sysctl kern.cp_time vm.loadavg hw.physmem", "sysctl_collect.txt"),
		sysctlSensorsFormat(),
		sysVmstatFormat(),
		sysSwapctlFormat(),
		sysDfFormat(),
		sysNtpctlFormat(),
		sysResolvConfFormat(),
		Format{Command: "ifconfig -A", Fixture: "ifconfig_-A.txt", Lines: sysIfconfigLines(true),
			Need: []string{"interface", "index", "groups", "inet"}},
		// The egress group's members; printif's error when it has none.
		Format{Command: "ifconfig egress", Fixture: "ifconfig_egress.txt",
			Lines: append(sysIfconfigLines(false), L("no egress", `egress: no such interface`))},
		sysNetstatIfFormat("netstat -ibn", "netstat_-ibn.txt",
			fmt.Sprintf("%-7.7s %-5.5s %-11.11s %-17.17s %10.10s %10.10s", "Name", "Mtu", "Network", "Address", "Ibytes", "Obytes"), 2),
		sysNetstatIfFormat("netstat -in", "netstat_-in.txt",
			fmt.Sprintf("%-7.7s %-5.5s %-11.11s %-17.17s %8.8s %5.5s %8.8s %5.5s %5.5s", "Name", "Mtu", "Network", "Address", "Ipkts", "Ifail", "Opkts", "Ofail", "Colls"), 5),
		sysNetstatRouteFormat("netstat -rnf inet", "netstat_-rnf_inet.txt", "Internet", 18, 18),
		sysNetstatRouteFormat("netstat -rnf inet6", "netstat_-rnf_inet6.txt", "Internet6", 43, 39),
		sysArpFormat(),
		sysGatewayPingFormat("ping"),
		sysGatewayPingFormat("ping6"),
		sysPsRSSFormat(),
		sysPsAuthpfFormat(),
		sysNewsyslogFormat(),
		sysLsFormat(),
		// The kernel's messages, shown as they are.
		Format{Command: "dmesg", Fixture: "dmesg.txt", Free: true},
		Format{Command: "tail -n * *", Fixture: "tail_syslog.txt", Lines: sysSyslogLines()},
		sysSyspatchFormat(),
		sysGetentFormat(),
		sysFtpFormat(),
		sysEncryptFormat(),
		Format{Command: "tool ping", Fixture: "tool_ping.txt", Lines: sysPingLines("ping")},
		Format{Command: "tool ping6", Fixture: "tool_ping6.txt", Lines: sysPingLines("ping6")},
		sysTracerouteFormat("traceroute"),
		sysTracerouteFormat("traceroute6"),
		sysDigFormat(),
		sysNcFormat(),
	)
	addFormats(sysRcctlFormats()...)
}
