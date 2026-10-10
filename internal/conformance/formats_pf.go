package conformance

import (
	"fmt"
	"regexp"
	"strings"
)

// The output of pfctl and tcpdump that OPF reads, line by line, as
// OpenBSD 7.9's source prints it: sbin/pfctl (pfctl.c, pfctl_parser.c,
// pf_print_state.c, pfctl_table.c, parse.y), usr.sbin/tcpdump
// (print-pflog.c, util.c) and the name arrays in sys/net/pfvar.h. Each
// pattern says which function prints the line. Column widths are the
// printf formats' own, so a widened or narrowed column fails too.
//
// OPF runs every command through run.Runner, which gives stdout and
// stderr together, so a command's stderr lines (pfctl's table messages,
// tcpdump's warnings) are part of its output here.

// pfReasons are PFRES_NAMES (pfvar.h): pfctl -s info's "Counters" and
// pflog's reason.
var pfReasons = []string{
	"match", "bad-offset", "fragment", "short", "normalize", "memory",
	"bad-timestamp", "congestion", "ip-option", "proto-cksum",
	"state-mismatch", "state-insert", "state-limit", "src-limit",
	"synproxy", "translate", "no-route",
}

// pfLimitCounters are LCNT_NAMES (pfvar.h): "Limit Counters".
var pfLimitCounters = []string{
	"max states per rule", "max-src-states", "max-src-nodes",
	"max-src-conn", "max-src-conn-rate", "overload table insertion",
	"overload flush states", "synfloods detected", "syncookies sent",
	"syncookies validated",
}

// pfTableCounters are FCNT_NAMES (pfvar.h), which print_status uses for
// the State Table, Source Tracking Table and Fragments alike.
var pfTableCounters = []string{"searches", "inserts", "removals"}

// pfLimits are pfctl.c's pf_limits: pfctl -s memory's pools and
// pf.conf's set limit names.
var pfLimits = []string{"states", "src-nodes", "frags", "tables", "table-entries", "pktdelay-pkts", "anchors"}

// pfTimeouts are pfctl_parser.c's pf_timeouts, in its order: pfctl -s
// timeouts' lines and pf.conf's set timeout names. The adaptive ones
// are state counts, the rest seconds.
var pfTimeouts = []string{
	"tcp.first", "tcp.opening", "tcp.established", "tcp.closing",
	"tcp.finwait", "tcp.closed", "tcp.tsdiff", "udp.first", "udp.single",
	"udp.multiple", "icmp.first", "icmp.error", "other.first",
	"other.single", "other.multiple", "frag", "interval",
	"adaptive.start", "adaptive.end", "src.track",
}

// pfDebugLevels are what loglevel_to_string (pfctl_parser.c) prints for
// pf's debug level: the first of syslog.h's prioritynames with each
// value, so LOG_WARNING is "warn" and LOG_ERR "err".
var pfDebugLevels = []string{"emerg", "alert", "crit", "err", "warn", "notice", "info", "debug"}

// pfTCPStates are tcp_fsm.h's tcpstates.
var pfTCPStates = []string{
	"CLOSED", "LISTEN", "SYN_SENT", "SYN_RCVD", "ESTABLISHED", "CLOSE_WAIT",
	"FIN_WAIT_1", "CLOSING", "LAST_ACK", "FIN_WAIT_2", "TIME_WAIT",
}

// pfPeerStates are PFUDPS_NAMES and PFOTHERS_NAMES (the same three).
var pfPeerStates = []string{"NO_TRAFFIC", "SINGLE", "MULTIPLE"}

// pfOtherProtocols are 7.9's /etc/protocols names, which print_state
// prints (getprotobynumber), besides tcp, udp, icmp and ipv6-icmp, whose
// states print differently.
var pfOtherProtocols = []string{
	"ip", "igmp", "ggp", "ipencap", "st2", "cbt", "egp", "igp", "bbn-rcc",
	"nvp", "pup", "argus", "emcon", "xnet", "chaos", "mux", "dcn", "hmp",
	"prm", "xns-idp", "trunk-1", "trunk-2", "leaf-1", "leaf-2", "rdp", "irtp",
	"iso-tp4", "netblt", "mfe-nsp", "merit-inp", "dccp", "3pc", "idpr", "xtp",
	"ddp", "idpr-cmtp", "tp++", "il", "ipv6", "sdrp", "ipv6-route",
	"ipv6-frag", "idrp", "rsvp", "gre", "dsr", "bna", "esp", "ah", "i-nlsp",
	"swipe", "narp", "mobile", "skip", "ipv6-nonxt", "ipv6-opts", "cftp",
	"sat-expak", "kryptolan", "rvd", "ippc", "sat-mon", "visa", "ipcv",
	"cpnx", "cphb", "wsn", "pvp", "br-sat-mon", "sun-nd", "wb-mon",
	"wb-expak", "iso-ip", "vmtp", "secure-vmtp", "vines", "ttp", "nsfnet-igp",
	"dgp", "tcf", "igrp", "ospf", "sprite-rpc", "larp", "mtp", "ax.25", "ipip",
	"micp", "scc-sp", "etherip", "encap", "gmtp", "ifmp", "pnni", "pim",
	"aris", "scps", "qnx", "a/n", "ipcomp", "snp", "compaq-peer", "ipx-in-ip",
	"carp", "pgm", "l2tp", "ddx", "iatp", "stp", "srp", "uti", "smp", "sm",
	"ptp", "isis", "fire", "crtp", "crudp", "sscopmce", "iplt", "sps", "pipe",
	"sctp", "fc", "rsvp-e2e-ignore", "mobility-header", "udplite",
	"mpls-in-ip", "manet", "hip", "shim6", "wesp", "rohc", "pfsync",
	"reserved", "divert",
}

// pfTableStats are pfctl_table.c's stats_text: a table's counters
// (pfctl -vvs Tables) are all four, an address's (-T show -v) the first
// three of each direction.
var (
	pfTableStats   = []string{"In/Block:", "In/Match:", "In/Pass:", "In/XPass:", "Out/Block:", "Out/Match:", "Out/Pass:", "Out/XPass:"}
	pfAddressStats = []string{"In/Block:", "In/Match:", "In/Pass:", "Out/Block:", "Out/Match:", "Out/Pass:"}
)

// pfIfaceStats are pfctl_table.c's istats_text, in print_iface's order.
var pfIfaceStats = []string{"In4/Pass:", "In4/Block:", "Out4/Pass:", "Out4/Block:", "In6/Pass:", "In6/Block:", "Out6/Pass:", "Out6/Block:"}

// pflogActions are what pflog_if_print prints for a rule's action.
var pflogActions = []string{"match", "scrub", "pass", "block", "nat", "binat", "rdr"}

// pfLit is a fixed line as C's printf would print it (Go's %-25s and
// %14s pad as C's do), matched literally.
func pfLit(format string, args ...any) string {
	return regexp.QuoteMeta(fmt.Sprintf(format, args...))
}

// pfRjust is an unsigned number printed right-justified in width
// columns (%14llu).
func pfRjust(width int) string {
	alts := []string{fmt.Sprintf(`\d{%d,}`, width)}
	for k := 1; k < width; k++ {
		alts = append(alts, strings.Repeat(" ", width-k)+fmt.Sprintf(`\d{%d}`, k))
	}
	return "(?:" + strings.Join(alts, "|") + ")"
}

// pfLjust is an unsigned number printed left-justified in width columns
// (%-18llu).
func pfLjust(width int) string {
	alts := []string{fmt.Sprintf(`\d{%d,}`, width)}
	for k := 1; k < width; k++ {
		alts = append(alts, fmt.Sprintf(`\d{%d}`, k)+strings.Repeat(" ", width-k))
	}
	return "(?:" + strings.Join(alts, "|") + ")"
}

// pfRate is %14.1f: a number with one decimal, right-justified.
func pfRate(width int) string {
	alts := []string{fmt.Sprintf(`\d{%d,}\.\d`, width-2)}
	for k := 1; k < width-2; k++ {
		alts = append(alts, strings.Repeat(" ", width-2-k)+fmt.Sprintf(`\d{%d}\.\d`, k))
	}
	return "(?:" + strings.Join(alts, "|") + ")"
}

// pfLeft is one of the names printed left-justified in width columns
// (%-25s).
func pfLeft(width int, names ...string) string {
	q := make([]string, len(names))
	for i, n := range names {
		q[i] = pfLit("%-*s", width, n)
	}
	return "(?:" + strings.Join(q, "|") + ")"
}

// pfLeftToken is a word of the pattern's characters printed
// left-justified in width columns (an interface name in %-16s).
func pfLeftToken(width int, first, rest string) string {
	alts := []string{first + rest + fmt.Sprintf(`{%d,}`, width-1)}
	for k := 1; k < width; k++ {
		alts = append(alts, first+rest+fmt.Sprintf(`{%d}`, k-1)+strings.Repeat(" ", width-k))
	}
	return "(?:" + strings.Join(alts, "|") + ")"
}

// Pieces of lines.
const (
	pfIfname = `[A-Za-z0-9_.-]+` // an interface or interface group
	pfIP4    = `(?:\d{1,3}\.){3}\d{1,3}`
	pfIP6    = `[0-9a-f]*:[0-9a-f:.]*` // inet_ntop's, with "::ffff:1.2.3.4"
	pfIP     = `(?:` + pfIP4 + `|` + pfIP6 + `)`
	pfHMS    = `\d{2,}:\d{2}:\d{2}` // %.2u:%.2u:%.2u, hours unbounded
	// ctime(3): "Wed Oct  7 15:44:41 2026" (%3d day); print_tstats and
	// friends print the seconds instead when ctime fails.
	pfCtime = `(?:(?:Sun|Mon|Tue|Wed|Thu|Fri|Sat) (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)(?:  [1-9]| [12]\d| 3[01]) \d{2}:\d{2}:\d{2} \d{4}|-?\d+)`
	// A table's name, and the anchor it's in (print_table's "@anchor").
	pfTableName = `[^\s@<>]+(?:@\S+)?`
	pfTflags    = `[c-][p-][a-][i-][r-][h-][C-]`
)

// pfAddr is print_addr's address: an interface's ((em0:network), with
// -vv the count of its addresses), a table (<t>, with -vv <t:N>), a
// range, an address or network, any, no-route, urpf-failed or a route
// label.
func pfAddr(verbose bool) string {
	dynCount, tblCount := "", ""
	if verbose {
		dynCount, tblCount = `(?::\*|:\d+)`, `(?::\*|:-?\d+)`
	}
	return `(?:\(` + pfIfname + `(?::network)?(?::broadcast)?(?::peer)?(?::0)?` + dynCount + `\)(?:/\d+)?` +
		`|<[^\s<>:]+` + tblCount + `>` +
		`|` + pfIP + ` - ` + pfIP +
		`|(?:any|` + pfIP + `)(?:/\d+)?` +
		`|no-route|urpf-failed|route "[^"]*"|\?)`
}

// pfOp is print_op's operator and operands, with its leading space.
func pfOp(v string) string {
	return `(?: (?:=|!=|<|<=|>|>=) ` + v + `| ` + v + ` (?:><|<>) ` + v + `| ` + v + `:` + v + `)`
}

// pfPool is print_pool's address pool.
func pfPool(verbose bool) string {
	return `(?:(?:` + pfAddr(verbose) + `@)?` + pfIfname + `|` + pfAddr(verbose) + `)` +
		`(?: port \d+(?::\d+)?)?` +
		`(?: bitmask| random| source-hash 0x[0-9a-f]{32}| round-robin| least-states)?` +
		`(?: sticky-address)?(?: static-port)?`
}

// pfRule is print_rule's rule (pfctl_parser.c), its parts in its order.
// verbose is -vv (pfctl -vv -s rules), which numbers each rule and
// counts tables' and interfaces' addresses; pfctl -nvf is neither.
func pfRule(verbose bool) string {
	addr := pfAddr(verbose)
	icmpName := `(?:[a-z][a-z0-9-]*|\d+)`
	proto := `(?:` + words(append([]string{"tcp", "udp", "icmp", "ipv6-icmp"}, pfOtherProtocols...)...) + `|\d+)`
	logOpt := `(?:all|matches|user|to pflog\d+)`
	setItem := `(?:prio \d+|prio\(\d+, \d+\)|queue [^\s,()]+|queue\([^\s,()]+, [^\s,()]+\)|tos 0x[0-9a-f]{2}|delay \d+)`
	ropt := `(?:max \d+|no-sync|source-track (?:rule|global)|max-src-states \d+|max-src-conn \d+|max-src-conn-rate \d+/\d+|max-src-nodes \d+|overload <[^\s<>]+>(?: flush(?: global)?)?|if-bound|sloppy|pflow|(?:` + words(pfTimeouts...) + `|inv\.timeout) \d+)`
	ropts := ` \(` + ropt + `(?:, ` + ropt + `)*\)`
	scrubItem := `(?:no-df|random-id|min-ttl \d+|reassemble tcp|max-mss \d+)`
	limiters := `(?: probability \d+(?:\.\d+)?%)?` +
		`(?: state limiter (?:"[^"]*"|id \d+) \((?:block|no-match)\))?` +
		`(?: source limiter (?:"[^"]*"|id \d+) \((?:block|no-match)\))?`
	pool := pfPool(verbose)
	return `(?:pass|match|block (?:drop|return|return-rst(?:\(ttl \d+\))?|return-icmp6?\(` + icmpName + `(?:, ` + icmpName + `)?\))|anchor(?: "[^"]*")?)` +
		`(?: in| out)?` +
		`(?: log(?: \(` + logOpt + `(?:, ` + logOpt + `)*\))?)?` +
		`(?: quick)?` +
		`(?: on (?:! )?` + pfIfname + `)?` +
		`(?: on (?:! )?rdomain \d+)?` +
		`(?: inet6?)?` +
		`(?: proto ` + proto + `)?` +
		`(?: all| from (?:! )?` + addr + `(?: port` + pfOp(`\d+`) + `)?(?: os "[^"]*")? to (?:! )?` + addr + `(?: port` + pfOp(`\d+`) + `)?)` +
		`(?: !?received-on ` + pfIfname + `)?` +
		`(?: user` + pfOp(`(?:\d+|unknown)`) + `)?` +
		`(?: group` + pfOp(`(?:\d+|unknown)`) + `)?` +
		`(?: flags [FSRPAUEW]*/[FSRPAUEW]*| flags any)?` +
		`(?: icmp6?-type ` + icmpName + `(?: code ` + icmpName + `)?)?` +
		`(?: tos 0x[0-9a-f]{2})?` +
		`(?: prio \d+)?` +
		`(?: max-pkt-rate \d+/\d+)?` +
		`(?: set \(` + setItem + `(?:, ` + setItem + `)*\))?` +
		// "keep state" is only printed with options after it.
		`(?: keep state` + limiters + ropts + `|(?: no state| modulate state| synproxy state)?` + limiters + `(?:` + ropts + `)?)` +
		`(?: fragment)?` +
		`(?: scrub \(` + scrubItem + `(?: ` + scrubItem + `)*\))?` +
		`(?: allow-opts)?` +
		`(?: label "[^"]*")?` +
		`(?: once)?` +
		`(?: tag \S+)?` +
		`(?:(?: !)? tagged \S+)?` +
		`(?: rtable \d+)?` +
		`(?: divert-to ` + pfIP + ` port \d+| divert-reply| divert-packet port \d+)?` +
		`(?: af-to inet6? from ` + pool + `(?: to ` + pool + `)?|(?: nat-to ` + pool + `)?(?: rdr-to ` + pool + `)?)` +
		`(?: (?:route-to|reply-to|dup-to) ` + pool + `)?` +
		`(?: # expired)?`
}

// pfStateLimiter and pfSourceLimiter are print_statelim and
// print_sourcelim, which pfctl -s rules and pfctl -nvf print first.
const (
	pfStateLimiter  = `state limiter "[^"]*" id \d+ limit \d+(?: rate \d+/\d+)?`
	pfSourceLimiter = `source limiter "[^"]*" id \d+ entries \d+ limit \d+(?: rate \d+/\d+)?(?: table <[^\s<>]+> above \d+(?: below \d+)?)?(?: inet mask \d+)?(?: inet6 mask \d+)?`
)

// pfStateHost is print_host in a state: "(rdomain) " when it has one,
// then 1.2.3.4:port or 2001:db8::1[port].
const pfStateHost = `(?:\(\d+\) )?(?:` + pfIP4 + `(?::\d+)?|` + pfIP6 + `(?:\[\d+\])?)`

// pfStateLine is the first line of print_state for a protocol and its
// pair of states: the interface, the protocol, each end with the other
// side of a translation in parentheses and a route-to address in
// braces, then four spaces and three more.
func pfStateLine(proto, states string) string {
	end := pfStateHost + `(?: \(` + pfStateHost + `\))?`
	route := `(?: \{` + pfIP + `\})?`
	return `(?:all|` + pfIfname + `) ` + proto + ` ` + end + route + ` (?:->|<-) ` + end + route + `       ` + states
}

// pfStatusLine is print_status's first line: "Status: Enabled for N days
// hh:mm:ss" (or without the time when pf has run no time) padded to 44
// columns, then "Debug: level" right-justified in 15.
func pfStatusLine() string {
	var status []string
	for _, run := range []string{"Enabled", "Disabled"} {
		short := "Status: " + run
		status = append(status, pfLit("%-44s", short))
		for days := 1; days <= 10; days++ {
			l := len(short) + len(" for ") + days + len(" days 00:00:00")
			pad := ""
			if l < 44 {
				pad = strings.Repeat(" ", 44-l)
			}
			status = append(status, regexp.QuoteMeta(short)+fmt.Sprintf(` for \d{%d} days (?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d`, days)+pad)
		}
	}
	var debug []string
	for _, d := range append(pfDebugLevels, "unknown") {
		debug = append(debug, pfLit("%15s", "Debug: "+d))
	}
	return `(?:` + strings.Join(status, "|") + `)(?:` + strings.Join(debug, "|") + `)`
}

// pfInfoRow is a print_status row: "  %-25s %14llu " and then a rate,
// or 14 spaces before pf has run a second.
func pfInfoRow(name string) string {
	return pfLit("  %-25s ", name) + pfRjust(14) + ` (?:` + pfRate(14) + `/s|` + strings.Repeat(" ", 14) + `)`
}

func pfInfoFormat() Format {
	lines := []Line{
		L("status", pfStatusLine()),
		L("blank", ``),
		L("hostid", `Hostid:   0x[0-9a-f]{8}`),
		L("checksum", `Checksum: 0x[0-9a-f]{32}`),
		// set loginterface's statistics.
		L("interface stats heading", `Interface Stats for `+pfLeftToken(16, `[a-z]`, `[a-z0-9]`)+pfLit(" %5s %16s", "IPv4", "IPv6")),
		L("interface bytes", pfLeft(25+2, "  Bytes In", "  Bytes Out")+` `+pfRjust(14)+` `+pfRjust(16)),
		L("interface packets heading", words("  Packets In", "  Packets Out")),
		L("interface packets", pfLeft(23+4, "    Passed", "    Blocked")+` `+pfRjust(14)+` `+pfRjust(16)),
		L("State Table heading", pfLit("%-27s %14s %16s", "State Table", "Total", "Rate")),
		L("current entries", pfLit("  %-25s ", "current entries")+pfRjust(14)+` `+strings.Repeat(" ", 14)),
		L("half-open tcp", pfLit("  %-25s ", "half-open tcp")+pfRjust(14)+` `+strings.Repeat(" ", 14)),
		L("Source Tracking Table heading", `Source Tracking Table`),
		L("Fragments heading", `Fragments`),
		L("Counters heading", `Counters`),
		L("Limit Counters heading", `Limit Counters`),
		L("Adaptive Syncookies Watermarks heading", `Adaptive Syncookies Watermarks`),
		L("watermark", pfLeft(25+2, "  start", "  end")+` `+pfRjust(14)+` states`),
	}
	need := []string{"status", "hostid", "checksum", "State Table heading", "current entries", "half-open tcp",
		"Source Tracking Table heading", "Fragments heading", "Counters heading", "Limit Counters heading",
		"Adaptive Syncookies Watermarks heading", "watermark"}
	for _, group := range [][]string{pfTableCounters, pfReasons, pfLimitCounters} {
		for _, n := range group {
			lines = append(lines, L("counter "+n, pfInfoRow(n)))
			need = append(need, "counter "+n)
		}
	}
	return Format{Command: "pfctl -v -s info", Fixture: "pfctl_-v_-s_info.txt", Lines: lines, Need: need}
}

func pfMemoryFormat() Format {
	f := Format{Command: "pfctl -s memory", Fixture: "pfctl_-s_memory.txt"}
	for _, n := range pfLimits {
		// pfctl_show_limits: "%-13s " then "unlimited" or "hard limit %8u".
		f.Lines = append(f.Lines, L(n, pfLit("%-13s ", n)+`(?:unlimited|hard limit `+pfRjust(8)+`)`))
		f.Need = append(f.Need, n)
	}
	return f
}

func pfTimeoutsFormat() Format {
	f := Format{Command: "pfctl -s timeouts", Fixture: "pfctl_-s_timeouts.txt"}
	for _, n := range pfTimeouts {
		// pfctl_show_timeouts: "%-20s %10d", then " states" or "s".
		unit := "s"
		if n == "adaptive.start" || n == "adaptive.end" {
			unit = " states"
		}
		f.Lines = append(f.Lines, L(n, pfLit("%-20s ", n)+pfRjust(10)+unit))
		f.Need = append(f.Need, n)
	}
	return f
}

// pfCounterRow is "\t%-12s [ Packets: %-18llu Bytes: %-18llu ]".
func pfCounterRow(name string) string {
	return pfLit("\t%-12s [ Packets: ", name) + pfLjust(18) + ` Bytes: ` + pfLjust(18) + ` \]`
}

func pfTablesVerboseFormat() Format {
	// print_tstats.
	f := Format{Command: "pfctl -vvs Tables", Fixture: "pfctl_-vvs_Tables.txt", Lines: []Line{
		L("table", pfTflags+`\t`+pfTableName),
		L("Addresses", `\tAddresses:   \d+`),
		L("Cleared", `\tCleared:     `+pfCtime),
		L("References", `\tReferences:  \[ Anchors: `+pfLjust(18)+` Rules: `+pfLjust(18)+` \]`),
		L("Evaluations", `\tEvaluations: \[ NoMatch: `+pfLjust(18)+` Match: `+pfLjust(18)+` \]`),
	}, Need: []string{"table", "Addresses", "Cleared", "References", "Evaluations"}}
	for _, n := range pfTableStats {
		f.Lines = append(f.Lines, L(n, pfCounterRow(n)))
		f.Need = append(f.Need, n)
	}
	return f
}

func pfInterfacesFormat() Format {
	// print_iface.
	f := Format{Command: "pfctl -vv -s Interfaces", Fixture: "pfctl_-vv_-s_Interfaces.txt", Lines: []Line{
		L("interface", pfIfname+`(?: \(skip\))?`),
		L("Cleared", `\tCleared:     `+pfCtime),
		L("References", `\tReferences:  \[ States:  `+pfLjust(18)+` Rules: `+pfLjust(18)+` \]`),
	}, Need: []string{"interface", "Cleared", "References"}}
	for _, n := range pfIfaceStats {
		f.Lines = append(f.Lines, L(n, pfCounterRow(n)))
		f.Need = append(f.Need, n)
	}
	return f
}

func pfStatesFormat() Format {
	seq := `\[\d+ \+ \d+\](?:\(\+\d+\))?`
	pair := func(names []string) string { return words(names...) + `:` + words(names...) }
	return Format{Command: "pfctl -vv -s states", Fixture: "pfctl_-vv_-s_states.txt", Lines: []Line{
		// print_state's first line, by protocol: TCP's peers are in
		// tcpstates (or a synproxy's), UDP's and other protocols' in
		// PFUDPS/PFOTHERS_NAMES, ICMP's are numbers.
		L("tcp state", pfStateLine("tcp", `(?:`+pair(pfTCPStates)+`|PROXY:SRC|PROXY:DST|<BAD STATE LEVELS \d+:\d+>)`)),
		L("udp state", pfStateLine("udp", pair(pfPeerStates))),
		L("icmp state", pfStateLine(words("icmp", "ipv6-icmp"), `\d+:\d+`)),
		L("other state", pfStateLine(`(?:`+words(pfOtherProtocols...)+`|\d+)`, `(?:`+pair(pfPeerStates)+`|\d+:\d+)`)),
		// TCP's sequence windows, with both window scales or neither.
		L("tcp windows", `   `+seq+`(?: wscale \d+  `+seq+` wscale \d+|  `+seq+`)`),
		L("age", `   age `+pfHMS+`, expires in `+pfHMS+`, \d+:\d+ pkts, \d+:\d+ bytes(?:, anchor \d+)?(?:, rule \d+)?(?:, sloppy)?(?:, pflow)?(?:, source-track)?(?:, sticky-address)?`),
		L("id", `   id: [0-9a-f]{16} creatorid: [0-9a-f]{8}`),
	}, Need: []string{"age", "id"}}
}

func pfRulesFormat() Format {
	// pfctl_show_rules and pfctl_print_rule_counters (pfctl.c). With -v
	// nothing is indented, in an anchor either.
	rule := `@\d+ ` + pfRule(true)
	return Format{Command: "pfctl -vv -s rules", Fixture: "pfctl_-vv_-s_rules.txt", Lines: []Line{
		L("state limiter", pfStateLimiter),
		L("source limiter", pfSourceLimiter),
		L("rule", rule),
		// An anchor written with braces, whose rules follow.
		L("anchor opened", rule+` \{`),
		L("anchor closed", `\}`),
		L("counters", `  \[ Evaluations: `+pfLjust(8)+`  Packets: `+pfLjust(8)+`  Bytes: `+pfLjust(10)+`  States: `+pfLjust(6)+`\]`),
		L("inserted", `  \[ Inserted: uid \d+ pid \d+ State Creations: `+pfLjust(6)+`\]`),
	}, Need: []string{"rule", "counters", "inserted"}}
}

func pfLabelsFormat() Format {
	// pfctl_show_statelims, pfctl_show_sourcelims and pfctl_show_rules
	// with PFCTL_SHOW_LABELS: the limiters' headings always, then a line
	// per limiter, then a line per rule with a label.
	rate := `(?:` + pfRjust(5) + `/` + pfLjust(5) + `|` + pfLit("%5s/%-5s", "nil", "nil") + `)`
	return Format{Command: "pfctl -s labels", Fixture: "pfctl_-s_labels.txt", Lines: []Line{
		L("state limiters heading", pfLit("%3s %8s/%-8s %5s/%-5s %8s %8s %8s", "ID", "USE", "LIMIT", "RATE", "SECS", "ADMIT", "HARDLIM", "RATELIM")),
		L("source limiters heading", pfLit("%3s %8s/%-8s %5s %5s/%-5s %8s %8s %8s %8s", "ID", "USE", "ADDRS", "LIMIT", "RATE", "SECS", "ADMIT", "ADDRLIM", "HARDLIM", "RATELIM")),
		L("state limiter", pfRjust(3)+` `+pfRjust(8)+`/`+pfLjust(8)+` `+rate+` `+pfRjust(8)+` `+pfRjust(8)+` `+pfRjust(8)),
		L("source limiter", pfRjust(3)+` `+pfRjust(8)+`/`+pfLjust(8)+` `+pfRjust(5)+` `+rate+` `+pfRjust(8)+` `+pfRjust(8)+` `+pfRjust(8)+` `+pfRjust(8)),
		// label evaluations packets bytes in-packets in-bytes out-packets
		// out-bytes states. A label is printed as it is; OPF's have no
		// spaces, and ParsePfLabels needs none.
		L("label", `\S+(?: \d+){8}`),
	}, Need: []string{"state limiters heading", "source limiters heading"}}
}

func pfTablesFormat() Format {
	// print_table without -v.
	return Format{Command: "pfctl -s Tables", Fixture: "pfctl_-s_Tables.txt", Lines: []Line{
		L("table", pfTableName),
	}, Need: []string{"table"}}
}

func pflogFormat() Format {
	// util.c's ts_print with -ttt: strftime "%b %d %T" and microseconds.
	ts := `(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) (?:0[1-9]|[12]\d|3[01]) [0-2]\d:[0-5]\d:[0-6]\d\.\d{6} `
	// pflog_if_print with -e: the rule (def, a number, or in an anchor
	// number.anchor.number or number.anchor.def), the reason, the action,
	// the direction and the interface, then the packet as ip_print or
	// ip6_print decodes it.
	head := ts + `rule (?:def|\d+(?:\.\S+\.(?:def|\d+))?)/\(` + words(pfReasons...) + `\) ` + words(pflogActions...) + ` (?:in|out) on [a-z]+\d+: `
	return Format{Command: "tcpdump -n -e -ttt -r /var/log/pflog", Fixture: "tcpdump_-n_-e_-ttt_-r_varlogpflog.txt", Lines: []Line{
		L("packet", head+`.+`),
		L("unknown family", head+`unknown-af \d+`),
		L("truncated", ts+`(?:\[\|pflog\]|\[pflog: invalid header length!\])`),
		// tcpdump.c: pflogd's files' snaplen is larger than tcpdump's
		// default.
		L("snaplen warning", `tcpdump: WARNING: snaplen raised from \d+ to \d+`),
		// No log yet (FirewallLog says nothing then).
		L("no log", `tcpdump: /var/log/pflog: No such file or directory`),
		// pflogd's last packet half written.
		L("loop error", `tcpdump: pcap_loop: .+`),
	}}
}

// pfAddrx is print_addrx: the feedback character (a space from show),
// a space, ! or a space, the address or network, and the interface of
// an entry that has one.
const pfAddrx = `  [ !]` + pfIP + `(?:/\d+)?(?:@` + pfIfname + `)?`

// pfNoTable is pfctl's warnx(pf_strerror(ESRCH)) for a table pf doesn't
// have.
const pfNoTable = `pfctl: Table does not exist`

func pfTableShowFormats() []Format {
	show := Format{Command: "pfctl -t * -T show", Fixture: "pfctl_-t_table_-T_show.txt", Lines: []Line{
		L("address", pfAddrx),
		L("no table", pfNoTable),
		L("empty", ``),
	}}
	// print_astats.
	verbose := []Line{
		L("address", pfAddrx),
		L("Cleared", `\tCleared:     `+pfCtime),
		L("Active States", `\tActive States:      \d+`),
		L("Weight", `\tWeight:             \d+`),
		L("Interface", `\tInterface:          `+pfIfname),
	}
	for _, n := range pfAddressStats {
		verbose = append(verbose, L(n, pfCounterRow(n)))
	}
	showV := Format{Command: "pfctl -t * -T show -v", Fixture: "pfctl_-t_table_-T_show_-v.txt",
		Lines: append(append([]Line{}, verbose...), L("no table", pfNoTable), L("empty", ``))}
	// opf_hosts is declared with counters, and OPF reads them. An
	// address gets its counters with its first packet (pf_table.c,
	// pfr_update_stats), and print_astats prints all six rows then, none
	// before: OPF counts none as nothing yet. TestPfTables checks a busy
	// address has them.
	hosts := Format{Command: "pfctl -t opf_hosts -T show -v", Fixture: "pfctl_-t_opf_hosts_-T_show_-v.txt",
		Lines: verbose, Need: []string{"address", "Cleared"}}
	return []Format{show, showV, hosts}
}

// pfTableMessages are pfctl_table.c's xprintf messages (on stderr, so in
// OPF's output), each ending in ".".
var pfTableMessages = struct {
	created, added, deleted, flushed, killed, addedN, deletedN, changedN, none, expired, duplicate string
}{
	created:  `\d+ table created\.`,
	added:    `\d+/\d+ addresses added\.`,
	deleted:  `\d+/\d+ addresses deleted\.`,
	flushed:  `\d+ addresses deleted\.`,
	killed:   `\d+ table deleted\.`,
	addedN:   `\d+ addresses added\.`,
	deletedN: `\d+ addresses deleted\.`,
	changedN: `\d+ addresses changed\.`,
	none:     `no changes\.`,
	expired:  `\d+/\d+ addresses expired\.`,
	// warn_duplicate_tables, before a table is created.
	duplicate: `pfctl: warning: table <[^\s<>]+> already defined in anchor "[^"]*"`,
}

func pfTableChangeFormats() []Format {
	m := pfTableMessages
	change := func(cmd, fixture string) Format {
		// add (which creates the table if it must), delete, flush.
		return Format{Command: cmd, Fixture: fixture, Lines: []Line{
			L("created", m.created),
			L("duplicate", m.duplicate),
			L("added", m.added),
			L("deleted", m.deleted),
			L("flushed", m.flushed),
		}}
	}
	return []Format{
		change("pfctl -t * -T * ...", "pfctl_-t_table_-T_change.txt"),
		change("pfctl -t opf_hosts -T * ...", "pfctl_-t_opf_hosts_-T_change.txt"),
		{Command: "pfctl -t opf_hosts -T kill", Fixture: "pfctl_-t_opf_hosts_-T_kill.txt", Lines: []Line{
			L("killed", m.killed),
		}, Need: []string{"killed"}},
		{Command: "pfctl -t * -T replace -f *", Fixture: "pfctl_-t_table_-T_replace.txt", Lines: []Line{
			L("created", m.created),
			L("duplicate", m.duplicate),
			L("added", m.addedN),
			L("deleted", m.deletedN),
			L("changed", m.changedN),
			L("no changes", m.none),
		}},
		{Command: "pfctl -t * -T expire *", Fixture: "pfctl_-t_table_-T_expire.txt", Lines: []Line{
			L("expired", m.expired),
		}, Need: []string{"expired"}},
	}
}

func pfKillFormat() Format {
	// pfctl_id_kill_states, on stderr.
	return Format{Command: "pfctl -k id -k *", Fixture: "pfctl_-k_id.txt", Lines: []Line{
		L("killed", `killed \d+ states`),
	}, Need: []string{"killed"}}
}

func pfAnchorsFormat() Format {
	// pfctl_walk_show: each anchor under authpf by its path, two spaces
	// in. authpf names a session's anchor user(pid), or pid when that
	// doesn't fit.
	return Format{Command: "pfctl -a authpf -s Anchors", Fixture: "pfctl_-a_authpf_-s_Anchors.txt", Lines: []Line{
		L("session", `  authpf/(?:[^\s/]+\(\d+\)|\d+)`),
		L("anchor in a session", `  authpf/(?:[^\s/]+\(\d+\)|\d+)(?:/\S+)+`),
		L("no anchor", `pfctl: Anchor does not exist`),
		L("empty", ``),
	}}
}

func pfLoadFormat() Format {
	// pfctl -nvf: what parse.y and pfctl.c print as they read pf.conf
	// with -v (not -vv): macros, options, tables, queues, limiters and
	// rules, each rule followed by an empty line, an anchor's rules
	// indented two spaces a level inside braces.
	limit := `(?i:` + words(pfLimits...) + `)`
	timeout := `(?i:` + words(pfTimeouts...) + `)`
	tableEntry := ` !?` + pfAddr(false) + `(?:@` + pfIfname + `)?`
	bw := `(?:\d+%|\d+[ KMG])`
	sc := bw + `(?: burst ` + bw + ` for \d+ms)?`
	indent := `(?:  )*`
	rule := indent + pfRule(false)
	return Format{Command: "pfctl -nvf *", Fixture: "pfctl_-nvf.txt", Lines: []Line{
		L("blank", ``),
		// varset (parse.y).
		L("macro", `[A-Za-z_][A-Za-z0-9_]* = ".*"`),
		L("set block-policy", `set block-policy (?:drop|return)`),
		L("set fingerprints", `set fingerprints ".*"`),
		L("set state-policy", `set state-policy (?:floating|if-bound)`),
		// expand_skip_interface.
		L("set skip", `set skip on (?:none|\{(?: `+pfIfname+`)+ \})`),
		// pfctl_set_limit and pfctl_set_timeout print the name as
		// written; they match it ignoring case.
		L("set limit", `set limit `+limit+` -?\d+`),
		L("set timeout", `set timeout `+timeout+` -?\d+`),
		// pfctl_set_reassembly: "set reassemble yes " ends in a space.
		L("set reassemble", `set reassemble (?:yes|no) (?:no-df)?`),
		L("set syncookies", `set syncookies (?:never|always|adaptive(?: \(start \d+%, end \d+%\))?)`),
		L("set optimization", `set optimization (?i:normal|satellite|high-latency|conservative|aggressive)`),
		L("set loginterface", `set loginterface (?:none|`+pfIfname+`)`),
		L("set hostid", `set hostid 0x[0-9a-f]{8}`),
		// pfctl_set_debug prints the level as written: a syslog
		// priority's name (any case) or number.
		L("set debug", `set debug (?:(?i:alert|crit|debug|emerg|err|error|info|notice|panic|warn|warning)|\d+)`),
		// print_tabledef.
		L("table", `table <[^\s<>]+>(?: const)?(?: persist)?(?: counters)?(?: file "[^"]*"| \{(?:`+tableEntry+`)* \})*`),
		// print_queuespec.
		L("queue", `queue [^\s]+(?: parent \S+| on `+pfIfname+`)?(?: flows \d+(?: quantum \d+)?(?: interval \d+ms)?(?: target \d+ms)?)?(?: bandwidth `+sc+`(?:, min `+sc+`)?(?:, max `+sc+`)?)?(?: default)?(?: qlimit \d+)?`),
		L("state limiter", pfStateLimiter),
		L("source limiter", pfSourceLimiter),
		L("rule", rule),
		L("anchor opened", rule+` \{`),
		L("anchor closed", indent+`\}`),
	}, Need: []string{"rule"}}
}

func init() {
	addFormats(
		pfInfoFormat(),
		pfMemoryFormat(),
		pfTablesVerboseFormat(),
		pfTimeoutsFormat(),
		pfInterfacesFormat(),
		pfStatesFormat(),
		pfRulesFormat(),
		pfLabelsFormat(),
		pfTablesFormat(),
		pflogFormat(),
		pfKillFormat(),
		pfAnchorsFormat(),
		pfLoadFormat(),
	)
	addFormats(pfTableShowFormats()...)
	addFormats(pfTableChangeFormats()...)
}
