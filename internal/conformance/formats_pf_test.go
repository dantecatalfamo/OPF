package conformance

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/dantecatalfamo/OPF/internal/pf"
)

// pfCaptures are the pf outputs captured on OpenBSD 7.9 elsewhere in the
// repository, with the commands whose formats they are.
var pfCaptures = map[string][]string{
	"pfctl_-s_labels.txt":               {"pfctl -s labels"},
	"pfctl_-s_memory.txt":               {"pfctl -s memory"},
	"pfctl_-s_timeouts.txt":             {"pfctl -s timeouts"},
	"pfctl_-t_opf_hosts_-T_show_-v.txt": {"pfctl -t opf_hosts -T show -v", "pfctl -t * -T show -v"},
	"pfctl_-v_-s_info.txt":              {"pfctl -v -s info"},
	"pfctl_-vv_-s_Interfaces.txt":       {"pfctl -vv -s Interfaces"},
	"pfctl_-vv_-s_rules.txt":            {"pfctl -vv -s rules"},
	"pfctl_-vv_-s_states.txt":           {"pfctl -vv -s states"},
	"pfctl_-vvs_Tables.txt":             {"pfctl -vvs Tables"},
	"tcpdump_pflog.txt":                 {"tcpdump -n -e -ttt -r /var/log/pflog"},
}

func pfCheck(t *testing.T, cmd, name, out string) []string {
	t.Helper()
	f, ok := Formats[cmd]
	if !ok {
		t.Fatalf("no Format for %q", cmd)
	}
	return f.Check(out)
}

func pfRead(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The real 7.9 captures fit the formats exactly.
func TestPfFormatsCaptures(t *testing.T) {
	inRepo(t)
	dir := filepath.Join("..", "sysinfo", "testdata", "openbsd-7.9")
	for file, cmds := range pfCaptures {
		out := pfRead(t, filepath.Join(dir, file))
		for _, cmd := range cmds {
			for _, p := range pfCheck(t, cmd, file, out) {
				t.Errorf("%s as %s: %s", file, cmd, p)
			}
		}
	}
	// pfctl -nvf of the import tests' pf.conf files, the machine's and
	// the one OPF writes.
	imports, _ := filepath.Glob(filepath.Join("..", "pf", "testdata", "import", "*-pfctl-*.txt"))
	if len(imports) == 0 {
		t.Fatal("no pfctl -nvf captures in internal/pf/testdata/import")
	}
	for _, p := range imports {
		for _, problem := range pfCheck(t, "pfctl -nvf *", p, pfRead(t, p)) {
			t.Errorf("%s: %s", p, problem)
		}
	}
}

// The handwritten fixtures were written by hand, and where pfctl's
// source prints something else they fail; each is listed with what
// pfctl would print. Any other problem, or one of these going away
// without the list changing, fails.
func TestPfFormatsHandwritten(t *testing.T) {
	inRepo(t)
	dir := filepath.Join("..", "sysinfo", "testdata", "handwritten")
	cases := []struct {
		file, cmd string
		want      []string
	}{
		{"pfctl_-s_memory.txt", "pfctl -s memory", nil},
		{"tcpdump_pflog.txt", "tcpdump -n -e -ttt -r /var/log/pflog", nil},
		{"pfctl_-v_-s_info.txt", "pfctl -v -s info", []string{
			// print_status prints the Interface Stats rows
			// "  %-25s %14llu %16llu" and "    %-23s %14llu %16llu": each
			// number here is one column too far right.
			`line 7 fits no kind of line OPF knows: "  Bytes In                     518431014829                0"`,
			`line 8 fits no kind of line OPF knows: "  Bytes Out                     69121891932                0"`,
			`line 10 fits no kind of line OPF knows: "    Passed                        576012345                0"`,
			`line 11 fits no kind of line OPF knows: "    Blocked                           22124                0"`,
			`line 13 fits no kind of line OPF knows: "    Passed                         76802102                0"`,
			`line 14 fits no kind of line OPF knows: "    Blocked                               0                0"`,
			// With -v print_status always prints a Fragments section
			// (and no blank line before Adaptive Syncookies Watermarks,
			// which a line-by-line check can't see).
			`no Fragments heading line`,
		}},
		{"pfctl_-vv_-s_rules.txt", "pfctl -vv -s rules", []string{
			// "Bytes: %-10llu  States": two spaces even after an
			// 11-digit count.
			`line 14 fits no kind of line OPF knows: "  [ Evaluations: 1204998   Packets: 88120334  Bytes: 99120334012 States: 241   ]"`,
			// With -vv print_addr counts a table's addresses: <bogons:N>.
			`line 16 fits no kind of line OPF knows: "@5 block drop in log quick on em0 from <bogons> to any label \"opf:builtin:block-bogons\""`,
			// print_rule prints "keep state" only with options after it.
			`line 19 fits no kind of line OPF knows: "@6 pass in quick on em0 proto udp from any to (em0:0) port = 51820 keep state label \"has no opf prefix\""`,
			// print_rule prints the label before nat-to.
			`line 22 fits no kind of line OPF knows: "@7 match out on em0 inet from 192.168.1.0/24 to any nat-to (em0:0) round-robin label \"opf:auto-nat:lan\""`,
			`line 23 fits no kind of line OPF knows: "  [ Evaluations: 99120     Packets: 88120334  Bytes: 99120334012 States: 0     ]"`,
		}},
		{"pfctl_-vv_-s_states.txt", "pfctl -vv -s states", []string{
			// print_state prints an ICMPv6 state's peers as numbers
			// ("0:0"), never NO_TRAFFIC.
			`line 19 fits no kind of line OPF knows: "all ipv6-icmp fe80::1[128] <- fe80::be24:11ff:fef6:5ebd[128]       NO_TRAFFIC:NO_TRAFFIC"`,
		}},
	}
	for _, c := range cases {
		got := pfCheck(t, c.cmd, c.file, pfRead(t, filepath.Join(dir, c.file)))
		if !slices.Equal(got, c.want) {
			t.Errorf("handwritten %s as %s:\ngot  %q\nwant %q", c.file, c.cmd, got, c.want)
		}
	}
}

// pfLines joins lines into an output.
func pfLines(ls ...string) string { return strings.Join(ls, "\n") + "\n" }

// Variants the captures lack, printed with the source's printf formats.
func TestPfFormatsSamples(t *testing.T) {
	inRepo(t)
	sp := fmt.Sprintf
	row := func(name string, n uint64, rate string) string {
		if rate == "" {
			return sp("  %-25s %14d %14s", name, n, "")
		}
		return sp("  %-25s %14d %14s/s", name, n, rate)
	}
	var info []string
	info = append(info,
		sp("%-44s%15s", "Status: Disabled", "Debug: warn"), "",
		sp("Hostid:   0x%08x", 0xd04fb106), sp("Checksum: 0x%s", strings.Repeat("0f", 16)), "",
		sp("Interface Stats for %-16s %5s %16s", "vio0", "IPv4", "IPv6"),
		sp("  %-25s %14d %16d", "Bytes In", 518431014829, 0),
		sp("  %-25s %14d %16d", "Bytes Out", 1, 99999999999999999),
		"  Packets In",
		sp("    %-23s %14d %16d", "Passed", 576012345, 0),
		sp("    %-23s %14d %16d", "Blocked", 22124, 3),
		"  Packets Out",
		sp("    %-23s %14d %16d", "Passed", 76802102, 0),
		sp("    %-23s %14d %16d", "Blocked", 0, 0), "",
		sp("%-27s %14s %16s", "State Table", "Total", "Rate"),
		row("current entries", 318, ""), row("half-open tcp", 2, ""))
	for _, n := range pfTableCounters {
		info = append(info, row(n, 0, ""))
	}
	for _, sec := range [][]string{{"Source Tracking Table"}, {"Fragments"}} {
		info = append(info, sec[0], row("current entries", 0, ""))
		for _, n := range pfTableCounters {
			info = append(info, row(n, 123456789012345678, ""))
		}
	}
	info = append(info, "Counters")
	for _, n := range pfReasons {
		info = append(info, row(n, 0, ""))
	}
	info = append(info, "Limit Counters")
	for _, n := range pfLimitCounters {
		info = append(info, row(n, 0, ""))
	}
	info = append(info, "Adaptive Syncookies Watermarks",
		sp("  %-25s %14d states", "start", 25000), sp("  %-25s %14d states", "end", 12500))
	// The same while running, with rates.
	running := slices.Clone(info)
	running[0] = sp("%-44s%15s", "Status: Enabled for 1234 days 23:59:59", "Debug: emerg")
	for i, l := range running {
		if strings.HasSuffix(l, strings.Repeat(" ", 14)) && !strings.Contains(l, "current entries") && !strings.Contains(l, "half-open") {
			running[i] = strings.TrimSuffix(l, strings.Repeat(" ", 14)) + sp("%14.1f/s", 12345.6)
		}
	}

	tstats := func(flags, name string) []string {
		ls := []string{flags + "\t" + name, "\tAddresses:   3", "\tCleared:     Wed Oct  7 14:58:42 2026",
			sp("\tReferences:  [ Anchors: %-18d Rules: %-18d ]", 1, 2),
			sp("\tEvaluations: [ NoMatch: %-18d Match: %-18d ]", 4, 123456789012345678)}
		for _, n := range pfTableStats {
			ls = append(ls, sp("\t%-12s [ Packets: %-18d Bytes: %-18d ]", n, 0, 1234567890123456789))
		}
		return ls
	}
	iface := func(name string) []string {
		ls := []string{name, "\tCleared:     Thu Oct 18 03:13:03 2026", sp("\tReferences:  [ States:  %-18d Rules: %-18d ]", 81, 1)}
		for _, n := range pfIfaceStats {
			ls = append(ls, sp("\t%-12s [ Packets: %-18d Bytes: %-18d ]", n, 342775, 412869865))
		}
		return ls
	}
	astats := func(addr string, extra ...string) []string {
		ls := append([]string{addr, "\tCleared:     Wed Oct  7 15:44:41 2026"}, extra...)
		for _, n := range pfAddressStats {
			ls = append(ls, sp("\t%-12s [ Packets: %-18d Bytes: %-18d ]", n, 2957, 4348092))
		}
		return ls
	}
	counters := func(ev, pk, by, st, cr int) []string {
		return []string{
			sp("  [ Evaluations: %-8d  Packets: %-8d  Bytes: %-10d  States: %-6d]", ev, pk, by, st),
			sp("  [ Inserted: uid %d pid %d State Creations: %-6d]", 0, 98091, cr),
		}
	}
	var pflog []string
	for _, r := range pfReasons {
		for _, a := range pflogActions {
			pflog = append(pflog, sp("Sep 01 16:20:01.123456 rule 3/(%s) %s out on vio0: 198.51.100.23.51234 > 203.0.113.24.22: S 1:1(0) win 1024", r, a))
		}
	}

	cases := []struct {
		cmd, what, out string
	}{
		{"pfctl -v -s info", "disabled, with the statistics interface", pfLines(info...)},
		{"pfctl -v -s info", "running, with rates", pfLines(running...)},
		{"pfctl -s memory", "unlimited pools", pfLines(
			sp("%-13s unlimited", "states"), sp("%-13s hard limit %8d", "src-nodes", 10000),
			sp("%-13s hard limit %8d", "frags", 4294967294), sp("%-13s unlimited", "tables"),
			sp("%-13s hard limit %8d", "table-entries", 200000), sp("%-13s hard limit %8d", "pktdelay-pkts", 1),
			sp("%-13s hard limit %8d", "anchors", 512))},
		{"pfctl -vvs Tables", "a table in an anchor, every flag", pfLines(append(tstats("cpairhC", "authpf_users@authpf/alice(1234)"), tstats("-------", "t")...)...)},
		{"pfctl -s Tables", "tables in anchors", pfLines("bruteforce", "opf_hosts", "authpf_users@authpf/alice(1234)")},
		{"pfctl -vv -s Interfaces", "groups, skipped interfaces", pfLines(append(append(iface("lo0 (skip)"), iface("wg")...), iface("vlan20")...)...)},
		{"pfctl -vv -s states", "every kind of state", pfLines(
			// NAT out: the address on the wire, the inside one in parentheses.
			"all tcp 203.0.113.24:50001 (192.168.1.112:52344) -> 140.82.112.4:443       ESTABLISHED:ESTABLISHED",
			"   [1234567890 + 132096](+4294967295) wscale 6  [3456789012 + 131328] wscale 7",
			"   age 1234:05:06, expires in 23:59:58, 1234:5678 pkts, 123456:7890123 bytes, anchor 3, rule 12, sloppy, pflow, source-track, sticky-address",
			"   id: 6505b0d400000002 creatorid: 1c9d3f2a",
			// A port forward in: the inside address, the one sent to in parentheses.
			"vio0 tcp 192.168.1.20:443 (203.0.113.24:8443) <- 198.51.100.9:61000       SYN_SENT:CLOSED",
			"   [0 + 0]  [0 + 0](+12)",
			"   age 00:00:01, expires in 00:00:29, 1:0 pkts, 60:0 bytes",
			"   id: 6505b0d400000003 creatorid: 00000001",
			// route-to (braces), an rdomain, IPv6 ports in brackets.
			"all udp (1) 2001:db8::1[53] (2001:db8::2[53]) {fe80::1} <- (1) 2001:db8::118[51000]       MULTIPLE:SINGLE",
			"   age 00:00:04, expires in 00:00:56, 1:1 pkts, 61:77 bytes, rule 9",
			"   id: 6505b0d400000004 creatorid: 1c9d3f2a",
			"all tcp 10.0.0.2:22 -> 10.0.0.1:1234 {192.0.2.1}       PROXY:SRC",
			"   [1 + 2]  [3 + 4]",
			"   age 00:00:04, expires in 00:00:56, 1:1 pkts, 61:77 bytes, rule 9",
			"   id: 6505b0d400000005 creatorid: 1c9d3f2a",
			"all tcp 10.0.0.2:22 -> 10.0.0.1:1234       <BAD STATE LEVELS 13:14>",
			"   age 00:00:04, expires in 00:00:56, 1:1 pkts, 61:77 bytes",
			"   id: 6505b0d400000006 creatorid: 1c9d3f2a",
			"all ipv6-icmp fe80::1[128] <- fe80::be24:11ff:fef6:5ebd[128]       0:0",
			"   age 00:00:02, expires in 00:00:08, 1:0 pkts, 64:0 bytes, rule 1",
			"   id: 6505b0d400000007 creatorid: 1c9d3f2a",
			"all icmp 192.168.1.1:11 <- 192.168.1.118:11       0:0",
			"all esp 192.0.2.1 -> 192.0.2.2       MULTIPLE:MULTIPLE",
			"all gre 192.0.2.1 -> 192.0.2.2       NO_TRAFFIC:SINGLE",
			"all 253 192.0.2.1 -> 192.0.2.2       2:1",
			"   age 00:00:02, expires in 00:00:08, 1:0 pkts, 64:0 bytes, rule 1",
			"   id: 6505b0d400000008 creatorid: 1c9d3f2a")},
		{"pfctl -vv -s rules", "limiters, anchors, tables, every option", pfLines(slices.Concat(
			[]string{
				`state limiter "web" id 1 limit 100 rate 10/1`,
				`source limiter "ssh" id 2 entries 1000 limit 5 rate 3/60 table <bruteforce> above 10 below 5 inet mask 24 inet6 mask 64`,
				`source limiter "dns" id 3 entries 10 limit 5`,
				`@0 block return-icmp6(port-unr) in log (all, matches, user, to pflog1) quick on ! vio0 on ! rdomain 1 inet6 proto ipv6-icmp from ! <bogons:12> port 1:2 os "OpenBSD" to (vio0:network:0:1) port 3 >< 4 !received-on vlan20 user = unknown group >= 1000 icmp6-type echoreq code 0 tos 0x10 prio 3 max-pkt-rate 100/10 set (prio(2, 5), queue(std, ack), tos 0x08, delay 100) state limiter "web" (no-match) label "opf:rule:r1" once tag t1 ! tagged t2 rtable 2 divert-reply # expired`,
			},
			counters(1204998, 88120334, 99120334012, 241, 402311),
			[]string{`@1 pass in on egress inet proto tcp from any to (egress:*) port = 22 flags S/SA modulate state probability 12.5% source limiter id 2 (block) (max 100, no-sync, source-track rule, max-src-states 3, max-src-conn 15, max-src-conn-rate 5/3, max-src-nodes 9, overload <bruteforce:0> flush global, if-bound, sloppy, pflow, tcp.established 3600, adaptive.start 6000) fragment scrub (no-df random-id min-ttl 3 reassemble tcp max-mss 1440) allow-opts label "opf:rule:r2" rdr-to 192.168.1.10 port 80:90 random sticky-address route-to 10.0.0.1@vio1`},
			counters(0, 0, 0, 0, 0),
			[]string{`@2 match out on egress inet from 192.168.1.0 - 192.168.1.9 to any label "opf:auto-nat:lan" nat-to (egress:0:1) port 1024:65535 source-hash 0x0123456789abcdef0123456789abcdef static-port`},
			counters(0, 0, 0, 0, 0),
			[]string{`@3 pass out inet6 all flags any keep state (max 10) af-to inet from 192.0.2.1 to 10.0.0.1 round-robin`},
			counters(0, 0, 0, 0, 0),
			[]string{`@4 anchor "authpf/*" all`},
			counters(0, 0, 0, 0, 0),
			// An anchor with braces: its rules after its counters, not
			// indented with -v.
			[]string{`@5 anchor in on vio1 all {`},
			counters(0, 0, 0, 0, 0),
			[]string{`@0 block drop all`},
			counters(0, 0, 0, 0, 0),
			[]string{"}"},
		)...)},
		{"pfctl -s labels", "limiters", pfLines(
			sp("%3s %8s/%-8s %5s/%-5s %8s %8s %8s", "ID", "USE", "LIMIT", "RATE", "SECS", "ADMIT", "HARDLIM", "RATELIM"),
			sp("%3d %8d/%-8d %5d/%-5d %8d %8d %8d", 1, 5, 100, 10, 1, 7, 0, 123456789),
			sp("%3d %8d/%-8d %5s/%-5s %8d %8d %8d", 255, 5, 100, "nil", "nil", 7, 0, 0),
			sp("%3s %8s/%-8s %5s %5s/%-5s %8s %8s %8s %8s", "ID", "USE", "ADDRS", "LIMIT", "RATE", "SECS", "ADMIT", "ADDRLIM", "HARDLIM", "RATELIM"),
			sp("%3d %8d/%-8d %5d %5s/%-5s %8d %8d %8d %8d", 2, 5, 1000, 5, "nil", "nil", 1, 2, 3, 4),
			sp("%3d %8d/%-8d %5d %5d/%-5d %8d %8d %8d %8d", 3, 5, 1000, 5, 3, 60, 1, 2, 3, 4),
			"opf:rule:r1 68 128 7616 64 3584 64 4032 64")},
		{"tcpdump -n -e -ttt -r /var/log/pflog", "every reason and action, anchors, truncation", pfLines(append(pflog,
			"tcpdump: WARNING: snaplen raised from 116 to 160",
			"Sep 29 16:22:10.000000 rule 2.authpf/alice(1234).1/(match) pass in on vio1: 192.168.1.118.51000 > 192.168.1.1.443: S 5:5(0) win 65535 (DF)",
			"Sep 29 16:22:10.000000 rule 2.authpf/alice(1234).def/(match) block in on vio1: 192.168.1.118.51000 > 192.168.1.1.443: S 5:5(0) win 65535 (DF)",
			"Dec 31 23:59:59.999999 rule def/(ip-option) block in on vio0: :: > ff02::16: HBH multicast listener report v2, 1 group record(s) [hlim 1]",
			"Dec 31 23:59:59.999999 rule 1/(match) pass out on wg0: unknown-af 18",
			"Dec 31 23:59:59.999999 [|pflog]",
			"Dec 31 23:59:59.999999 [pflog: invalid header length!]",
			"tcpdump: pcap_loop: truncated dump file; tried to read 160 captured bytes, only got 12")...)},
		{"tcpdump -n -e -ttt -r /var/log/pflog", "no log", pfLines("tcpdump: /var/log/pflog: No such file or directory")},
		{"pfctl -t * -T show", "networks, negation, interfaces", pfLines("   192.0.2.0/24", "  !192.0.2.128/25", "   2001:db8::/32", "   10.0.0.1@vio0")},
		{"pfctl -t * -T show", "an empty table", ""},
		{"pfctl -t * -T show", "no table", pfLines("pfctl: Table does not exist")},
		{"pfctl -t * -T show -v", "states, weight, interface", pfLines(append(astats("  !192.0.2.128/25", "\tActive States:      3", "\tWeight:             2", "\tInterface:          vio0"),
			"   192.0.2.1", "\tCleared:     1234")...)},
		{"pfctl -t opf_hosts -T show -v", "counters", pfLines(append(astats("   192.168.50.2"), astats("   2001:db8::2")...)...)},
		{"pfctl -t * -T * ...", "add to a new table", pfLines(`pfctl: warning: table <t> already defined in anchor "authpf/alice(1)"`, "1 table created.", "2/3 addresses added.")},
		{"pfctl -t * -T * ...", "delete", pfLines("0/1 addresses deleted.")},
		{"pfctl -t * -T * ...", "flush", pfLines("12 addresses deleted.")},
		{"pfctl -t opf_hosts -T * ...", "add", pfLines("1 table created.", "2/2 addresses added.")},
		{"pfctl -t opf_hosts -T kill", "kill", pfLines("1 table deleted.")},
		{"pfctl -t * -T replace -f *", "changes", pfLines("1 table created.", "3 addresses added.", "1 addresses deleted.", "2 addresses changed.")},
		{"pfctl -t * -T replace -f *", "no changes", pfLines("no changes.")},
		{"pfctl -t * -T replace ...", "a group's gateways", pfLines("2 addresses added.", "1 addresses deleted.")},
		{"pfctl -t * -T expire *", "expire", pfLines("0/0 addresses expired.")},
		{"pfctl -k id -k *", "kill", pfLines("killed 1 states")},
		{"pfctl -a authpf -s Anchors", "sessions", pfLines("  authpf/alice(1234)", "  authpf/5678", "  authpf/alice(1234)/sub")},
		{"pfctl -a authpf -s Anchors", "none", ""},
		{"pfctl -a authpf -s Anchors", "no anchor", pfLines("pfctl: Anchor does not exist")},
		{"pfctl -nvf *", "every option, tables, queues, anchors", pfLines(
			`ext_if = "vio0"`,
			"set block-policy return", `set fingerprints "/etc/pf.os"`, "set state-policy if-bound",
			"set skip on none", "set skip on { lo wg0 }",
			"set limit states 100000", "set limit TABLE-ENTRIES 400000", "set timeout tcp.established 3600", "set timeout adaptive.start 6000",
			"set reassemble yes no-df", "set reassemble yes ", "set reassemble no ",
			"set syncookies always", "set syncookies adaptive", "set syncookies adaptive (start 25%, end 12%)",
			"set optimization high-latency", "set loginterface vio0", "set hostid 0x0000002a", "set debug warning", "set debug 3",
			"table <servers> const persist counters { 192.168.1.10 !192.168.1.11 2001:db8::/64 (vio0) 10.0.0.1@vio1 }",
			`table <list> persist file "/etc/opf/tables/list"`, "table <empty> { }",
			"queue rootq on vio0 bandwidth 100M, max 100M",
			"queue std parent rootq flows 1024 quantum 1500 interval 100ms target 5ms bandwidth 500  burst 1G for 50ms, min 5%, max 50M default qlimit 50",
			`state limiter "web" id 1 limit 100`,
			"block drop all", "",
			`anchor "authpf/*" all`, "",
			"anchor in on vio1 all {",
			"  pass all flags S/SA",
			"",
			"}",
			`anchor "named" all {`,
			"  match out on egress inet from ! (egress:network) to any nat-to (egress:0) round-robin",
			"",
			"}")},
	}
	for _, c := range cases {
		for _, p := range pfCheck(t, c.cmd, c.what, c.out) {
			t.Errorf("%s (%s): %s", c.cmd, c.what, p)
		}
	}
}

// Lines the source can't print, or a changed release would, fail.
func TestPfFormatsReject(t *testing.T) {
	inRepo(t)
	sp := fmt.Sprintf
	cases := []struct{ cmd, why, line string }{
		{"pfctl -v -s info", "a new counter", sp("  %-25s %14d %14s", "new-counter", 0, "")},
		{"pfctl -v -s info", "a counter a column off", sp("  %-25s %15d %13s", "match", 0, "")},
		{"pfctl -v -s info", "a renamed debug level", sp("%-44s%15s", "Status: Disabled", "Debug: warning")},
		{"pfctl -s memory", "a new pool", sp("%-13s hard limit %8d", "sources", 1)},
		{"pfctl -s memory", "a wider name column", sp("%-14s hard limit %8d", "states", 1)},
		{"pfctl -s timeouts", "seconds on a state count", sp("%-20s %10ds", "adaptive.start", 1)},
		{"pfctl -s timeouts", "a new timeout", sp("%-20s %10ds", "sctp.first", 1)},
		{"pfctl -vvs Tables", "a new flag", "-pa-r--x\tt"},
		{"pfctl -vvs Tables", "a new counter", sp("\t%-12s [ Packets: %-18d Bytes: %-18d ]", "In/Drop:", 0, 0)},
		{"pfctl -vv -s Interfaces", "a new counter", sp("\t%-12s [ Packets: %-18d Bytes: %-18d ]", "In4/Match:", 0, 0)},
		{"pfctl -vv -s states", "a new TCP state", "all tcp 1.2.3.4:1 -> 5.6.7.8:2       ESTABLISHED:RESET"},
		{"pfctl -vv -s states", "UDP state names on ICMP", "all icmp 1.2.3.4:1 -> 5.6.7.8:1       SINGLE:SINGLE"},
		{"pfctl -vv -s states", "one fewer space before the states", "all udp 1.2.3.4:1 -> 5.6.7.8:2      SINGLE:SINGLE"},
		{"pfctl -vv -s states", "an IPv6 port after a colon", "all udp 2001:db8::1:53 -> 2001:db8::2[53]       SINGLE:SINGLE"},
		{"pfctl -vv -s states", "a new age field", "   age 00:00:01, expires in 00:00:29, 1:0 pkts, 60:0 bytes, rule 1, nat"},
		{"pfctl -vv -s states", "a short id", "   id: 6505b0d4 creatorid: 1c9d3f2a"},
		{"pfctl -vv -s rules", "a rule without its number", "pass all flags S/SA"},
		{"pfctl -vv -s rules", "a table without its count", "@0 pass from <t> to any flags S/SA"},
		{"pfctl -vv -s rules", "a new action", "@0 drop all"},
		{"pfctl -vv -s rules", "the label after nat-to", `@0 match out all nat-to 1.2.3.4 label "x"`},
		{"pfctl -vv -s rules", "counters a column off", sp("  [ Evaluations: %-9d Packets: %-8d  Bytes: %-10d  States: %-6d]", 1, 2, 3, 4)},
		{"pfctl -s labels", "a label without states", "opf:rule:r1 68 128 7616 64 3584 64 4032"},
		{"tcpdump -n -e -ttt -r /var/log/pflog", "a new reason", "Sep 01 16:20:01.123456 rule 3/(state-flood) block in on vio0: x"},
		{"tcpdump -n -e -ttt -r /var/log/pflog", "a new action", "Sep 01 16:20:01.123456 rule 3/(match) drop in on vio0: x"},
		{"tcpdump -n -e -ttt -r /var/log/pflog", "a space-padded day", "Sep  1 16:20:01.123456 rule 3/(match) block in on vio0: x"},
		{"tcpdump -n -e -ttt -r /var/log/pflog", "an unknown reason", "Sep 01 16:20:01.123456 rule 3/(unkn 17) block in on vio0: x"},
		{"pfctl -t * -T show", "an address without its indent", "192.0.2.1"},
		{"pfctl -t opf_hosts -T show -v", "a new counter", sp("\t%-12s [ Packets: %-18d Bytes: %-18d ]", "In/XPass:", 0, 0)},
		{"pfctl -t * -T * ...", "a message without its period", "2/3 addresses added"},
		{"pfctl -t * -T expire *", "a renamed message", "0/0 addresses removed."},
		{"pfctl -k id -k *", "a reworded message", "killed 1 state"},
		{"pfctl -nvf *", "a new option", "set syncookies sometimes"},
		{"pfctl -nvf *", "a limit pfctl doesn't have", "set limit sources 10"},
		{"pfctl -nvf *", "keep state without options", "pass all flags S/SA keep state"},
		{"pfctl -nvf *", "a table count without -vv", "pass from <t:3> to any flags S/SA"},
	}
	for _, c := range cases {
		if len(pfCheck(t, c.cmd, c.why, c.line+"\n")) == 0 {
			t.Errorf("%s: %s fits: %q", c.cmd, c.why, c.line)
		}
	}
	// And a missing line fails too.
	for cmd, l := range map[string]string{
		"pfctl -s memory":   sp("%-13s hard limit %8d", "states", 1),
		"pfctl -s timeouts": sp("%-20s %10ds", "tcp.first", 120),
		"pfctl -v -s info":  sp("%-44s%15s", "Status: Disabled", "Debug: err"),
	} {
		if len(pfCheck(t, cmd, "one line", l+"\n")) == 0 {
			t.Errorf("%s: one line of the output is enough", cmd)
		}
	}
}

// OPF's own lists of pf's names are pfctl's.
func TestPfFormatsNames(t *testing.T) {
	inRepo(t)
	if !slices.Equal(pf.LimitNames, pfLimits) {
		t.Errorf("pf.LimitNames %q, pfctl's pf_limits %q", pf.LimitNames, pfLimits)
	}
	if a, b := slices.Sorted(slices.Values(pf.TimeoutNames)), slices.Sorted(slices.Values(pfTimeouts)); !slices.Equal(a, b) {
		t.Errorf("pf.TimeoutNames %q, pfctl's pf_timeouts %q", a, b)
	}
	// Every format is a registry command's.
	for _, f := range []string{"pfctl -v -s info", "pfctl -s memory", "pfctl -vvs Tables", "pfctl -s timeouts",
		"pfctl -vv -s Interfaces", "pfctl -vv -s states", "pfctl -vv -s rules", "pfctl -s labels", "pfctl -s Tables",
		"tcpdump -n -e -ttt -r /var/log/pflog", "pfctl -t * -T show", "pfctl -t * -T show -v",
		"pfctl -t opf_hosts -T show -v", "pfctl -t * -T * ...", "pfctl -t opf_hosts -T * ...", "pfctl -t opf_hosts -T kill",
		"pfctl -t * -T replace -f *", "pfctl -t * -T replace ...", "pfctl -t * -T expire *", "pfctl -k id -k *", "pfctl -nvf *", "pfctl -a authpf -s Anchors"} {
		if _, ok := Formats[f]; !ok {
			t.Errorf("no Format for %s", f)
		}
		if !slices.ContainsFunc(Commands, func(c Command) bool { return strings.Join(c.Argv, " ") == f }) {
			t.Errorf("Format %s isn't a registry command", f)
		}
	}
}
