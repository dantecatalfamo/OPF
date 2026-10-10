package conformance

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The resolver's formats against the outputs captured on 7.9 and, for
// what those lack, samples written as unbound's and dhcpd's source
// prints them (see formats_unbound.go for the functions).

func ubRead(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", rel))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func ubCheck(t *testing.T, command, what, out string) {
	t.Helper()
	f, ok := Formats[command]
	if !ok {
		t.Fatalf("no format for %q", command)
	}
	for _, p := range f.Check(out) {
		t.Errorf("%s (%s): %s", command, what, p)
	}
}

// ubSamples are outputs the captures don't have, by command.
var ubSamples = map[string][]string{
	ubCtl + "lookup *": {
		// A delegation from the cache: the rrset and its addresses
		// (dump_rrset with now 0 prints absolute TTLs).
		"The following name servers are used for lookup of example.com.\n" +
			";rrset 1791387300 2 0 1 0\n" +
			"example.com.\t1791387300\tIN\tNS\ta.iana-servers.net.\n" +
			"example.com.\t1791387300\tIN\tNS\tb.iana-servers.net.\n" +
			"Delegation with 2 names, of which 0 can be examined to query further addresses.\n" +
			"It provides 2 IP addresses.\n" +
			"199.43.135.53   \trto 120 msec, ttl 812, ping 24 var 24 rtt 120, tA 0, tAAAA 0, tother 0, EDNS 0 probed.\n" +
			"2001:500:8f::53 \tnot in infra cache.\n",
		// A forward zone.
		"The following name servers are used for lookup of example.com.\n" +
			"forwarding request:\n" +
			"Delegation with 0 names, of which 0 can be examined to query further addresses.\n" +
			"It provides 2 IP addresses.\n" +
			"9.9.9.9         \tnot in infra cache.\n" +
			"149.112.112.112 \tLAME rto 376 msec, ttl 900, ping 24 var 88 rtt 376, tA 0, tAAAA 0, tother 0, probedelay 2, noEDNS assumed.\n",
		// Nothing cached yet, and a useless delegation.
		"The following name servers are used for lookup of example.com.\n" +
			"no delegation from cache; goes to configured roots\n",
		"The following name servers are used for lookup of www.example.com.\n" +
			";rrset 1791387300 1 0 1 0\n" +
			"example.com.\t1791387300\tIN\tNS\ta.iana-servers.net.\n" +
			"Delegation with 1 names, of which 1 can be examined to query further addresses.\n" +
			"It provides 0 IP addresses.\n" +
			"cache delegation was useless (no IP addresses)\n" +
			"going up, lookup com.\n" +
			";rrset 1791473700 1 0 1 0\n" +
			"com.\t1791473700\tIN\tNS\ta.gtld-servers.net.\n" +
			"Delegation with 1 names, of which 0 can be examined to query further addresses.\n" +
			"It provides 1 IP addresses.\n" +
			"192.5.6.30      \texpired, rto 120000 msec, tA 0 tAAAA 0 tother 0.\n",
	},
	ubCtl + "list_local_zones": {
		"home.test. transparent\n" +
			"test. static\n" +
			"localhost. redirect\n" +
			"127.in-addr.arpa. static\n" +
			"1.168.192.in-addr.arpa. transparent\n" +
			"onion. always_nxdomain\n",
	},
	// Each record ends in an empty line (do_list_local_data).
	ubCtl + "list_local_data": {
		"localhost.\t10800\tIN\tNS\tlocalhost.\n\n" +
			"localhost.\t10800\tIN\tSOA\tlocalhost. nobody.invalid. 1 3600 1200 604800 10800\n\n" +
			"localhost.\t10800\tIN\tA\t127.0.0.1\n\n" +
			"priya-mbp.home.test.\t3600\tIN\tA\t192.168.1.112\n\n",
	},
	ubCtl + "status": {
		"version: 1.26.1\nverbosity: 1\nthreads: 1\nmodules: 2 [ validator iterator ]\nuptime: 152 seconds\noptions: control(namedpipe)\nunbound (pid 46658) is running...\n",
		"version: 1.26.1\nverbosity: 1\nthreads: 2\nmodules: 3 [ respip validator iterator ]\nuptime: 0 seconds\noptions: reuseport control(namedpipe)\nunbound (pid 46658) is running...\n",
	},
	ubCtl + "flush *":                   {"ok\n"},
	ubCtl + "flush_zone *":              {"ok removed 3 rrsets, 1 messages and 0 key entries\n"},
	ubCtl + "flush_bogus":               {"ok removed 0 rrsets, 0 messages and 0 key entries\n"},
	ubCtl + "flush_negative":            {"ok removed 0 rrsets, 2 messages and 0 key entries\n"},
	ubCtl + "local_data * * IN A *":     {"ok\n"},
	ubCtl + "local_data * * IN PTR *":   {"ok\n"},
	ubCtl + "local_data_remove *":       {"ok\n"},
	ubCtl + "auth_zone_reload *":        {"ok\n"},
	ubCtl + "auth_zone_reload opf-own.": {"ok\n", "opf-own.: ZONEMD verification successful\nok\n"},
	"unbound-anchor -v -a *": {
		"/var/unbound/db/root.key does not exist\nsuccess: the anchor is ok\n",
		"/var/unbound/db/root.key has content\n" +
			"[1791387199] libunbound[51234:0] error: udp connect failed: Network is unreachable for 198.41.0.4 port 53 (len 16)\n" +
			"last successful probe: Mon Oct  5 10:00:00 2026\n" +
			"the last successful probe is recent\n" +
			"fail: the anchor is NOT ok and could not be fixed\n",
	},
	// unbound's logfile with OPF's settings: log_reply_info,
	// log_rpz_apply and other messages (sysinfo's test lines among
	// them; their thread numbers read the same in hex or decimal).
	"file /var/unbound/db/opf-dns.log": {
		"[1791387197] unbound[46658:0] notice: init module 0: respip\n" +
			"[1791387197] unbound[46658:0] info: start of service (unbound 1.26.1).\n" +
			"[1791387199] unbound[46658:0] reply: 127.0.0.1 a.home.test. A IN NOERROR 0.000000 1 56\n" +
			"[1791387199] unbound[46658:0] reply: 192.168.1.23 nope.home.test. AAAA IN NXDOMAIN 0.012000 0 43\n" +
			"[1791387199] unbound[46659:1] reply: fd00::23 example.com. HTTPS IN NOERROR 0.034211 0 104\n" +
			"[1791387199] unbound[46658:0] reply: 192.168.1.23 . NS IN NOERROR 0.000000 1 239\n" +
			"[1791387199] unbound[46658:0] reply: 192.168.1.23 we?ird.example. TYPE65280 IN SERVFAIL 1.500000 0 40\n" +
			"[1791387199] unbound[46658:0] reply: 192.168.1.5 - - - FORMERR - - -\n" +
			"[1791387199] unbound[46658:0] info: rpz: applied [opf:own] blocked.example. rpz-nxdomain 127.0.0.1@45073 blocked.example. A IN\n" +
			"[1791387200] unbound[46658:0] info: rpz: applied [opf:list:ads] *.doubleclick.net. rpz-local-data 192.168.1.23@51932 securepubads.g.doubleclick.net. A IN\n" +
			"[1791387200] unbound[46658:0] info: rpz: applied [opf:own] nsdname ns1.bad.example. rpz-nxdomain  x.bad.example. A IN\n" +
			"[1791387200] unbound[46658:0] info: rpz: applied [opf:own] clientip 192.168.1.66/32 rpz-drop 192.168.1.66@5353 a.example. A IN\n" +
			"[1791387200] unbound[46658:0] info: rpz: applied [opf:own] nsip 2001:db8::53/128 rpz-passthru fd00::23@4410 b.example. AAAA IN\n" +
			"[1791387206] unbound[46658:0] warning: continuing with less udp ports: 472\n" +
			"[1791387206] unbound[46658:0] info: validation failure <bad.example. A IN>: signature crypto failed from 192.0.2.53 for DS bad.example. while building chain of trust\n" +
			"[1791387207] unbound[46658:0] error: could not open autotrust file for writing, /var/unbound/db/root.key.46658-0-1c2d3e4f: Permission denied\n" +
			"[1791387300] unbound[46658:0] info: service stopped (unbound 1.26.1).\n",
	},
	// write_lease's blocks: every statement, one lease with nothing after
	// ends, and hostnames a client chose, written as they came.
	"file /var/db/dhcpd.leases": {
		"lease 192.168.1.112 {\n" +
			"\tstarts 1 2026/09/28 10:00:00 UTC;\n" +
			"\tends 2 2026/09/29 10:00:00 UTC;\n" +
			"\thardware ethernet 3c:22:fb:10:aa:01;\n" +
			"\tuid 01:3c:22:fb:10:aa:01;\n" +
			"\tclient-hostname \"priya-mbp\";\n" +
			"}\n" +
			"lease 192.168.1.118 {\n" +
			"\tstarts 1 2026/09/28 09:00:00 UTC;\n" +
			"\tends 1 2026/09/28 21:00:00 UTC;\n" +
			"\thardware ethernet 3c:22:fb:10:aa:02;\n" +
			"\tdynamic-bootp;\n" +
			"\tabandoned;\n" +
			"\thostname \"printer\";\n" +
			"}\n" +
			"lease 192.168.1.120 {\n" +
			"\tstarts 1 2026/09/28 09:00:00 UTC;\n" +
			"\tends 1 2026/09/28 21:00:00 UTC;\n" +
			"\n" +
			"}\n" +
			"lease 192.168.1.121 {\n" +
			"\tstarts 1 2026/09/28 09:00:00 UTC;\n" +
			"\tends 1 2026/09/28 21:00:00 UTC;\n" +
			"\thardware ethernet 3c:22:fb:10:aa:03;\n" +
			"\tclient-hostname \"evil\\\";\n" +
			"}\n" +
			"lease 192.168.1.122 {\n" +
			"\tstarts 1 2026/09/28 09:00:00 UTC;\n" +
			"\tends 1 2026/09/28 21:00:00 UTC;\n" +
			"\thardware ethernet 3c:22:fb:10:aa:04;\n" +
			"\tclient-hostname \"x\";ends\"never\";client-hostname\"y\";\n" +
			"}\n",
		"", // a leases file before the first lease
	},
}

func TestUnboundFormats(t *testing.T) {
	inRepo(t)
	// The captures from 7.9.
	ubCheck(t, ubCtl+"stats_noreset", "capture", ubRead(t, "sysinfo/testdata/openbsd-7.9/unbound-control_stats_noreset.txt"))
	ubCheck(t, ubCtl+"dump_cache", "capture", ubRead(t, "appliance/testdata/openbsd-7.9/unbound-control_dump_cache.txt"))
	leases, _ := filepath.Glob(filepath.Join("..", "pf", "testdata", "import", "*", "var", "db", "dhcpd.leases"))
	for _, p := range leases {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		ubCheck(t, "file /var/db/dhcpd.leases", p, string(b))
	}

	// Two threads (num-threads: 2, for a blocklist), and counters only
	// printed when not zero.
	stats := ubRead(t, "sysinfo/testdata/openbsd-7.9/unbound-control_stats_noreset.txt")
	var thread1 []string
	for _, l := range strings.Split(stats, "\n") {
		if strings.HasPrefix(l, "thread0.") {
			thread1 = append(thread1, "thread1."+strings.TrimPrefix(l, "thread0."))
		}
	}
	stats = strings.Replace(stats, "total.num.queries=", strings.Join(thread1, "\n")+"\ntotal.num.queries=", 1)
	stats += "num.query.type.HTTPS=4\nnum.query.type.TYPE0=1\nnum.query.type.other=1\nnum.query.class.CLASS7=1\n" +
		"num.query.opcode.NOTIFY=1\nnum.answer.rcode.YXDOMAIN=1\nnum.answer.rcode.RCODE11=1\nnum.answer.rcode.nodata=2\n" +
		"num.rpz.action.rpz-nxdomain=3\n"
	// %g of a small median.
	stats = strings.Replace(stats, "total.recursion.time.median=0", "total.recursion.time.median=1.5e-05", 1)
	ubCheck(t, ubCtl+"stats_noreset", "two threads", stats)

	for cmd, outs := range ubSamples {
		for i, out := range outs {
			ubCheck(t, cmd, "sample "+string(rune('a'+i)), out)
		}
	}
}

// Every unbound and dhcpd format is for a command the registry has,
// and has a capture or a sample.
func TestUnboundFormatsCovered(t *testing.T) {
	inRepo(t)
	registry := map[string]bool{}
	for _, c := range Commands {
		registry[strings.Join(c.Argv, " ")] = true
	}
	captured := map[string]bool{ubCtl + "stats_noreset": true, ubCtl + "dump_cache": true}
	for cmd := range Formats {
		ours := strings.HasPrefix(cmd, "unbound-") || cmd == "file /var/db/dhcpd.leases" || cmd == "file /var/unbound/db/opf-dns.log"
		if !ours {
			continue
		}
		if !strings.HasPrefix(cmd, "file ") && !registry[cmd] {
			t.Errorf("format for %q, which the registry doesn't have", cmd)
		}
		if !captured[cmd] && len(ubSamples[cmd]) == 0 {
			t.Errorf("format for %q has nothing to check it against", cmd)
		}
	}
	for _, c := range Commands {
		line := strings.Join(c.Argv, " ")
		if (c.Program() == "unbound-control" || c.Program() == "unbound-anchor") && Formats[line].Command == "" {
			t.Errorf("no format for %q", line)
		}
	}
}

// What the formats must refuse: lines unbound or dhcpd don't print.
func TestUnboundFormatsRefuse(t *testing.T) {
	inRepo(t)
	stats := ubRead(t, "sysinfo/testdata/openbsd-7.9/unbound-control_stats_noreset.txt")
	for what, out := range map[string]string{
		"a renamed counter":          strings.Replace(stats, "total.num.cachehits=", "total.num.cache_hits=", 1),
		"a dropped counter":          strings.Replace(stats, "time.up=13.457272\n", "", 1),
		"a new counter":              stats + "num.query.quic=0\n",
		"an unknown RPZ action":      stats + "num.rpz.action.rpz-block=1\n",
		"no-override, never counted": stats + "num.rpz.action.rpz-no-override=1\n",
		"a counter with a new type":  strings.Replace(stats, "time.up=13.457272", "time.up=13", 1),
	} {
		if len(Formats[ubCtl+"stats_noreset"].Check(out)) == 0 {
			t.Errorf("stats_noreset with %s passed", what)
		}
	}
	log := Formats["file /var/unbound/db/opf-dns.log"]
	for _, l := range []string{
		// log-destaddr, which OPF doesn't set and doesn't read.
		"[1791387199] unbound[46658:0] reply: 192.168.1.23 example.com. A IN NOERROR 0.000000 1 56 on udp 192.168.1.1 53",
		"[1791387199] unbound[46658:0] reply: 192.168.1.23 example.com. A IN NOERROR 0.0 1 56",
		"[1791387199] unbound[46658:0] query: 192.168.1.23 example.com. A IN",
		"[1791387199] unbound[46658:0] info: rpz: applied [opf:own] a.example. rpz-block 192.168.1.23@1 a.example. A IN",
		"[1791387199] unbound[46658:0] info: rpz: applied [opf:own] broken",
		"Sep 29 10:00:00 gw unbound: [29114:0] info: start of service (unbound 1.26.1).",
	} {
		if len(log.Check(l)) == 0 {
			t.Errorf("unbound's log line %q passed", l)
		}
	}
	lf := Formats["file /var/db/dhcpd.leases"]
	for _, l := range []string{
		"\tends never;",                             // ISC dhcpd's, not OpenBSD's
		"\tstarts 1 2026/09/28 09:00:00;",           // OLD_DB_TIMEFMT, read but not written
		"\tclient-hostname \"with \\\"quote\\\"\";", // a space: dhcpd leaves the line out
		"\tclient-hostname \"a b\";",
		"\toption agent.circuit-id 1;",
	} {
		if len(lf.Check(l)) == 0 {
			t.Errorf("leases line %q passed", l)
		}
	}
}

// The unbound lines of the handwritten daemon log, through syslog
// (log_vmsg's syslog(pri, "[%d:%d] %s: %s")): each must be one unbound
// prints, but for the three written to test that OPF's parser rejects
// what unbound never writes.
func TestUnboundFormatsDaemonLog(t *testing.T) {
	inRepo(t)
	syslog := regexp.MustCompile(`^[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d \S+ unbound: (\[\d+:\d+\] .*)$`)
	unprintable := map[string]bool{
		"Sep 29 10:00:08 gw unbound: [29114:0] info: rpz: applied [opf:list:hagezi] broken":                                                          true,
		"Sep 29 10:00:09 gw unbound: [29114:0] info: rpz: applied [opf:list:hagezi] a.example. rpz-local-data 192.168.1.23@notaport a.example. A IN": true,
		"Sep 29 10:00:10 gw unbound: [29114:0] info: rpz: applied [opf:list:hagezi] a.example. made-up 192.168.1.23@5199 a.example. A IN":            true,
	}
	f := Formats["file /var/unbound/db/opf-dns.log"]
	n := 0
	for _, l := range strings.Split(strings.TrimSpace(ubRead(t, "sysinfo/testdata/handwritten/daemon_rpz.txt")), "\n") {
		m := syslog.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		n++
		problems := f.Check("[1] unbound" + m[1])
		if unprintable[l] && len(problems) == 0 {
			t.Errorf("%q passed, but unbound can't print it", l)
		} else if !unprintable[l] {
			for _, p := range problems {
				t.Errorf("daemon_rpz.txt: %s", strings.Replace(p, "line 1 ", "", 1))
			}
		}
	}
	if n < 10 {
		t.Errorf("only %d unbound lines in daemon_rpz.txt", n)
	}
}
