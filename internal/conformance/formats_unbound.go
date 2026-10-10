package conformance

import (
	"fmt"
	"regexp"
	"strings"
)

// The resolver's outputs and files: unbound-control's commands,
// unbound-anchor, unbound's own log file (DNS activity) and dhcpd's
// leases file.
//
// The unbound shapes follow unbound 1.26.1, which OpenBSD 7.9 runs
// once its errata are applied (the release's src.tar.gz has 1.24.2,
// whose outputs differ only in the two stats keys marked below and in
// writing the log's thread number in hex). OpenBSD builds it without
// dnscrypt, client subnet, cachedb, ipsecmod, dynlib, python or
// ngtcp2 (usr.sbin/unbound/Makefile.bsd-wrapper), so the keys and
// modules those add are left out: one appearing means the build
// changed. The functions named are in unbound's source unless a path
// says otherwise.

// ubCtl is the start of every unbound-control command line OPF runs.
const ubCtl = "unbound-control -c /var/unbound/etc/unbound.conf "

// Values as unbound prints them.
const (
	ubUL = `\d+`                        // %lu, %u
	ubG  = `\d+(?:\.\d+)?(?:e[-+]\d+)?` // %g of a count or time
	ubTV = `\d+\.\d{6}`                 // ARG_LL "d.%6.6d": seconds
	ubIP = `[0-9A-Fa-f:.]+`             // inet_ntop's v4 or v6
)

// ubTypesLow are the RR type names sldns_rr_descript has below 256
// (sldns/rrdef.c), the ones extended statistics count by name; the rest
// print as TYPE<n>.
var ubTypesLow = []string{
	"A", "NS", "MD", "MF", "CNAME", "SOA", "MB", "MG", "MR", "NULL", "WKS", "PTR", "HINFO", "MINFO", "MX", "TXT",
	"RP", "AFSDB", "X25", "ISDN", "RT", "NSAP", "NSAP-PTR", "SIG", "KEY", "PX", "GPOS", "AAAA", "LOC", "NXT", "EID",
	"NIMLOC", "SRV", "ATMA", "NAPTR", "KX", "CERT", "A6", "DNAME", "SINK", "OPT", "APL", "DS", "SSHFP", "IPSECKEY",
	"RRSIG", "NSEC", "DNSKEY", "DHCID", "NSEC3", "NSEC3PARAM", "TLSA", "SMIMEA", "HIP", "NINFO", "RKEY", "TALINK",
	"CDS", "CDNSKEY", "OPENPGPKEY", "CSYNC", "ZONEMD", "SVCB", "HTTPS", "SPF", "NID", "L32", "L64", "LP", "EUI48",
	"EUI64", "TKEY", "TSIG", "IXFR", "AXFR", "MAILB", "MAILA", "ANY",
}

// ubTypesHigh are its named types from 256 up, which logs and records
// show by name.
var ubTypesHigh = []string{"URI", "CAA", "AVC", "RESINFO", "TA", "DLV"}

var (
	ubType     = "(?:" + words(append(append([]string{}, ubTypesLow...), ubTypesHigh...)...) + `|TYPE\d+)`
	ubClass    = "(?:" + words("IN", "CH", "HS", "NONE", "ANY") + `|CLASS\d+)` // sldns_rr_classes
	ubRcodes   = []string{"NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMPL", "REFUSED", "YXDOMAIN", "YXRRSET", "NXRRSET", "NOTAUTH", "NOTZONE"}
	ubRcode    = "(?:" + words(ubRcodes...) + `|RCODE\d+)`                 // sldns_rcodes
	ubOpcodes  = []string{"QUERY", "IQUERY", "STATUS", "NOTIFY", "UPDATE"} // sldns_opcodes
	ubRPZNames = []string{                                                 // rpz_action_to_string
		"rpz-nxdomain", "rpz-nodata", "rpz-passthru", "rpz-drop", "rpz-tcp-only",
		"rpz-invalid", "rpz-local-data", "rpz-disabled", "rpz-cname-override", "rpz-no-override",
	}
	// ubDname is a name as dname_str writes it: letters, digits, -, _
	// and *, anything else as ?, & or # for a name too long or a label
	// too long.
	ubDname = `(?:\.|(?:[A-Za-z0-9_*?-]+\.)+|(?:[A-Za-z0-9_*?-]+\.)*[A-Za-z0-9_*?-]*[&#])`
	// ubPresName is a name in presentation format (sldns_wire2str_dname),
	// special characters escaped with a backslash.
	ubPresName = `(?:\.|(?:(?:[^\s.\\]|\\\d{3}|\\\S)+\.)+)`
	// ubRR is a record as packed_rr_to_string writes it: owner, TTL,
	// class, type and data, tab-separated; DNSKEY, RRSIG and NSEC3 data
	// end in a ;{...} comment.
	ubRR = ubPresName + `\t\d+\t` + ubClass + `\t` + ubType + `\t.*`
)

// ubSince126 are counters unbound 1.26 added, which 7.9 has from its
// errata (syspatch) but not as released (1.24.2): accepted, not needed,
// so the suite passes on a release either way.
var ubSince126 = map[string]bool{"num.queries_replyaddr_limit": true, "requestlist.current.replies": true}

// ubThreadStats are the counters print_stats writes for each thread
// (thread<n>.) and their sum (total.), and how each value looks.
var ubThreadStats = []struct{ key, val string }{
	{"num.queries", ubUL}, // OPF: total.num.queries (Queries)
	{"num.queries_ip_ratelimited", ubUL},
	{"num.queries_cookie_valid", ubUL},
	{"num.queries_cookie_client", ubUL},
	{"num.queries_cookie_invalid", ubUL},
	{"num.queries_discard_timeout", ubUL},
	{"num.queries_replyaddr_limit", ubUL}, // ubSince126
	{"num.queries_wait_limit", ubUL},
	{"num.cachehits", ubUL}, // OPF: total. (CacheHits)
	{"num.cachemiss", ubUL}, // OPF: total. (CacheMisses)
	{"num.prefetch", ubUL},  // OPF: total. (Prefetches)
	{"num.queries_timed_out", ubUL},
	{"query.queue_time_us.max", ubUL},
	{"num.expired", ubUL},
	{"num.recursivereplies", ubUL},
	{"num.dns_error_reports", ubUL},
	{"requestlist.avg", ubG},
	{"requestlist.max", ubUL},
	{"requestlist.overwritten", ubUL},
	{"requestlist.exceeded", ubUL},
	{"requestlist.current.all", ubUL},
	{"requestlist.current.user", ubUL},
	{"requestlist.current.replies", ubUL}, // ubSince126
	{"recursion.time.avg", ubTV},          // OPF: total. (RecursionAvg)
	{"recursion.time.median", ubG},        // OPF: total. (RecursionMedian)
	{"tcpusage", ubUL},
}

// ubFixedStats are the other lines stats prints every time, with
// extended-statistics: print_uptime, print_mem and the fixed part of
// print_ext. RCODEs 0 to 5 are always printed, the rest only when not
// zero (statistics-inhibit-zero, on by default).
var ubFixedStats = []struct{ key, val string }{
	{"time.now", ubTV},
	{"time.up", ubTV}, // OPF: Uptime
	{"time.elapsed", ubTV},
	// print_mem; OPF reads every mem.* into Memory.
	{"mem.cache.rrset", ubUL},
	{"mem.cache.message", ubUL},
	{"mem.mod.iterator", ubUL},
	{"mem.mod.validator", ubUL},
	{"mem.mod.respip", ubUL},
	{"mem.streamwait", ubUL},
	{"mem.http.query_buffer", ubUL},
	{"mem.http.response_buffer", ubUL},
	// print_ext
	{"num.query.tcp", ubUL},
	{"num.query.tcpout", ubUL},
	{"num.query.udpout", ubUL},
	{"num.query.tls", ubUL},
	{"num.query.tls.resume", ubUL},
	{"num.query.ipv6", ubUL},
	{"num.query.https", ubUL},
	{"num.query.flags.QR", ubUL},
	{"num.query.flags.AA", ubUL},
	{"num.query.flags.TC", ubUL},
	{"num.query.flags.RD", ubUL},
	{"num.query.flags.RA", ubUL},
	{"num.query.flags.Z", ubUL},
	{"num.query.flags.AD", ubUL},
	{"num.query.flags.CD", ubUL},
	{"num.query.edns.present", ubUL},
	{"num.query.edns.DO", ubUL},
	{"num.answer.rcode.NOERROR", ubUL}, // OPF: Answers
	{"num.answer.rcode.FORMERR", ubUL},
	{"num.answer.rcode.SERVFAIL", ubUL},
	{"num.answer.rcode.NXDOMAIN", ubUL},
	{"num.answer.rcode.NOTIMPL", ubUL},
	{"num.answer.rcode.REFUSED", ubUL},
	{"num.query.ratelimited", ubUL},
	{"num.answer.secure", ubUL}, // OPF: Secure
	{"num.answer.bogus", ubUL},  // OPF: Bogus
	{"num.rrset.bogus", ubUL},
	{"num.valops", ubUL},
	{"num.query.aggressive.NOERROR", ubUL},
	{"num.query.aggressive.NXDOMAIN", ubUL},
	{"unwanted.queries", ubUL},
	{"unwanted.replies", ubUL},
	{"msg.cache.count", ubUL},
	{"rrset.cache.count", ubUL},
	{"infra.cache.count", ubUL},
	{"key.cache.count", ubUL},
	{"msg.cache.max_collisions", ubUL},
	{"rrset.cache.max_collisions", ubUL},
	{"num.query.authzone.up", ubUL},
	{"num.query.authzone.down", ubUL},
}

// ubHistogram is print_hist's 40 buckets (timehist.c dosetup and
// timestwo): from 0 to 1 µs, doubling to 524288 µs, then 1 s doubling.
func ubHistogram() []string {
	var out []string
	sec, usec := 0, 0
	for i := 0; i < 40; i++ {
		lo := fmt.Sprintf("%06d.%06d", sec, usec)
		if sec == 0 && usec == 0 {
			usec = 1
		} else {
			sec, usec = sec*2, usec*2
			if usec == 1024*1024 {
				sec, usec = 1, 0
			}
		}
		out = append(out, fmt.Sprintf("histogram.%s.to.%06d.%06d", lo, sec, usec))
	}
	return out
}

// ubStats is stats_noreset with extended-statistics: yes (do_stats).
// Every line it always prints is its own kind and needed, so one
// renamed or dropped fails; the counted-by-name lines (types, classes,
// opcodes, uncommon RCODEs, RPZ actions) only appear when not zero.
//
// OPF (sysinfo.ParseUnboundStats) reads total.num.queries, cachehits,
// cachemiss, prefetch, recursion.time.avg and .median, time.up,
// num.answer.secure and .bogus, and every num.answer.rcode.*,
// num.rpz.action.*, num.query.type.* and mem.*.
func ubStats() Format {
	f := Format{Command: ubCtl + "stats_noreset", Fixture: "unbound-control_stats_noreset.txt"}
	for _, s := range ubThreadStats {
		k := regexp.QuoteMeta(s.key)
		f.Lines = append(f.Lines, L("thread."+s.key, `thread\d+\.`+k+"="+s.val), L("total."+s.key, `total\.`+k+"="+s.val))
		if !ubSince126[s.key] {
			f.Need = append(f.Need, "thread."+s.key, "total."+s.key)
		}
	}
	for _, s := range ubFixedStats {
		f.Lines = append(f.Lines, L(s.key, regexp.QuoteMeta(s.key)+"="+s.val))
		f.Need = append(f.Need, s.key)
	}
	for _, h := range ubHistogram() {
		f.Lines = append(f.Lines, L(h, regexp.QuoteMeta(h)+"="+ubUL))
		f.Need = append(f.Need, h)
	}
	var rpz []string
	for _, a := range ubRPZNames {
		if a != "rpz-no-override" { // print_ext skips it
			rpz = append(rpz, a)
		}
	}
	f.Lines = append(f.Lines,
		L("num.query.type", `num\.query\.type\.(?:`+words(ubTypesLow...)+`|TYPE\d+|other)=`+ubUL),
		L("num.query.class", `num\.query\.class\.(?:`+words("IN", "CH", "HS", "NONE", "ANY")+`|CLASS\d+|other)=`+ubUL),
		L("num.query.opcode", `num\.query\.opcode\.(?:`+words(ubOpcodes...)+`|OPCODE\d+)=`+ubUL),
		L("num.answer.rcode (not zero)", `num\.answer\.rcode\.(?:`+words(append(append([]string{}, ubRcodes[6:]...), "nodata")...)+`|RCODE\d+)=`+ubUL),
		L("num.rpz.action", `num\.rpz\.action\.`+words(rpz...)+"="+ubUL),
	)
	return f
}

// ubNotPrefix matches any text that doesn't start with p.
func ubNotPrefix(p string) string {
	var alts []string
	for i := 0; i < len(p); i++ {
		alts = append(alts, regexp.QuoteMeta(p[:i])+`(?:[^`+regexp.QuoteMeta(p[i:i+1])+`].*)?`)
	}
	return "(?:" + strings.Join(alts, "|") + ")"
}

// ubLogHead starts each line unbound writes to its logfile with
// log-time-ascii off (log_vmsg): [seconds] ident[pid:thread]. 1.24.2
// wrote the thread in hex; 1.26.1 in decimal.
const ubLogHead = `\[\d+\] unbound\[\d+:\d+\] `

// ubRPZApplied is what log_rpz_apply writes after "rpz: applied ":
// [rpz-log-name], the trigger (nothing for qname, else clientip, nsip
// or nsdname) with the zone's entry or address/prefix, the action, the
// client and its port (nothing, leaving two spaces, when the query has
// no client), and then log_nametypeclass's query name, type and class.
var ubRPZApplied = `rpz: applied (?:\[[^\s\]]+\] )?(?:(?:clientip |nsdname )?` + ubDname + `|(?:clientip|nsip) ` + ubIP + `/\d+) ` +
	words(ubRPZNames...) + ` (?:` + ubIP + `@\d+)? ` + ubDname + ` ` + ubType + ` ` + ubClass

// ubLogLines are the kinds of line in unbound's logfile as OPF
// configures it (pf.GenerateUnboundConf: use-syslog: no, logfile,
// log-replies, log-tag-queryreply, rpz-log with a name, val-log-level
// 2, verbosity left at 1, no log-queries, log-destaddr or
// log-time-ascii). OPF (sysinfo.ParseUnboundLogLine) reads the reply
// and rpz lines and passes the rest on as level and message; so
// those two must match exactly, and the rest may say anything.
func ubLogLines(head string) []Line {
	return []Line{
		// log_reply_info: client name type class rcode seconds cached size.
		L("reply", head+`reply: `+ubIP+` `+ubDname+` `+ubType+` `+ubClass+` `+ubRcode+` `+ubTV+` [01] \d+`),
		// log_reply_info for a FORMERR answer, which has no question.
		L("reply FORMERR", head+`reply: `+ubIP+` - - - FORMERR - - -`),
		L("rpz applied", head+`info: `+ubRPZApplied),
		L("info", head+`info: `+ubNotPrefix("rpz: applied ")),
		// log_err, log_warn, fatal_exit and verbose().
		L("other level", head+`(?:notice|warning|error|fatal error|debug): .*`),
	}
}

func ubControl() []Format {
	// What print_deleg_lookup (daemon/cachedump.c) prints.
	rrsetMeta := L("rrset", `;rrset(?: nsec_apex)? -?\d+ \d+ \d+ -?\d+ -?\d+`)
	lookup := Format{
		Command: ubCtl + "lookup *",
		Fixture: "unbound-control_lookup.txt",
		Lines: []Line{
			L("header", `The following name servers are used for lookup of `+ubDname),
			L("forwarding", `forwarding request:`),
			L("stub", `The noprime stub servers are used:|The stub is primed with servers:`),
			L("bogus rrset", `Address is BOGUS:`),
			rrsetMeta,
			L("record", ubRR),
			L("bad record", `BADRR`),
			L("delegation", `Delegation with \d+ names, of which \d+ can be examined to query further addresses\.`),
			L("addresses", `(?:It is BOGUS\. )?It provides \d+ IP addresses\.`),
			// print_dp_details: the address padded to 16, a tab, then
			// what the infra cache knows.
			L("server", ubIP+` *\t(?:Address is BOGUS\. )?(?:`+
				`expired, rto -?\d+ msec, tA \d+ tAAAA \d+ tother \d+\.`+
				`|not in infra cache\.`+
				`|(?:LAME )?(?:NoDNSSEC )?(?:AddrWasParentSide )?(?:NoAuthButRecursive )?rto -?\d+ msec, ttl -?\d+, ping -?\d+ var -?\d+ rtt -?\d+, tA \d+, tAAAA \d+, tother \d+(?:, probedelay \d+)?(?:, noEDNS(?: probed| assumed)\.|, EDNS \d+(?: probed| assumed)\.)?)`),
			L("useless", `cache delegation was useless \(no IP addresses\)`),
			L("roots", `no delegation from cache; goes to configured roots`),
			L("going up", `going up, lookup `+ubDname),
		},
		Need: []string{"header"},
	}
	// dump_cache: the rrset cache, then the message cache, then EOF.
	// OPF (appliance.cacheLines) reads records' owner and type, and the
	// msg lines' name, class, type and TTL (the seventh field).
	dump := Format{
		Command: ubCtl + "dump_cache",
		Fixture: "unbound-control_dump_cache.txt",
		Lines: []Line{
			L("START_RRSET_CACHE", `START_RRSET_CACHE`),
			rrsetMeta,
			L("record", ubRR),
			L("bad record", `BADRR`),
			L("END_RRSET_CACHE", `END_RRSET_CACHE`),
			L("START_MSG_CACHE", `START_MSG_CACHE`),
			// dump_msg: name class type flags qdcount ttl security an ns
			// ar reason_bogus and its text, empty but for a space.
			L("msg", `msg `+ubPresName+` `+ubClass+` `+ubType+` \d+ \d+ \d+ -?\d+ \d+ \d+ \d+ -?\d+ .*`),
			// dump_msg_ref: an rrset of the message.
			L("msg rrset", ubPresName+` `+ubClass+` `+ubType+` \d+`),
			L("bad msg rrset", `BADREF`),
			L("END_MSG_CACHE", `END_MSG_CACHE`),
			L("EOF", `EOF`),
		},
		Need: []string{"START_RRSET_CACHE", "END_RRSET_CACHE", "START_MSG_CACHE", "END_MSG_CACHE", "EOF"},
	}
	// do_list_local_zones: name and local_zone_type2str.
	zones := Format{
		Command: ubCtl + "list_local_zones",
		Fixture: "unbound-control_list_local_zones.txt",
		Lines: []Line{L("zone", ubDname+` `+words(
			"unset", "deny", "refuse", "redirect", "transparent", "typetransparent", "static", "nodefault",
			"inform", "inform_deny", "inform_redirect", "always_transparent", "block_a", "block_aaaa",
			"block_a_wdata", "block_aaaa_wdata", "always_refuse", "always_nxdomain", "always_nodata",
			"always_deny", "always_null", "noview", "truncate", "invalid", "badtyped"))},
		Need: []string{"zone"},
	}
	// do_list_local_data prints "%s\n" of a record that already ends in
	// a newline, so an empty line follows each. OPF
	// (leases.parseLocalData) reads the A records' name and address and
	// skips the rest.
	data := Format{
		Command: ubCtl + "list_local_data",
		Fixture: "unbound-control_list_local_data.txt",
		Lines:   []Line{L("record", ubRR), L("empty", ``), L("bad record", `BADRR`)},
		Need:    []string{"record", "empty"},
	}
	ok := []Line{L("ok", `ok`)} // send_ok
	// do_flush_zone, do_flush_bogus, do_flush_negative.
	removed := []Line{L("removed", `ok removed \d+ rrsets, \d+ messages and \d+ key entries`)}
	// do_auth_zone_reload: ok, after a line when the zone has a ZONEMD
	// that verified.
	reload := []Line{L("ok", `ok`), L("zonemd", `\S+: ZONEMD verification successful`)}
	return []Format{
		lookup, dump, zones, data,
		{
			// do_status.
			Command: ubCtl + "status",
			Fixture: "unbound-control_status.txt",
			Lines: []Line{
				L("version", `version: \d+\.\d+\.\d+`),
				L("verbosity", `verbosity: \d+`),
				L("threads", `threads: \d+`),
				// module_list_avail, as OpenBSD builds it.
				L("modules", `modules: \d+ \[(?: `+words("dns64", "respip", "validator", "iterator")+`)* \]`),
				L("uptime", `uptime: \d+ seconds`),
				// control(namedpipe): OPF's control-interface is a socket path.
				L("options", `options:(?: reuseport)?(?: control(?:\(ssl\))?(?:\(namedpipe\))?)?`),
				L("running", `unbound \(pid \d+\) is running\.\.\.`),
			},
			Need: []string{"version", "verbosity", "threads", "modules", "uptime", "options", "running"},
		},
		{Command: ubCtl + "flush *", Fixture: "unbound-control_flush.txt", Lines: ok, Need: []string{"ok"}},
		{Command: ubCtl + "flush_zone *", Fixture: "unbound-control_flush_zone.txt", Lines: removed, Need: []string{"removed"}},
		{Command: ubCtl + "flush_bogus", Fixture: "unbound-control_flush_bogus.txt", Lines: removed, Need: []string{"removed"}},
		{Command: ubCtl + "flush_negative", Fixture: "unbound-control_flush_negative.txt", Lines: removed, Need: []string{"removed"}},
		// do_data_add and do_data_remove; leases.Unbound.expectOK wants
		// exactly "ok".
		{Command: ubCtl + "local_data * * IN A *", Fixture: "unbound-control_local_data_A.txt", Lines: ok, Need: []string{"ok"}},
		{Command: ubCtl + "local_data * * IN PTR *", Fixture: "unbound-control_local_data_PTR.txt", Lines: ok, Need: []string{"ok"}},
		{Command: ubCtl + "local_data_remove *", Fixture: "unbound-control_local_data_remove.txt", Lines: ok, Need: []string{"ok"}},
		{Command: ubCtl + "auth_zone_reload *", Fixture: "unbound-control_auth_zone_reload.txt", Lines: reload, Need: []string{"ok"}},
		{Command: ubCtl + "auth_zone_reload opf-own.", Fixture: "unbound-control_auth_zone_reload_opf-own.txt", Lines: reload, Need: []string{"ok"}},
	}
}

// ubAnchor is unbound-anchor -v -a <root.key> (smallapp/unbound-anchor.c
// at verbosity 1, with OpenBSD's unveil and pledge), on stdout and
// stderr together as OPF runs it. OPF only looks at whether the file is
// there afterwards, and logs the first line when it isn't.
func ubAnchor() Format {
	return Format{
		Command: "unbound-anchor -v -a *",
		Fixture: "unbound-anchor_-v_-a.txt",
		Lines: []Line{
			// try_read_anchor.
			L("anchor file", `\S+ (?:does not exist|is empty|has content)`),
			L("anchor unreadable", `/\S+: .+|error: cannot access the file`),
			L("revoked", `\S+ : the trust point is revoked|and the zone is considered unsigned\.|if you wish to re-enable, delete the file`),
			L("builtin write", `could not (?:complete )?write builtin anchor, to file \S+: .*`),
			// probe_date_allows_certupdate and what it reads.
			L("probe", `RFC5011-state has ADDPEND keys`+
				`|last successful probe: [A-Z][a-z]{2} [A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d \d{4}`+
				`|failed to parse last_success probe time`+
				`|no last_success probe time in anchor file`+
				`|the date is before the root was first signed, please correct the clock`+
				`|the last successful probe is in the future, clock was modified`+
				`|the last successful probe was more than 30 days ago`+
				`|the last successful probe is recent`),
			// create_unbound_context, add_5011_probe_root, prime_root_key.
			L("context", `ctx targetfetchpolicy: .*|error: could not create unbound resolver context|add 5011 probe to ctx: .*|resolve DNSKEY: .*|out of memory`),
			// do_certupdate: the certificate, the server, the files.
			L("certupdate", `using builtin certificate|have \d+ trusted certificates`+
				`|(?:error: )?resolve \S+ (?:A|AAAA): .*|\S+ has no IP addresses I can use|server address is \S+`+
				`|(?:resolved server address|connect to) (?:\S+|\(inet_ntop error\))|(?:socket|bind|connect): .*`+
				`|could not fetch \S+|fetched \S+ \(\d+ bytes\)|SSL handshake failed|bad status .*`+
				`|XML was parsed successfully, \d+ keys|error: xml cannot be parsed|xml not for the right zone`+
				`|signer \d+: Subject: .*|signer \d+: cert has no subject name|did not check commonName of signer`+
				`|removed cert with (?:wrong|no) emailaddress|no signers in pkcs7 signature`+
				`|the PKCS7 signature (?:verified|failed)|could not parse p7s signature file`),
			// do_root_update_work's outcome.
			L("outcome", `success: the anchor is ok|success: the anchor has been updated using the cert|fail: the anchor is NOT ok and could not be fixed`),
			// libunbound's log on stderr (log_vmsg), and OpenBSD's err().
			L("libunbound log", `\[\d+\] (?:libunbound|unbound-anchor)\[\d+:\d+\] (?:notice|info|warning|error|fatal error|debug): .*`),
			L("err", `unbound-anchor: (?:unveil|pledge).*`),
		},
		Need: []string{"anchor file", "outcome"},
	}
}

// ubLeases is /var/db/dhcpd.leases as dhcpd writes it (usr.sbin/dhcpd
// db.c write_lease): each lease a block, the optional statements each
// starting a new line ("\n\t..."), so a lease with nothing after ends
// leaves an empty line, as does one with a uid and no hardware.
//
// client-hostname and hostname are written with "%s" between quotes,
// and only when every byte is from 33 to 126: no spaces, but a '"', a
// '\', ';', '{', '}' and '#' are written as they are, unescaped. OPF
// (leases.Parse) reads them through a lexer that takes '\' as an escape.
func ubLeases() Format {
	date := `[0-6] \d{4}/\d\d/\d\d \d\d:\d\d:\d\d UTC` // DB_TIMEFMT
	return Format{
		Command: "file /var/db/dhcpd.leases",
		Fixture: "dhcpd.leases",
		Lines: []Line{
			L("lease", `lease \d{1,3}(?:\.\d{1,3}){3} \{`), // piaddr
			L("starts", `\tstarts `+date+`;`),
			L("ends", `\tends `+date+`;`),
			// hardware_types and print_hw_addr.
			L("hardware", `\thardware (?:ethernet|token-ring|fddi|ipsec-tunnel|unknown-\d+) (?:[0-9a-f]{2}(?::[0-9a-f]{2})*|<null>);`),
			L("uid", `\tuid [0-9a-f]{2}(?::[0-9a-f]{2})*;`),
			L("dynamic-bootp", `\tdynamic-bootp;`),
			L("abandoned", `\tabandoned;`),
			L("client-hostname", `\tclient-hostname "[!-~]*";`),
			L("hostname", `\thostname "[!-~]*";`),
			L("end of lease", `\}`),
			L("empty", ``),
		},
	}
}

func init() {
	addFormats(ubStats())
	addFormats(ubControl()...)
	addFormats(ubAnchor(), ubLeases(), Format{
		Command: "file /var/unbound/db/opf-dns.log",
		Fixture: "opf-dns.log",
		Lines:   ubLogLines(ubLogHead),
	})
}
