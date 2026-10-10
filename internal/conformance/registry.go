package conformance

import "strings"

// Kind says what running a command does to the system.
type Kind int

const (
	// Read only reads the system.
	Read Kind = iota
	// Change changes the system.
	Change
	// Validate checks a file without using it.
	Validate
)

// A Command is a command line OPF runs. Argv is a template: a literal
// word, "*" for one argument OPF chooses at run time (or a script, for
// sh -c), or "..." for any number of them, which ends the template. A
// word in brackets, such as "[-v]", may be left out.
type Command struct {
	Argv []string
	Kind Kind
	// Where names the code that runs it.
	Where string
	// Test is the suite's test, on OpenBSD, that runs it for real and
	// checks what OPF assumes about it.
	Test string
}

// A Tool is a program whose command line OPF builds up word by word
// (the diagnostics tools). Words lists every literal word OPF may pass
// to it; the rest are values OPF checks itself (addresses, counts).
type Tool struct {
	Program string
	Words   []string
	Where   string
	Test    string
}

// cmd makes a Command from a command line written as one string.
func cmd(kind Kind, where, test, line string) Command {
	return Command{Argv: strings.Fields(line), Kind: kind, Where: where, Test: test}
}

// Program is the program a command runs.
func (c Command) Program() string { return c.Argv[0] }

// Matches says whether a command line found in OPF's source fits the
// template. In found, "*" is a value OPF chooses and "..." any number of
// them; a "*" only fits a "*" in the template, and a literal word fits
// itself or a "*".
func (c Command) Matches(found []string) bool {
	return match(c.Argv, found)
}

func match(tmpl, found []string) bool {
	if len(tmpl) == 0 {
		return len(found) == 0
	}
	t := tmpl[0]
	if t == "..." {
		return true
	}
	if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
		inner := t[1 : len(t)-1]
		if match(tmpl[1:], found) {
			return true
		}
		return match(append([]string{inner}, tmpl[1:]...), found)
	}
	if len(found) == 0 {
		return false
	}
	f := found[0]
	switch {
	case f == "...":
		return false
	case f == "*":
		if t != "*" {
			return false
		}
	case t == "{}" || t == "{*}":
		// A registry file's placeholder: the path, or the part of a
		// pattern's name, it runs with.
	case t != "*" && t != f:
		return false
	}
	return match(tmpl[1:], found[1:])
}

// Commands lists every command line OPF runs outside a shell script.
// Where is the code that runs it; Test is the suite's test that runs it
// on OpenBSD.
var Commands = []Command{
	// Status: the dashboard, graphs and storage (internal/appliance).
	cmd(Read, "appliance status", "TestStatusReads", "sysctl kern.osrelease"),
	cmd(Read, "appliance status", "TestStatusReads", "sysctl kern.hostname kern.osrelease kern.version kern.boottime hw.machine hw.model hw.vendor hw.product hw.ncpuonline hw.physmem vm.loadavg"),
	cmd(Read, "appliance status", "TestStatusReads", "sysctl kern.cp_time"),
	cmd(Read, "appliance collect", "TestStatusReads", "sysctl kern.cp_time vm.loadavg hw.physmem"),
	cmd(Read, "appliance status", "TestStatusReads", "sysctl hw.sensors"),
	cmd(Read, "appliance status", "TestStatusReads", "vmstat -s"),
	cmd(Read, "appliance status", "TestStatusReads", "swapctl -lk"),
	cmd(Read, "appliance status, storage", "TestStatusReads", "df -kPl"),
	cmd(Read, "appliance status, collect", "TestStatusReads", "ntpctl -s all"),
	cmd(Read, "appliance status, systemdns", "TestStatusReads", "cat /etc/resolv.conf"),
	cmd(Read, "appliance status, collect", "TestStatusReads", "ifconfig -A"),
	cmd(Read, "appliance status, collect", "TestStatusReads", "netstat -ibn"),
	cmd(Read, "appliance status, collect", "TestStatusReads", "netstat -in"),
	cmd(Read, "appliance gateways", "TestStatusReads", "ping -n -q -c 3 -i 0.2 -w 1 -- *"),
	cmd(Read, "appliance gateways", "TestStatusReads", "ping6 -n -q -c 3 -i 0.2 -w 1 -- *"),
	cmd(Read, "appliance storage, dnsstats", "TestStatusReads", "ps -A -o rss=,comm="),
	cmd(Read, "appliance storage", "TestStatusReads", "cat /etc/newsyslog.conf"),
	cmd(Read, "appliance storage", "TestStatusReads", "ls -ln ..."),
	cmd(Read, "appliance syslog", "TestStatusReads", "dmesg"),
	cmd(Read, "appliance syslog, dnsstats", "TestStatusReads", "tail -n * *"),
	cmd(Read, "appliance arp, eventwatch", "TestNetworkReads", "arp -an"),
	cmd(Read, "appliance routes", "TestNetworkReads", "netstat -rnf inet"),
	cmd(Read, "appliance routes", "TestNetworkReads", "netstat -rnf inet6"),
	cmd(Read, "appliance takeover", "TestNetworkReads", "ifconfig egress"),
	cmd(Change, "appliance systemdns", "TestSystemDNS", "route nameserver lo0 ..."),

	// pf (internal/appliance).
	cmd(Read, "appliance pfstatus, collect, storage", "TestPfReads", "pfctl -v -s info"),
	cmd(Read, "appliance pfstatus, storage", "TestPfReads", "pfctl -s memory"),
	cmd(Read, "appliance pfstatus, storage", "TestPfReads", "pfctl -vvs Tables"),
	cmd(Read, "appliance pfstatus", "TestPfReads", "pfctl -s timeouts"),
	cmd(Read, "appliance pfstatus", "TestPfReads", "pfctl -vv -s Interfaces"),
	cmd(Read, "appliance pfstatus", "TestPfReads", "pfctl -vv -s states"),
	cmd(Read, "appliance pfstatus, collect", "TestPfReads", "pfctl -vv -s rules"),
	cmd(Read, "appliance traffic", "TestPfReads", "pfctl -s labels"),
	cmd(Read, "appliance traffic", "TestPfReads", "pfctl -s Tables"),
	cmd(Read, "appliance pfstatus (firewall log)", "TestPfReads", "tcpdump -n -e -ttt -r /var/log/pflog"),
	cmd(Read, "appliance tablecontents", "TestPfTables", "pfctl -t * -T show"),
	cmd(Read, "appliance tablecontents", "TestPfTables", "pfctl -t * -T show -v"),
	cmd(Read, "appliance traffic", "TestPfTables", "pfctl -t opf_hosts -T show -v"),
	cmd(Change, "appliance tablecontents (add, delete, flush)", "TestPfTables", "pfctl -t * -T * ..."),
	cmd(Change, "appliance traffic (add, delete)", "TestPfTables", "pfctl -t opf_hosts -T * ..."),
	cmd(Change, "appliance traffic", "TestPfTables", "pfctl -t opf_hosts -T kill"),
	cmd(Change, "appliance tables", "TestPfTables", "pfctl -t * -T replace -f *"),
	cmd(Change, "appliance expiry", "TestPfTables", "pfctl -t * -T expire *"),
	cmd(Change, "appliance pfstatus (close a connection)", "TestPfKillState", "pfctl -k id -k *"),
	cmd(Read, "appliance takeover", "TestImportCompare", "pfctl -nvf *"),

	// unbound (internal/appliance, internal/leases).
	cmd(Read, "appliance collect, dnsstats", "TestUnbound", "unbound-control -c /var/unbound/etc/unbound.conf stats_noreset"),
	cmd(Read, "appliance dnsstats", "TestUnbound", "unbound-control -c /var/unbound/etc/unbound.conf status"),
	cmd(Change, "appliance dnslists", "TestUnbound", "unbound-control -c /var/unbound/etc/unbound.conf auth_zone_reload *"),
	cmd(Read, "appliance dnstools", "TestUnbound", "unbound-control -c /var/unbound/etc/unbound.conf lookup *"),
	cmd(Read, "appliance dnstools", "TestUnbound", "unbound-control -c /var/unbound/etc/unbound.conf dump_cache"),
	cmd(Read, "appliance dnstools", "TestUnbound", "unbound-control -c /var/unbound/etc/unbound.conf list_local_zones"),
	cmd(Read, "appliance dnstools, leases", "TestUnbound", "unbound-control -c /var/unbound/etc/unbound.conf list_local_data"),
	cmd(Change, "appliance dnstools", "TestUnbound", "unbound-control -c /var/unbound/etc/unbound.conf flush *"),
	cmd(Change, "appliance dnstools", "TestUnbound", "unbound-control -c /var/unbound/etc/unbound.conf flush_zone *"),
	cmd(Change, "appliance dnstools", "TestUnbound", "unbound-control -c /var/unbound/etc/unbound.conf flush_bogus"),
	cmd(Change, "appliance dnstools", "TestUnbound", "unbound-control -c /var/unbound/etc/unbound.conf flush_negative"),
	cmd(Change, "leases", "TestUnbound", "unbound-control -c /var/unbound/etc/unbound.conf local_data * * IN A *"),
	cmd(Change, "leases", "TestUnbound", "unbound-control -c /var/unbound/etc/unbound.conf local_data * * IN PTR *"),
	cmd(Change, "leases", "TestUnbound", "unbound-control -c /var/unbound/etc/unbound.conf local_data_remove *"),
	cmd(Change, "appliance tables (DNSSEC)", "TestUnbound", "unbound-anchor -v -a *"),

	// Services (internal/appliance, internal/config).
	cmd(Read, "appliance services", "TestServices", "rcctl ls on"),
	cmd(Read, "appliance services", "TestServices", "rcctl ls started"),
	cmd(Read, "appliance services", "TestServices", "rcctl ls all"),
	cmd(Read, "appliance services, eventwatch; config commit", "TestServices", "rcctl check *"),
	cmd(Read, "appliance services", "TestServices", "rcctl get *"),
	cmd(Change, "config commit (reload, restart); appliance services (start, stop, restart, reload)", "TestServices", "rcctl * *"),
	cmd(Read, "cmd/opf (leaving read-only mode)", "TestServices", "rcctl get opf flags"),
	cmd(Read, "appliance hostlookup (a WireGuard peer's name, as it's entered)", "TestSystemDNS", "getent hosts *"),
	cmd(Change, "cmd/opf (leaving read-only mode)", "TestServices", "rcctl set opf flags ..."),

	// Accounts and sign-in (internal/auth, internal/appliance authpf).
	cmd(Change, "auth admin", "TestAccounts", "groupadd -g * *"),
	cmd(Change, "auth admin", "TestAccounts", "groupdel *"),
	cmd(Change, "auth admin (with -G groups, then the name)", "TestAccounts", "useradd -m -c * -s * -L default -p * ..."),
	cmd(Change, "auth admin", "TestAccounts", "usermod -S * *"),
	cmd(Change, "auth admin", "TestAccounts", "usermod -p * *"),
	cmd(Change, "auth admin", "TestAccounts", "usermod -Z *"),
	cmd(Change, "auth admin", "TestAccounts", "usermod -U *"),
	cmd(Change, "auth admin", "TestAccounts", "userdel -r *"),
	cmd(Read, "auth admin", "TestAccounts", "encrypt"),
	cmd(Change, "cmd/opf (audit log)", "TestAccounts", "logger -p auth.notice -t opf"),
	cmd(Read, "appliance authpf", "TestAuthpf", "ps -axww -o pid,lstart,command"),
	cmd(Read, "appliance authpf", "TestAuthpf", "pfctl -a authpf -s Anchors"),
	cmd(Change, "appliance authpf (end a session)", "TestAuthpf", "kill -TERM *"),

	// Files: each file's check and how it's put into use (internal/config).
	cmd(Change, "config registry: pf.conf", "TestApply", "pfctl -f {}"),
	cmd(Validate, "config registry: dhcpd.conf", "TestValidators", "dhcpd -n -c {}"),
	cmd(Validate, "config registry: ntpd.conf", "TestValidators", "ntpd -n -f {}"),
	cmd(Validate, "config registry: httpd.conf", "TestValidators", "httpd -n -f {}"),
	cmd(Validate, "config registry: sshd_config", "TestValidators", "sshd -t -f {}"),
	cmd(Validate, "config registry: dhcpleased.conf", "TestValidators", "dhcpleased -n -f {}"),
	cmd(Validate, "config registry: rc.conf.local", "TestValidators", "sh -n {}"),
	cmd(Validate, "config registry: authpf rules", "TestValidators", "pfctl -n -a authpf/opfcheck -D user_ip=192.0.2.1 -D user_id=opfcheck -f {}"),
	cmd(Validate, "config registry: unbound.conf (UnboundCheck)", "TestValidators", "sh -c * sh {} {staged} {root}"),
	cmd(Change, "config registry: own RPZ zone", "TestApply", "unbound-control -c /var/unbound/etc/unbound.conf auth_zone_reload opf-own."),
	cmd(Change, "config registry: myname", "TestApply", "sh -c * sh {}"),
	cmd(Change, "config registry: hostname.if (HostnameApply), removal", "TestApply", "sh -c * sh {*}"),
	{Argv: []string{"sh", "-c", "pkill -HUP -x dhcpleased || true"}, Kind: Change, Where: "config registry: dhcpleased.conf", Test: "TestApply"},
	cmd(Read, "config store (diffs)", "TestDiff", "diff -u -L * -L * * *"),

	// Downloads and patches.
	cmd(Read, "appliance fetch (URL lists, blocklists)", "TestInternet", "ftp -V -o - -- *"),
	cmd(Read, "appliance updates", "TestInternet", "syspatch -c"),
}

// Tools lists the programs whose command lines OPF builds word by word:
// the diagnostics tools (internal/diag).
var Tools = []Tool{
	{"ping", []string{"-c", "-s", "-w", "2", "-D", "--"}, "diag tools", "TestTools"},
	{"ping6", []string{"-c", "-s", "-w", "2", "-D", "--"}, "diag tools", "TestTools"}, // -D: the scan sees it, diag refuses it for IPv6
	{"traceroute", []string{"-I", "-A", "-n", "-m", "-q", "3", "-w", "2", "--"}, "diag tools", "TestTools"},
	{"traceroute6", []string{"-I", "-A", "-n", "-m", "-q", "3", "-w", "2", "--"}, "diag tools", "TestTools"},
	{"dig", []string{"@127.0.0.1", "-x", "-q", "-t", "+time=3", "+tries=2", "+trace", "+dnssec"}, "diag tools", "TestTools"},
	{"nc", []string{"-4", "-6", "-z", "-v", "-w", "5", "-u", "--"}, "diag tools", "TestTools"},
}

// NotCommands are []string literals that start with a program's name
// but aren't whole command lines.
var NotCommands = [][]string{
	// The start of the unbound-control wrappers' command lines, whose
	// calls the scan reads one by one.
	{"unbound-control", "-c", "/var/unbound/etc/unbound.conf", "..."},
	{"unbound-control", "-c", "*", "..."},
	// config.RcServices: the daemons rc.conf.local manages.
	{"dhcpd", "unbound"},
	// sysinfo.ParseResolvConf: resolv.conf's default lookup order.
	{"file", "bind"},
}
