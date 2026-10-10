package conformance

// What OPF takes from OpenBSD besides commands: files and directories,
// accounts, interface kinds, limits from the headers, and names from the
// source. The suite checks each against the release (TestBase,
// TestHeaders, TestSource).

import "github.com/dantecatalfamo/OPF/internal/pf"

// A Path is a file or directory OPF relies on finding on a stock
// install. Kind is "file", "dir" or "exec".
type Path struct {
	Path, Kind, Why string
}

// Paths lists what OPF expects a stock install to have. What OPF makes
// itself (/var/opf, its own files) isn't here.
var Paths = []Path{
	{"/etc/netstart", "file", "hostname.if changes are applied with sh /etc/netstart <if> (it isn't executable)"},
	{"/etc/rc.conf", "file", "the defaults rc.conf.local overrides (dhcpd_flags=NO, unbound_flags=NO)"},
	{"/etc/rc.d/dhcpd", "exec", "rcctl manages dhcpd"},
	{"/etc/rc.d/unbound", "exec", "rcctl manages unbound; it runs unbound-anchor first"},
	{"/etc/rc.d/ntpd", "exec", "rcctl manages ntpd"},
	{"/etc/rc.d/sshd", "exec", "sshd is reloaded for sign-in access"},
	{"/etc/rc.d/httpd", "exec", "httpd.conf is checked and httpd reloaded"},
	{"/etc/rc.d/dhcpleased", "exec", "dhcpleased is sent SIGHUP"},
	{"/etc/rc.d/pflogd", "exec", "the firewall log"},
	{"/usr/libexec/auth/login_passwd", "exec", "sign-in checks passwords through login_<style> (bsdauth)"},
	{"/usr/sbin/authpf", "exec", "sign-in access users' shell"},
	{"/sbin/nologin", "exec", "accounts that only sign in to OPF"},
	{"/bin/ksh", "exec", "accounts that may also log in over SSH"},
	{"/var/empty", "dir", "authpf users' home; the web process's unveil"},
	{"/etc/ssl/cert.pem", "file", "the webhook sender verifies TLS against it"},
	{"/etc/examples/pf.conf", "file", "stock pf.conf, the take-over's starting point"},
	{"/etc/pf.os", "file", "the default for set fingerprints"},
	{"/etc/newsyslog.conf", "file", "how big each log may grow"},
	{"/etc/login.conf", "file", "login classes and styles"},
	{"/etc/master.passwd", "file", "accounts (read directly)"},
	{"/etc/group", "file", "group membership (read directly)"},
	{"/etc/passwd", "file", "authpf accounts (read directly)"},
	{"/etc/shells", "file", "useradd only takes a listed shell"},
	{"/var/unbound/etc", "dir", "unbound.conf"},
	{"/var/unbound/db", "dir", "zones, root.key and unbound's own log, writable by _unbound"},
	{"/var/db", "dir", "dhcpd.leases"},
	{"/var/log/messages", "file", "System logs"},
	{"/var/log/daemon", "file", "System logs, blocked names"},
	{"/var/log/authlog", "file", "System logs"},
	{"/var/log/maillog", "file", "System logs"},
	{"/var/log/pflog", "file", "the firewall log, once pflogd runs"},
	{"/etc/signify", "dir", "syspatch's keys"},
}

// Accounts OPF uses that the base system makes.
var Accounts = []struct {
	User, Group string
	UID         int // -1 for any
	Why         string
}{
	{"_unbound", "_unbound", -1, "unbound writes its logfile and zones in /var/unbound/db as _unbound"},
	{"_dhcp", "_dhcp", -1, "dhcpd runs as it"},
	{"nobody", "", 32767, "admin.go leaves uid 32767 out of the accounts it lists"},
	{"", "authpf", -1, "sign-in access users are in the authpf group (useradd -G authpf)"},
	{"root", "wheel", 0, ""},
}

// LoginClasses are login.conf classes OPF names (useradd -L).
var LoginClasses = []string{"default", "daemon"}

// Cloners are the interface kinds OPF makes, which ifconfig -C must
// list.
var Cloners = []string{"vlan", "svlan", "wg", "carp", "trunk", "aggr", "pflog", "enc", "lo", "vether", "pair", "pflow"}

// A Constant is a limit OPF hard-codes from a header in /usr/include.
type Constant struct {
	Header, Name string
	Value        int
	Why          string
}

// Constants are checked against /usr/include (the comp set) on the
// release.
var Constants = []Constant{
	{"net/if.h", "IFNAMSIZ", 16, "device names are at most 15 characters (pf validate)"},
	{"net/pfvar.h", "PF_TABLE_NAME_SIZE", 32, "table names are at most 31 characters (tableRE)"},
	{"net/pfvar.h", "PF_TAG_NAME_SIZE", 64, "tags are at most 63 characters (tagRE)"},
	{"net/pfvar.h", "PF_RULE_LABEL_SIZE", 64, "labels are at most 63 bytes (generate.go)"},
	{"net/pfvar.h", "PF_ANCHOR_NAME_SIZE", 64, "authpf/<user>(<pid>) anchors"},
	{"sys/socket.h", "RT_TABLEID_MAX", 255, "rtable is 0 to 255; ways out use 200 plus their wg number"},
	{"resolv.h", "MAXNS", 3, "the system asks at most three name servers"},
	{"sys/param.h", "MAXHOSTNAMELEN", 256, "host names"},
	{"limits.h", "LOGIN_NAME_MAX", 32, "login names are at most 31 characters"},
	{"net/if_pflow.h", "PFLOW_PROTO_5", pf.FlowNetFlow5, "a flow export's pflowproto (pf.FlowExport)"},
	{"net/if_pflow.h", "PFLOW_PROTO_10", pf.FlowIPFIX, "a flow export's pflowproto (pf.FlowExport)"},
	{"net/if_pflow.h", "PFLOW_IPFIX_TMPL_SET_ID", 2, "TestFlowExport tells templates from records"},
	{"net/if_pflow.h", "PFLOW_IPFIX_TMPL_IPV4_ID", 256, "TestFlowExport finds IPv4 records"},
}

// SourceDirs are the release source directories the suite reads names
// from; scripts/conformance/vm.sh copies them into the guest.
var SourceDirs = []string{"sbin/pfctl", "sys/net", "usr.sbin/ntpd", "usr.sbin/dhcpd", "sbin/ifconfig"}
