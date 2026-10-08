package pf

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// The base system's services (rc.d(8), rcctl(8)): what each is, and the
// boot settings OPF keeps for those the admin sets (System.Services).
// Those are written into rc.conf.local as lines of their own, each
// ending in rcServiceMark, so a merge finds them wherever they are:
// rcctl sorts the whole file when it edits it, and moves OPF's block.

// ServiceKind is a daemon (started and stopped) or a boot setting (a
// task rc runs at boot, on or off).
type ServiceKind string

const (
	ServiceDaemon ServiceKind = "daemon"
	ServiceBoot   ServiceKind = "boot"
)

// ServiceInfo is what OPF knows of a base service.
type ServiceInfo struct {
	Name        string      `json:"name"`
	Kind        ServiceKind `json:"kind"`
	Category    string      `json:"category"`
	Description string      `json:"description"`
	// ManagedAt is the page that sets it up, for a service OPF manages
	// itself; its boot settings can't be set here.
	ManagedAt string `json:"managedAt,omitempty"`
}

// The categories, in the order a page shows them.
var ServiceCategories = []string{"Network", "Firewall and VPN", "Routing", "Name and time", "Web and mail", "Monitoring and logging", "System", "File sharing", "Rarely needed"}

var baseServices = []ServiceInfo{
	// Network
	{Name: "dhcpd", Kind: ServiceDaemon, Category: "Network", Description: "DHCP server: hands out addresses on the inside networks", ManagedAt: "/services/dhcp"},
	{Name: "dhcpleased", Kind: ServiceDaemon, Category: "Network", Description: "DHCP client: gets the WAN's address (and others set to DHCP)"},
	{Name: "dhcp6leased", Kind: ServiceDaemon, Category: "Network", Description: "DHCPv6 client: asks the ISP for an IPv6 prefix to delegate"},
	{Name: "slaacd", Kind: ServiceDaemon, Category: "Network", Description: "IPv6 autoconfiguration: addresses from router advertisements"},
	{Name: "rad", Kind: ServiceDaemon, Category: "Network", Description: "IPv6 router advertisements for the inside networks"},
	{Name: "resolvd", Kind: ServiceDaemon, Category: "Network", Description: "Writes /etc/resolv.conf from the DNS servers interfaces learn"},
	{Name: "dhcrelay", Kind: ServiceDaemon, Category: "Network", Description: "DHCP relay: passes a network's requests to a server elsewhere"},
	{Name: "dhcrelay6", Kind: ServiceDaemon, Category: "Network", Description: "DHCPv6 relay"},
	{Name: "hostapd", Kind: ServiceDaemon, Category: "Network", Description: "Host access point daemon (IAPP for wireless roaming)"},
	{Name: "npppd", Kind: ServiceDaemon, Category: "Network", Description: "PPP server: L2TP and PPPoE for VPN clients"},
	{Name: "ifstated", Kind: ServiceDaemon, Category: "Network", Description: "Runs commands when interfaces change state (failover)"},
	{Name: "multicast", Kind: ServiceBoot, Category: "Network", Description: "Routes multicast at boot, for a multicast router"},
	// Firewall and VPN
	{Name: "pf", Kind: ServiceBoot, Category: "Firewall and VPN", Description: "The packet filter, loaded at boot; OPF needs it", ManagedAt: "/firewall/settings"},
	{Name: "pflogd", Kind: ServiceDaemon, Category: "Firewall and VPN", Description: "Writes the packets pf logs to /var/log/pflog (the firewall log)"},
	{Name: "iked", Kind: ServiceDaemon, Category: "Firewall and VPN", Description: "IKEv2 IPsec VPN"},
	{Name: "isakmpd", Kind: ServiceDaemon, Category: "Firewall and VPN", Description: "IKEv1 IPsec VPN (older; iked is its successor)"},
	{Name: "ipsec", Kind: ServiceBoot, Category: "Firewall and VPN", Description: "Loads /etc/ipsec.conf's static IPsec flows at boot"},
	{Name: "sasyncd", Kind: ServiceDaemon, Category: "Firewall and VPN", Description: "Keeps IPsec state in sync between carp firewalls"},
	{Name: "ftpproxy", Kind: ServiceDaemon, Category: "Firewall and VPN", Description: "Lets FTP through NAT"},
	{Name: "ftpproxy6", Kind: ServiceDaemon, Category: "Firewall and VPN", Description: "Lets FTP through, over IPv6"},
	{Name: "tftpproxy", Kind: ServiceDaemon, Category: "Firewall and VPN", Description: "Lets TFTP through NAT (PXE boot, phones)"},
	{Name: "relayd", Kind: ServiceDaemon, Category: "Firewall and VPN", Description: "Load balancer and relay, with health checks"},
	{Name: "spamd", Kind: ServiceDaemon, Category: "Firewall and VPN", Description: "Spam deferral daemon for mail servers"},
	{Name: "spamd_black", Kind: ServiceBoot, Category: "Firewall and VPN", Description: "spamd in blacklist-only mode"},
	{Name: "spamlogd", Kind: ServiceDaemon, Category: "Firewall and VPN", Description: "Updates spamd's whitelist from pf's log"},
	{Name: "radiusd", Kind: ServiceDaemon, Category: "Firewall and VPN", Description: "RADIUS server, for VPN and 802.1X logins"},
	{Name: "opf", Kind: ServiceDaemon, Category: "Firewall and VPN", Description: "OPF itself: this web interface", ManagedAt: "/system/general"},
	// Routing
	{Name: "bgpd", Kind: ServiceDaemon, Category: "Routing", Description: "BGP routing"},
	{Name: "bgplgd", Kind: ServiceDaemon, Category: "Routing", Description: "A looking glass for bgpd, over HTTP"},
	{Name: "ospfd", Kind: ServiceDaemon, Category: "Routing", Description: "OSPF routing"},
	{Name: "ospf6d", Kind: ServiceDaemon, Category: "Routing", Description: "OSPFv3 routing, for IPv6"},
	{Name: "eigrpd", Kind: ServiceDaemon, Category: "Routing", Description: "EIGRP routing"},
	{Name: "ripd", Kind: ServiceDaemon, Category: "Routing", Description: "RIP routing"},
	{Name: "ldpd", Kind: ServiceDaemon, Category: "Routing", Description: "MPLS label distribution"},
	{Name: "dvmrpd", Kind: ServiceDaemon, Category: "Routing", Description: "DVMRP multicast routing"},
	{Name: "mrouted", Kind: ServiceDaemon, Category: "Routing", Description: "DVMRP multicast routing (older)"},
	{Name: "route6d", Kind: ServiceDaemon, Category: "Routing", Description: "RIPng routing, for IPv6"},
	// Name and time
	{Name: "unbound", Kind: ServiceDaemon, Category: "Name and time", Description: "The DNS resolver for the network", ManagedAt: "/services/dns"},
	{Name: "unwind", Kind: ServiceDaemon, Category: "Name and time", Description: "A validating resolver for the firewall's own lookups"},
	{Name: "nsd", Kind: ServiceDaemon, Category: "Name and time", Description: "Authoritative DNS server"},
	{Name: "ntpd", Kind: ServiceDaemon, Category: "Name and time", Description: "Keeps the clock right (and serves time, when set to)"},
	// Web and mail
	{Name: "httpd", Kind: ServiceDaemon, Category: "Web and mail", Description: "Web server"},
	{Name: "slowcgi", Kind: ServiceDaemon, Category: "Web and mail", Description: "Runs CGI programs for httpd"},
	{Name: "smtpd", Kind: ServiceDaemon, Category: "Web and mail", Description: "Mail server: delivers the system's own mail"},
	// Monitoring and logging
	{Name: "syslogd", Kind: ServiceDaemon, Category: "Monitoring and logging", Description: "System logging: /var/log, and logs sent elsewhere"},
	{Name: "snmpd", Kind: ServiceDaemon, Category: "Monitoring and logging", Description: "SNMP agent, for monitoring systems"},
	{Name: "sensorsd", Kind: ServiceDaemon, Category: "Monitoring and logging", Description: "Watches hardware sensors and runs commands at limits"},
	{Name: "bpflogd", Kind: ServiceDaemon, Category: "Monitoring and logging", Description: "Captures packets matching a filter to a file"},
	{Name: "accounting", Kind: ServiceBoot, Category: "Monitoring and logging", Description: "Process accounting at boot (lastcomm, sa)"},
	{Name: "watchdogd", Kind: ServiceDaemon, Category: "Monitoring and logging", Description: "Keeps the hardware watchdog from resetting the machine"},
	// System
	{Name: "sshd", Kind: ServiceDaemon, Category: "System", Description: "SSH server: remote shell access (and sign-in access)"},
	{Name: "cron", Kind: ServiceDaemon, Category: "System", Description: "Runs scheduled jobs (the daily, weekly and monthly scripts)"},
	{Name: "apmd", Kind: ServiceDaemon, Category: "System", Description: "Power management: battery, suspend, CPU speed"},
	{Name: "hotplugd", Kind: ServiceDaemon, Category: "System", Description: "Runs commands when devices are attached or detached"},
	{Name: "sndiod", Kind: ServiceDaemon, Category: "System", Description: "Audio server"},
	{Name: "vmd", Kind: ServiceDaemon, Category: "System", Description: "Runs virtual machines"},
	{Name: "library_aslr", Kind: ServiceBoot, Category: "System", Description: "Relinks system libraries in a random order at boot"},
	{Name: "check_quotas", Kind: ServiceBoot, Category: "System", Description: "Checks disk quotas at boot"},
	{Name: "wsmoused", Kind: ServiceDaemon, Category: "System", Description: "Mouse support on the text console"},
	{Name: "xenodm", Kind: ServiceDaemon, Category: "System", Description: "Graphical login (X)"},
	{Name: "ldattach", Kind: ServiceDaemon, Category: "System", Description: "Attaches a line discipline to a serial line (GPS, say)"},
	{Name: "ldomd", Kind: ServiceDaemon, Category: "System", Description: "Logical domain daemon (sparc64)"},
	// File sharing
	{Name: "nfsd", Kind: ServiceDaemon, Category: "File sharing", Description: "NFS server"},
	{Name: "mountd", Kind: ServiceDaemon, Category: "File sharing", Description: "NFS mount requests"},
	{Name: "portmap", Kind: ServiceDaemon, Category: "File sharing", Description: "RPC port mapper (for NFS and NIS)"},
	{Name: "lockd", Kind: ServiceDaemon, Category: "File sharing", Description: "NFS file locking"},
	{Name: "statd", Kind: ServiceDaemon, Category: "File sharing", Description: "NFS host status, for locking"},
	{Name: "amd", Kind: ServiceDaemon, Category: "File sharing", Description: "Mounts NFS file systems on demand"},
	{Name: "iscsid", Kind: ServiceDaemon, Category: "File sharing", Description: "iSCSI initiator"},
	{Name: "ftpd", Kind: ServiceDaemon, Category: "File sharing", Description: "FTP server"},
	{Name: "tftpd", Kind: ServiceDaemon, Category: "File sharing", Description: "TFTP server (PXE boot, firmware)"},
	// Rarely needed
	{Name: "ldapd", Kind: ServiceDaemon, Category: "Rarely needed", Description: "LDAP directory server"},
	{Name: "ypldap", Kind: ServiceDaemon, Category: "Rarely needed", Description: "Serves LDAP accounts as NIS maps"},
	{Name: "ypbind", Kind: ServiceDaemon, Category: "Rarely needed", Description: "NIS client"},
	{Name: "ypserv", Kind: ServiceDaemon, Category: "Rarely needed", Description: "NIS server"},
	{Name: "identd", Kind: ServiceDaemon, Category: "Rarely needed", Description: "Identification protocol (ident) server"},
	{Name: "inetd", Kind: ServiceDaemon, Category: "Rarely needed", Description: "Starts small network services when they're asked for"},
	{Name: "lpd", Kind: ServiceDaemon, Category: "Rarely needed", Description: "Print spooler"},
	{Name: "bootparamd", Kind: ServiceDaemon, Category: "Rarely needed", Description: "Boot parameters for diskless clients"},
	{Name: "rarpd", Kind: ServiceDaemon, Category: "Rarely needed", Description: "Reverse ARP, for diskless clients"},
	{Name: "rbootd", Kind: ServiceDaemon, Category: "Rarely needed", Description: "Boots HP diskless clients"},
	{Name: "mopd", Kind: ServiceDaemon, Category: "Rarely needed", Description: "Boots DEC MOP clients"},
}

// BaseService is what OPF knows of a service; ok is false for one it
// doesn't (a package's, say).
func BaseService(name string) (ServiceInfo, bool) {
	for _, s := range baseServices {
		if s.Name == name {
			return s, true
		}
	}
	return ServiceInfo{}, false
}

// BaseServices are all of them.
func BaseServices() []ServiceInfo { return append([]ServiceInfo(nil), baseServices...) }

// ServiceSetting is a service's boot settings, as the admin sets them:
// whether it starts at boot, and for a daemon its flags (nil: rc.d's
// defaults), routing table and stop timeout.
type ServiceSetting struct {
	Name    string  `json:"name"`
	Enabled bool    `json:"enabled"`
	Flags   *string `json:"flags,omitempty"`
	RTable  *int    `json:"rtable,omitempty"`
	Timeout *int    `json:"timeout,omitempty"`
}

// rcServiceMark ends each line OPF writes for a ServiceSetting. rc(8)
// reads the value up to the comment.
const rcServiceMark = "# set by OPF"

func isRcServiceLine(l string) bool {
	return strings.HasSuffix(strings.TrimRight(l, " \t"), rcServiceMark)
}

// serviceFlagsRE is what flags may be: what's safe between double
// quotes in a file sh sources, and nothing else.
var serviceFlagsRE = regexp.MustCompile(`^[A-Za-z0-9 ._,:/=@%+-]*$`)

// rcServiceVars are a setting's variables and their values.
func rcServiceVars(s ServiceSetting) [][2]string {
	info, _ := BaseService(s.Name)
	if info.Kind == ServiceBoot {
		v := "NO"
		if s.Enabled {
			v = "YES"
		}
		return [][2]string{{s.Name, v}}
	}
	flags := "NO"
	if s.Enabled {
		flags = ""
		if s.Flags != nil {
			flags = *s.Flags
		}
	}
	out := [][2]string{{s.Name + "_flags", flags}}
	if s.RTable != nil {
		out = append(out, [2]string{s.Name + "_rtable", fmt.Sprint(*s.RTable)})
	}
	if s.Timeout != nil {
		out = append(out, [2]string{s.Name + "_timeout", fmt.Sprint(*s.Timeout)})
	}
	return out
}

// RcServiceLines are OPF's lines for the model's service settings, in
// name order.
func RcServiceLines(m *Model) []string {
	settings := append([]ServiceSetting(nil), m.System.Services...)
	sort.Slice(settings, func(i, j int) bool { return settings[i].Name < settings[j].Name })
	var out []string
	for _, s := range settings {
		for _, kv := range rcServiceVars(s) {
			out = append(out, fmt.Sprintf("%s=\"%s\" %s", kv[0], kv[1], rcServiceMark))
		}
	}
	return out
}

// rcServiceNames are the variables the model's service settings set.
func rcServiceNames(m *Model) map[string]bool {
	out := map[string]bool{}
	for _, s := range m.System.Services {
		for _, kv := range rcServiceVars(s) {
			out[kv[0]] = true
		}
	}
	return out
}

// RcServiceValues are OPF's service lines in an rc.conf.local, for
// telling whether someone changed them.
func RcServiceValues(content string) []string {
	var out []string
	for _, l := range strings.Split(content, "\n") {
		if isRcServiceLine(l) {
			out = append(out, strings.Join(strings.Fields(l), " "))
		}
	}
	sort.Strings(out)
	return out
}
