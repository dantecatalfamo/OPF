package conformance

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/dantecatalfamo/OPF/internal/pf"
)

// The models the suite generates files from. Together they reach every
// branch of the generators (TestGeneratorCoverage fails on one they
// don't), so every line OPF can write is put through OpenBSD's own
// checks: pfctl -n, dhcpd -n, unbound-checkconf, ntpd -n, sshd -t, sh
// -n, dhcpleased -n.
//
// Every model is valid (pf.Validate), uses only the devices it's given
// (and the vlanN and wgN devices it makes itself), keeps its addresses
// in documentation and private ranges clear of 100.64.0.0/10 (the
// test machine's management network, which its WAN gets by DHCP), and
// lets SSH in on the WAN from 100.64.0.0/10, so applying it never cuts
// the suite off.

// NamedModel is a model and what it's for.
type NamedModel struct {
	Name  string
	Model *pf.Model
}

// Devices are the network devices of the machine the files are for.
// WAN is the one the suite reaches the machine on, by DHCP; LAN a
// physical port that leads nowhere (it carries VLANs too); Spare are
// ports the suite makes (vether), at least two.
type Devices struct {
	WAN, LAN string
	// Port is a physical port that only carries the models' VLANs (a
	// VLAN's parent must be one).
	Port  string
	Spare []string
}

// VMDevices are the test machine's (scripts/conformance/vm.sh): vio0 on
// vmd's local network; pair0, the LAN, patched to the test client; vio1
// a tap to nowhere; and the vether ports the suite makes.
var VMDevices = Devices{WAN: "vio0", LAN: "pair0", Port: "vio1", Spare: []string{"vether0", "vether1"}}

// ManagementNet is the test machine's management network, which the
// WAN is on and SSH comes from.
const ManagementNet = "100.64.0.0/10"

// Models are the models, "everything" first.
func Models(devs Devices) []NamedModel {
	if devs.WAN == "" || devs.LAN == "" || devs.Port == "" || len(devs.Spare) < 2 {
		panic("conformance.Models: needs a WAN, a LAN and two spare devices")
	}
	var out []NamedModel
	add := func(name string, m *pf.Model) { out = append(out, NamedModel{name, m}) }

	add("everything", everything(devs))
	add("minimal", base(devs))
	add("wan-only", wanOnly(devs))

	// The firewall's options, one choice at a time (everything has the
	// rest: return, if-bound, aggressive, adaptive with thresholds,
	// basic, notice, reassemble yes no-df, an explicit log interface).
	opts := func(name string, f func(o *pf.FirewallOptions)) {
		m := base(devs)
		f(&m.Firewall.Options)
		add(name, m)
	}
	for _, o := range []pf.Optimization{pf.OptNormal, pf.OptHighLatency, pf.OptSatellite, pf.OptConservative} {
		opts("optimization-"+string(o), func(x *pf.FirewallOptions) { x.Optimization = o })
	}
	opts("syncookies-always", func(x *pf.FirewallOptions) { x.Syncookies = pf.SyncookiesAlways })
	opts("syncookies-adaptive-defaults", func(x *pf.FirewallOptions) { x.Syncookies = pf.SyncookiesAdaptive })
	opts("ruleset-optimization-none", func(x *pf.FirewallOptions) { x.RulesetOptimization = "none" })
	opts("ruleset-optimization-profile", func(x *pf.FirewallOptions) { x.RulesetOptimization = "profile" })
	for _, d := range []string{"emerg", "alert", "crit", "err", "warning", "info", "debug"} {
		opts("debug-"+d, func(x *pf.FirewallOptions) { x.Debug = d })
	}
	opts("reassemble-yes", func(x *pf.FirewallOptions) { x.Reassemble = "yes" })
	opts("reassemble-no", func(x *pf.FirewallOptions) { x.Reassemble = "no" })
	opts("loginterface-none", func(x *pf.FirewallOptions) { x.LogInterface = "none" })
	opts("scrub-without-options", func(x *pf.FirewallOptions) { x.Scrub = pf.ScrubOptions{Enabled: true} })
	opts("block-log-default", func(x *pf.FirewallOptions) { x.LogDefaultBlock = true })

	// Outbound NAT's other modes (everything is hybrid).
	for _, mode := range []pf.NATMode{pf.NATModeAuto, pf.NATModeManual} {
		m := everything(devs)
		m.Firewall.OutboundNAT.Mode = mode
		add("nat-"+string(mode), m)
	}

	add("dns-recursive", dnsRecursive(devs))
	add("dns-forward-plain", dnsForwardPlain(devs))
	add("dns-through-exit", dnsThroughExit(devs))
	add("system-dns-servers", systemDNS(devs, pf.SystemDNS{Mode: pf.SystemDNSServers, Servers: []string{"192.0.2.53", "2001:db8::53"}, Only: true}))
	add("system-dns-wan", systemDNS(devs, pf.SystemDNS{Mode: pf.SystemDNSWAN}))
	add("unmanaged", unmanaged(devs))
	add("bare-vlan", bareVLANs(devs, 1))
	add("bare-vlans", bareVLANs(devs, 2))
	add("static-only", staticOnly(devs))
	add("dhcp-inside", dhcpInside(devs))
	add("route-to-dhcp-gateway", routeToDHCP(devs))
	add("endpoints", endpoints(devs))
	add("aggregate-lacp", aggregateLACP(devs))
	add("trunk-failover", trunkFailover(devs))
	return out
}

// ---------- building blocks ----------

func num(n int) *int        { return &n }
func text(s string) *string { return &s }
func yes() *bool            { b := true; return &b }
func no() *bool             { b := false; return &b }

// wgKey is a WireGuard key, distinct for each n.
func wgKey(n byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{n}, 32)) }

// sshKey is an ed25519 public key line, distinct for each n.
func sshKey(n byte, comment string) string {
	const typ = "ssh-ed25519"
	var b []byte
	b = binary.BigEndian.AppendUint32(b, uint32(len(typ)))
	b = append(b, typ...)
	b = binary.BigEndian.AppendUint32(b, 32)
	b = append(b, bytes.Repeat([]byte{n}, 32)...)
	return typ + " " + base64.StdEncoding.EncodeToString(b) + " " + comment
}

var anyEP = pf.Endpoint{Type: pf.EndpointAny}

func hostEP(a string) pf.Endpoint  { return pf.Endpoint{Type: pf.EndpointHost, Value: a} }
func netEP(n string) pf.Endpoint   { return pf.Endpoint{Type: pf.EndpointNetwork, Value: n} }
func aliasEP(a string) pf.Endpoint { return pf.Endpoint{Type: pf.EndpointAlias, Alias: a} }
func selfEP() pf.Endpoint          { return pf.Endpoint{Type: pf.EndpointSelf} }
func ifEP(id string, part pf.IfacePart) pf.Endpoint {
	return pf.Endpoint{Type: pf.EndpointIface, Iface: id, Part: part}
}

func static(addr string, prefix int) pf.IPv4Config {
	return pf.IPv4Config{Mode: pf.IPv4Static, Address: addr, Prefix: num(prefix)}
}

var dhcp = pf.IPv4Config{Mode: pf.IPv4DHCP}

// sshIn lets the suite's SSH in: on interfaces of the model, or on
// devices it doesn't manage.
func sshIn(ifaces, groups []string) pf.Rule {
	return pf.Rule{
		ID: "conformance-ssh", Kind: "form", Enabled: true, Interfaces: ifaces, Groups: groups,
		Description: "The conformance suite's own SSH connection",
		Action:      pf.ActionPass, Direction: pf.DirectionIn, Quick: true, Family: pf.FamilyInet, Protocol: pf.ProtoTCP,
		Source: netEP(ManagementNet), Destination: selfEP(), Port: "22", Log: pf.LogOff,
	}
}

// form is a guided rule with the usual defaults; f sets the rest.
func form(id string, ifaces []string, f func(r *pf.Rule)) pf.Rule {
	r := pf.Rule{
		ID: id, Kind: "form", Enabled: true, Interfaces: ifaces,
		Action: pf.ActionPass, Direction: pf.DirectionIn, Family: pf.FamilyAny, Protocol: pf.ProtoAny,
		Source: anyEP, Destination: anyEP, Log: pf.LogOff,
	}
	f(&r)
	return r
}

func wanIface(devs Devices) pf.Iface {
	return pf.Iface{ID: "wan", Name: "WAN", Device: devs.WAN, Role: pf.RoleWAN, Enabled: true, IPv4: dhcp, IPv6: pf.IPv6None}
}

func lanIface(devs Devices) pf.Iface {
	return pf.Iface{ID: "lan", Name: "LAN", Device: devs.LAN, Role: pf.RoleLAN, Enabled: true, IPv4: static("192.168.1.1", 24), IPv6: pf.IPv6None}
}

func defaultOptions() pf.FirewallOptions {
	return pf.FirewallOptions{
		BlockPolicy: pf.BlockPolicyDrop, StatePolicy: pf.StatePolicyOptionFloating, Optimization: pf.OptNormal,
		MaxStates: 100000, Syncookies: pf.SyncookiesNever,
	}
}

// base is the smallest sound model: a WAN by DHCP and a LAN, nothing
// else on.
func base(devs Devices) *pf.Model {
	return &pf.Model{
		System: pf.SystemSettings{Hostname: "fw", Domain: "office.arpa", Timezone: "UTC", NTPServers: []string{"pool.ntp.org"}},
		Interfaces: []pf.Iface{
			wanIface(devs),
			lanIface(devs),
		},
		Routing: pf.Routing{
			DefaultGateway: "gw_wan",
			Gateways:       []pf.Gateway{{ID: "gw_wan", Name: "WAN_DHCP", Iface: "wan", Address: "dhcp"}},
		},
		Firewall: pf.Firewall{
			Rules:       []pf.Rule{sshIn([]string{"wan"}, nil)},
			OutboundNAT: pf.OutboundNAT{Mode: pf.NATModeAuto},
			Options:     defaultOptions(),
		},
		DNS: pf.DNS{Mode: pf.ResolverModeRecursive},
	}
}

// wanOnly is a firewall with nothing behind it: no forwarding, no
// anti-lockout, and a resolver with no network to answer.
func wanOnly(devs Devices) *pf.Model {
	m := base(devs)
	m.Interfaces = m.Interfaces[:1]
	m.DNS.Enabled = true
	return m
}

// clone is a deep copy.
func clone(m *pf.Model) *pf.Model {
	data, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	var c pf.Model
	if err := json.Unmarshal(data, &c); err != nil {
		panic(err)
	}
	return &c
}

// ---------- everything ----------

// everything has as much on at once as validation allows.
// The collector the everything model's pflow0 sends to.
const (
	flowCollector = "127.0.0.1"
	flowPort      = 9995
)

func everything(devs Devices) *pf.Model {
	m := &pf.Model{}
	m.System = pf.SystemSettings{
		Hostname: "fw", Domain: "office.arpa", Timezone: "Europe/Berlin",
		NTPServers: []string{"pool.ntp.org", "1.pool.ntp.org"},
		NTP: &pf.NTPSettings{
			Servers: []pf.NTPServer{
				{Address: "time.example.org", One: true, Trusted: true, Weight: 5},
				{Address: "192.0.2.123"},
				{Address: "ntp.example.net", Weight: 2},
			},
			Sensors: []pf.NTPSensor{
				{Device: "*", Correction: 100, RefID: "GPS", Stratum: 2, Trusted: true, Weight: 3},
				{Device: "nmea0", Correction: -50, RefID: "10"}, // a refid that would read as a number: quoted
			},
			Constraints: []pf.NTPConstraint{
				{URL: "https://www.example.com/", Every: true},
				{URL: "https://time.example.net/date", Addresses: []string{"192.0.2.10", "2001:db8::10"}},
				{URL: "constraint.example.org"},
			},
			ServeOn:   []string{"lan", "iot"},
			Listen:    []pf.NTPListen{{Address: "192.168.1.1"}, {Address: "127.0.0.1", RTable: 202}, {Address: "::1"}},
			QueryFrom: []string{"192.168.1.1", "2001:db8::1"},
		},
		DNS: &pf.SystemDNS{Mode: pf.SystemDNSSelf, Servers: []string{"9.9.9.9"}, Only: true},
		Services: []pf.ServiceSetting{
			{Name: "pflogd", Enabled: true},
			{Name: "ntpd", Enabled: true, Flags: text("-v"), RTable: num(0), Timeout: num(30)},
			{Name: "smtpd", Enabled: false},
			{Name: "multicast", Enabled: true},
			{Name: "library_aslr", Enabled: false},
			{Name: "httpd", Enabled: false, Timeout: num(60)},
		},
	}

	m.Interfaces = []pf.Iface{
		// The first WAN is the one the WAN protections are for: a fixed
		// address on a spare port, so blocking bogons (100.64.0.0/10
		// among them) doesn't block the suite.
		{ID: "edge", Name: "Edge", Device: devs.Spare[0], Role: pf.RoleWAN, Enabled: true, IPv4: static("198.51.100.2", 24), IPv6: pf.IPv6None,
			MTU: num(1400), BlockPrivate: true, BlockBogons: true, Antispoof: true},
		wanIface(devs),
		func() pf.Iface {
			i := lanIface(devs)
			i.Antispoof, i.Masquerade = true, true
			return i
		}(),
		{ID: "iot", Name: "IoT", Device: "vlan20", Role: pf.RoleOPT, Enabled: true, IPv4: static("192.168.20.1", 24), IPv6: pf.IPv6None,
			VLAN: &pf.VLANConfig{Parent: devs.Port, Tag: 20}},
		{ID: "lab", Name: "Lab", Device: devs.Spare[1], Role: pf.RoleOPT, Enabled: true, IPv4: static("172.16.5.1", 24), IPv6: pf.IPv6SLAAC},
		{ID: "old", Name: "Old", Device: "vlan40", Role: pf.RoleOPT, Enabled: false, IPv4: static("192.168.40.1", 24), IPv6: pf.IPv6None,
			VLAN: &pf.VLANConfig{Parent: devs.Port, Tag: 40}},
		{ID: "remote", Name: "Remote access", Device: "wg0", Role: pf.RoleVPN, Enabled: true, IPv4: static("10.8.0.1", 24), IPv6: pf.IPv6None,
			WireGuard: &pf.WireGuard{ListenPort: 51820, PublicKey: wgKey(1), PublicEndpoint: "vpn.example.com:51820", ReachableFrom: []string{"lan", "old"},
				Peers: []pf.Peer{
					{ID: "p_full", Name: "Priya phone", PublicKey: wgKey(11), Address: "10.8.0.2/32", Keepalive: num(25), ClientRoutes: pf.ClientRoutesFull, PresharedKey: "00112233445566778899aabbccddeeff"},
					{ID: "p_split1", Name: "Sam laptop", PublicKey: wgKey(12), Address: "10.8.0.3/32", ClientRoutes: pf.ClientRoutesSplit},
					{ID: "p_split2", Name: "Ana laptop", PublicKey: wgKey(13), Address: "10.8.0.4/32", ClientRoutes: pf.ClientRoutesSplit},
					{ID: "p_vpn1", Name: "Kiosk", PublicKey: wgKey(14), Address: "10.8.0.5/32", ClientRoutes: pf.ClientRoutesVPN},
				}}},
		{ID: "sites", Name: "Sites", Device: "wg1", Role: pf.RoleVPN, Enabled: true, IPv4: static("10.9.0.1", 24), IPv6: pf.IPv6None,
			WireGuard: &pf.WireGuard{ListenPort: 51821, PublicKey: wgKey(2),
				Peers: []pf.Peer{
					{ID: "p_site", Name: "Warehouse router", PublicKey: wgKey(21), Address: "10.9.0.2/32", Networks: []string{"10.20.0.0/16", "10.21.0.0/16"},
						Endpoint: "warehouse.example.net:51820", Keepalive: num(25), ClientRoutes: pf.ClientRoutesSite},
					{ID: "p_split3", Name: "Lee laptop", PublicKey: wgKey(22), Address: "10.9.0.3/32", Endpoint: "203.0.113.7:51820", ClientRoutes: pf.ClientRoutesSplit},
					{ID: "p_vpn2", Name: "Camera one", PublicKey: wgKey(23), Address: "10.9.0.4/32", ClientRoutes: pf.ClientRoutesVPN},
					{ID: "p_vpn3", Name: "Camera two", PublicKey: wgKey(24), Address: "10.9.0.5/32", Endpoint: "[2001:db8::7]:51820", ClientRoutes: pf.ClientRoutesVPN},
				}}},
		{ID: "provider", Name: "Provider", Device: "wg2", Role: pf.RoleVPN, Enabled: true, IPv4: static("10.66.0.2", 32), IPv6: pf.IPv6None,
			WireGuard: &pf.WireGuard{PublicKey: wgKey(3), Exit: &pf.Exit{
				PublicKey: wgKey(31), Endpoint: "vpn.example.net:51820", PresharedKey: "0123456789abcdef", Keepalive: num(25),
				From: []string{"iot", "old"},
			}}},
		{ID: "spare_wg", Name: "Spare tunnel", Device: "wg3", Role: pf.RoleVPN, Enabled: false, IPv4: static("10.10.0.1", 24), IPv6: pf.IPv6None,
			WireGuard: &pf.WireGuard{ListenPort: 51822, PublicKey: wgKey(4), ReachableFrom: []string{"lan"},
				Peers: []pf.Peer{{ID: "p_spare", Name: "Spare", PublicKey: wgKey(41), Address: "10.10.0.2/32", ClientRoutes: pf.ClientRoutesSplit}}}},
	}

	m.Routing = pf.Routing{
		DefaultGateway: "gw_wan",
		Gateways: []pf.Gateway{
			{ID: "gw_wan", Name: "WAN_DHCP", Iface: "wan", Address: "dhcp", Monitor: "9.9.9.9", Description: "The provider's"},
			{ID: "gw_edge", Name: "Edge", Iface: "edge", Address: "198.51.100.1"},
		},
		Routes: []pf.StaticRoute{
			{ID: "r_partner", Enabled: true, Network: "203.0.113.0/24", Gateway: "gw_edge", Description: "Partner network"},
			{ID: "r_off", Enabled: false, Network: "198.18.0.0/15", Gateway: "gw_edge"},
		},
	}

	fw := &m.Firewall
	fw.Aliases = []pf.Alias{
		{ID: "a1", Name: "office_hosts", Type: pf.AliasHosts, Entries: []string{"192.168.1.10", "192.168.1.11", "2001:db8::10"}, Description: "Servers"},
		{ID: "a2", Name: "office_nets", Type: pf.AliasNetworks, Entries: []string{"192.168.1.0/24", "192.168.20.5"}},
		{ID: "a3", Name: "web_ports", Type: pf.AliasPorts, Entries: []string{"80", "443", "https"}},
		{ID: "a4", Name: "abusers", Type: pf.AliasTable, Entries: []string{}},
		{ID: "a5", Name: "t_minute", Type: pf.AliasTable, Entries: []string{}, ExpireMinutes: num(1)},
		{ID: "a6", Name: "t_minutes", Type: pf.AliasTable, Entries: []string{}, ExpireMinutes: num(90)},
		{ID: "a7", Name: "t_hour", Type: pf.AliasTable, Entries: []string{}, ExpireMinutes: num(60)},
		{ID: "a8", Name: "t_hours", Type: pf.AliasTable, Entries: []string{}, ExpireMinutes: num(120)},
		{ID: "a9", Name: "t_day", Type: pf.AliasTable, Entries: []string{}, ExpireMinutes: num(1440)},
		{ID: "a10", Name: "t_days", Type: pf.AliasTable, Entries: []string{}, ExpireMinutes: num(2880)},
		{ID: "a11", Name: "drop_list", Type: pf.AliasURL, Entries: []string{}, URL: "https://lists.example.com/drop.txt", RefreshHours: num(12)},
	}

	lan := []string{"lan"}
	fw.Rules = []pf.Rule{
		sshIn([]string{"wan"}, nil),
		// Floating: several interfaces and a group; none at all.
		form("float-tag", []string{"lan", "iot"}, func(r *pf.Rule) {
			r.Groups = []string{"egress"}
			r.Action, r.Direction, r.Log, r.Family = pf.ActionMatch, pf.DirectionOut, pf.LogAll, pf.FamilyInet
			r.Tag, r.Prio = "bulk", num(1)
			r.Description = "Floating: tag what leaves"
		}),
		form("float-ping", nil, func(r *pf.Rule) {
			r.Direction, r.Family, r.Protocol, r.ICMPType = pf.DirectionAny, pf.FamilyInet, pf.ProtoICMP, "echoreq"
		}),
		form("float-group", nil, func(r *pf.Rule) {
			r.Groups = []string{"wg"}
			r.Protocol, r.Destination, r.Port = pf.ProtoUDP, selfEP(), "53"
		}),
		// Every state option.
		form("lan-web", lan, func(r *pf.Rule) {
			r.Quick, r.Family, r.Protocol = true, pf.FamilyInet, pf.ProtoTCP
			r.Source, r.SourcePort = ifEP("lan", pf.PartNetwork), "1024:65535"
			r.Port, r.TCPFlags, r.Probability = "alias:web_ports", "S/SA", num(100)
			r.State = &pf.StateOptions{Mode: pf.StateModeKeep, MaxStates: num(5000), MaxSrcConn: num(100),
				MaxSrcConnRate: &pf.SrcConnRate{Count: 50, Seconds: 5}, Overload: "abusers", FlushGlobal: true, Policy: pf.StatePolicyIfBound}
			r.Description = "Web out, limited"
		}),
		form("lan-overload", lan, func(r *pf.Rule) {
			r.Protocol, r.Port = pf.ProtoTCP, "25"
			r.State = &pf.StateOptions{Mode: pf.StateModeKeep, MaxSrcConn: num(10), Overload: "abusers"}
		}),
		form("lan-list", lan, func(r *pf.Rule) {
			r.Log, r.Protocol = pf.LogOn, pf.ProtoTCP
			r.Source, r.Destination, r.Port = netEP("192.168.1.0/24"), hostEP("198.51.100.80"), "80,443, 8443"
			r.TCPFlags = "any"
			r.State = &pf.StateOptions{Mode: pf.StateModeModulate}
		}),
		form("lan-range", lan, func(r *pf.Rule) {
			r.Protocol, r.SourcePort, r.Port = pf.ProtoUDP, "> 1023", "8000-8080"
			r.State = &pf.StateOptions{Mode: pf.StateModeKeep, Sloppy: true, Pflow: true, Policy: pf.StatePolicyFloating}
		}),
		form("lan-synproxy", lan, func(r *pf.Rule) {
			r.Protocol, r.Destination, r.Port, r.TCPFlags = pf.ProtoTCP, selfEP(), "ssh", "S/SAFR"
			r.State = &pf.StateOptions{Mode: pf.StateModeSynproxy}
		}),
		form("lan-nostate", lan, func(r *pf.Rule) {
			r.Direction, r.Protocol, r.Source, r.Port = pf.DirectionOut, pf.ProtoUDP, selfEP(), "123"
			r.State = &pf.StateOptions{Mode: pf.StateModeNone}
		}),
		form("lan-os", lan, func(r *pf.Rule) {
			r.Protocol, r.OSFingerprint, r.Destination = pf.ProtoTCP, "OpenBSD", aliasEP("office_hosts")
			r.State = &pf.StateOptions{Mode: pf.StateModeKeep}
		}),
		form("lan-route", lan, func(r *pf.Rule) {
			r.Family, r.Protocol = pf.FamilyInet, pf.ProtoTCP
			r.Source, r.Destination, r.Port = ifEP("lan", pf.PartNetwork), netEP("203.0.113.0/24"), "443"
			r.Gateway = "gw_edge"
		}),
		form("lan-tcpudp", lan, func(r *pf.Rule) {
			r.Protocol, r.Destination, r.Port = pf.ProtoTCPUDP, aliasEP("office_nets"), "domain"
		}),
		form("lan-v6", lan, func(r *pf.Rule) {
			r.Family, r.Protocol, r.ICMPType = pf.FamilyInet6, pf.ProtoICMP6, "echoreq"
		}),
		form("lan-esp", lan, func(r *pf.Rule) {
			r.Protocol, r.Source, r.Destination = pf.ProtoESP, hostEP("192.168.1.30"), hostEP("198.51.100.30")
		}),
		form("lan-gre", lan, func(r *pf.Rule) {
			r.Direction, r.Protocol, r.Once = pf.DirectionOut, pf.ProtoGRE, true
		}),
		form("lan-sample", lan, func(r *pf.Rule) {
			r.Action, r.Protocol, r.Tagged, r.Tag, r.Probability = pf.ActionMatch, pf.ProtoTCP, "bulk", "sampled", num(50)
		}),
		form("lan-rtable", lan, func(r *pf.Rule) {
			r.Action, r.Source, r.Destination, r.RTable = pf.ActionMatch, ifEP("lan", pf.PartNetwork), netEP("10.99.0.0/16"), num(0)
		}),
		form("lan-users", lan, func(r *pf.Rule) {
			r.Source = pf.Endpoint{Type: pf.EndpointAuthpfUsers}
			r.Destination = ifEP("iot", pf.PartNetwork)
		}),
		form("lan-noalias", lan, func(r *pf.Rule) {
			r.Source = pf.Endpoint{Type: pf.EndpointIface, Iface: "lan", Part: pf.PartNetwork, NoAlias: true}
			r.Destination = pf.Endpoint{Type: pf.EndpointIface, Group: "egress", Part: pf.PartNetwork}
		}),
		form("lan-loopback", lan, func(r *pf.Rule) {
			r.Destination = pf.Endpoint{Type: pf.EndpointIface, Group: "lo0", Dynamic: no()}
		}),
		form("lan-broadcast", lan, func(r *pf.Rule) {
			r.Protocol, r.Destination, r.Port = pf.ProtoUDP, ifEP("lan", pf.PartBroadcast), "137:138"
		}),
		// Every way to block.
		form("lan-reject", lan, func(r *pf.Rule) {
			r.Action, r.Quick, r.Protocol, r.Port = pf.ActionReject, true, pf.ProtoTCP, "23"
		}),
		form("lan-drop", lan, func(r *pf.Rule) {
			r.Action, r.BlockReturn, r.Source = pf.ActionBlock, pf.BlockReturnDrop, hostEP("192.168.1.66")
		}),
		form("lan-block", lan, func(r *pf.Rule) {
			r.Action, r.Source = pf.ActionBlock, pf.Endpoint{Type: pf.EndpointHost, Value: "192.168.1.67", Not: true}
			r.Destination = pf.Endpoint{Type: pf.EndpointNetwork, Value: "10.0.0.0/8", Not: true}
		}),
		form("lan-return", lan, func(r *pf.Rule) {
			r.Action, r.BlockReturn = pf.ActionBlock, pf.BlockReturnReturn
			r.Destination = pf.Endpoint{Type: pf.EndpointAlias, Alias: "office_nets", Not: true}
		}),
		form("lan-rst-ttl", lan, func(r *pf.Rule) {
			r.Action, r.BlockReturn, r.ReturnRstTTL, r.Protocol, r.Port = pf.ActionBlock, pf.BlockReturnRST, num(64), pf.ProtoTCP, "25"
		}),
		form("lan-rst", lan, func(r *pf.Rule) {
			r.Action, r.BlockReturn, r.Protocol, r.Port = pf.ActionBlock, pf.BlockReturnRST, pf.ProtoTCP, "26"
		}),
		form("lan-icmp-code", lan, func(r *pf.Rule) {
			r.Action, r.BlockReturn, r.ReturnICMPCode, r.Family = pf.ActionBlock, pf.BlockReturnICMP, "port-unr", pf.FamilyInet
			r.Protocol, r.Port = pf.ProtoUDP, "69"
		}),
		form("lan-icmp", lan, func(r *pf.Rule) {
			r.Action, r.BlockReturn, r.Family, r.Protocol, r.Port = pf.ActionBlock, pf.BlockReturnICMP, pf.FamilyInet, pf.ProtoUDP, "70"
		}),
		form("lan-icmp6-code", lan, func(r *pf.Rule) {
			r.Action, r.BlockReturn, r.ReturnICMPCode, r.Family = pf.ActionBlock, pf.BlockReturnICMP6, "port-unr", pf.FamilyInet6
			r.Protocol, r.Port = pf.ProtoUDP, "69"
		}),
		form("lan-icmp6", lan, func(r *pf.Rule) {
			r.Action, r.BlockReturn, r.Family, r.Protocol, r.Port = pf.ActionBlock, pf.BlockReturnICMP6, pf.FamilyInet6, pf.ProtoUDP, "70"
		}),
		{ID: "lan-raw", Kind: "raw", Enabled: true, Interfaces: lan, Description: "mDNS", Text: "pass in on $lan inet proto udp from any to 224.0.0.251 port 5353"},
		{ID: "raw-float", Kind: "raw", Enabled: true, Text: "pass quick on lo0 all"},
		form("lan-off", lan, func(r *pf.Rule) { r.Enabled, r.Action = false, pf.ActionBlock }),
		// On the other interfaces.
		form("iot-reply", []string{"iot"}, func(r *pf.Rule) {
			r.Source, r.Destination, r.ReplyTo = ifEP("iot", pf.PartNetwork), netEP("203.0.113.0/24"), "gw_edge"
		}),
		form("remote-peer", []string{"remote"}, func(r *pf.Rule) {
			r.Source, r.Destination = ifEP("remote", pf.PartPeer), ifEP("lan", pf.PartNetwork)
		}),
		form("sites-in", []string{"sites"}, func(r *pf.Rule) {
			r.Source, r.Destination = netEP("10.20.0.0/16"), ifEP("lan", pf.PartNetwork)
		}),
		// For signed-in users: everyone's, one user's, and one that's off.
		form("authpf-all", lan, func(r *pf.Rule) {
			r.Authpf = &pf.RuleAuthpf{}
			r.Quick, r.Protocol, r.Port = true, pf.ProtoTCP, "445"
			r.Source, r.Destination = pf.Endpoint{Type: pf.EndpointAuthpfUser}, aliasEP("office_hosts")
			r.Description = "Signed-in users reach the file servers"
		}),
		form("authpf-alice", lan, func(r *pf.Rule) {
			r.Authpf = &pf.RuleAuthpf{Users: []string{"u_alice"}}
			r.Source, r.Destination = pf.Endpoint{Type: pf.EndpointAuthpfUser}, aliasEP("office_nets")
		}),
		form("authpf-bob", lan, func(r *pf.Rule) {
			r.Enabled = false
			r.Authpf = &pf.RuleAuthpf{Users: []string{"u_bob"}}
			r.Source, r.Destination = pf.Endpoint{Type: pf.EndpointAuthpfUser}, ifEP("iot", pf.PartNetwork)
		}),
	}

	fw.Forwards = []pf.PortForward{
		{ID: "fwd-web", Enabled: true, Iface: "wan", Protocol: pf.ProtoTCPUDP, Source: anyEP, ExternalPort: "8443",
			Target: "192.168.1.10", TargetPort: "443", Reflection: true, Log: true, Description: "Web server"},
		{ID: "fwd-range", Enabled: true, Iface: "edge", Protocol: pf.ProtoUDP, Source: netEP("203.0.113.0/24"), ExternalPort: "10000:10010",
			Target: "192.168.1.11", TargetPort: "10000"},
		{ID: "fwd-off", Enabled: false, Iface: "wan", Protocol: pf.ProtoTCP, Source: anyEP, ExternalPort: "2222", Target: "192.168.1.12", TargetPort: "22"},
		{ID: "fwd-old", Enabled: true, Iface: "old", Protocol: pf.ProtoTCP, Source: anyEP, ExternalPort: "80", Target: "192.168.40.10", TargetPort: "80"},
	}

	fw.OutboundNAT = pf.OutboundNAT{Mode: pf.NATModeHybrid, Rules: []pf.NATRule{
		{ID: "nat-none", Enabled: true, Iface: "wan", Source: netEP("192.168.1.128/25"), Destination: netEP("203.0.113.0/24"),
			Translation: pf.Translation{Type: pf.TranslationNone}, Description: "Partner sees real addresses"},
		{ID: "nat-addr", Enabled: true, Iface: "edge", Source: ifEP("lan", pf.PartNetwork), Destination: anyEP,
			Translation: pf.Translation{Type: pf.TranslationAddress, Value: "198.51.100.10"}, StaticPort: true},
		{ID: "nat-hash", Enabled: true, Iface: "edge", Source: ifEP("iot", pf.PartNetwork), Destination: anyEP,
			Translation: pf.Translation{Type: pf.TranslationAddress, Value: "198.51.100.32/28"}, Pool: pf.PoolSourceHash},
		{ID: "nat-random", Enabled: true, Iface: "edge", Source: netEP("172.16.5.0/24"), Destination: anyEP,
			Translation: pf.Translation{Type: pf.TranslationAddress, Value: "198.51.100.48/28"}, Pool: pf.PoolRandom},
		{ID: "nat-rr", Enabled: true, Iface: "wan", Source: hostEP("192.168.1.20"), Destination: anyEP,
			Translation: pf.Translation{Type: pf.TranslationIfaddr}, Pool: pf.PoolRoundRobin},
		{ID: "nat-off", Enabled: false, Iface: "wan", Source: anyEP, Destination: anyEP, Translation: pf.Translation{Type: pf.TranslationIfaddr}},
	}}

	hostID := uint32(1)
	fw.Options = pf.FirewallOptions{
		BlockPolicy: pf.BlockPolicyReturn, StatePolicy: pf.StatePolicyOptionIfBound, Optimization: pf.OptAggressive,
		MaxStates: 200000, Syncookies: pf.SyncookiesAdaptive, SyncookiesStart: num(30), SyncookiesEnd: num(10),
		Scrub:           pf.ScrubOptions{Enabled: true, MaxMss: num(1440), RandomID: true, NoDf: true, MinTTL: num(5), ReassembleTCP: true},
		LogDefaultBlock: true,
		Limits: pf.Limits{SrcNodes: num(20000), Frags: num(30000), Tables: num(2000), TableEntries: num(400000),
			PktdelayPkts: num(20000), Anchors: num(1024)},
		Timeouts: map[string]int{"tcp.first": 120, "tcp.established": 86400, "udp.first": 60, "icmp.error": 10,
			"frag": 60, "interval": 10, "src.track": 0, "adaptive.start": 120000, "adaptive.end": 240000},
		StateDefaults:       []string{"no-sync", "pflow"},
		Reassemble:          "yes",
		ReassembleNoDf:      true,
		RulesetOptimization: "basic",
		Debug:               "notice",
		HostID:              &hostID,
		Fingerprints:        "/etc/pf.os",
		LogInterface:        "lan",
		SkipOn:              []string{"lab", "enc0"},
	}
	fw.Custom = pf.CustomPf{
		Options:      "set timeout udp.multiple 60\n",
		BeforeFilter: "pass in quick on $lan inet proto icmp all icmp-type echoreq\n\npass out quick on $lan inet proto icmp all",
		AfterFilter:  "block in log quick on $iot proto tcp to port 23",
	}
	fw.Traffic = &pf.TrafficAccounting{Enabled: true, Days: 7, MaxDevices: 100}
	// pflow0 goes to the suite's own collector (TestFlowExport); pflow1
	// is sent from the LAN's address, and pflow2 is turned off.
	fw.FlowExports = []pf.FlowExport{
		{ID: "flow_local", Name: "Suite collector", Enabled: true, Device: "pflow0", Collector: flowCollector, Port: flowPort, Version: pf.FlowIPFIX},
		{ID: "flow_lan", Name: "Lab collector", Enabled: true, Device: "pflow1", Collector: "192.0.2.50", Port: 2055, Source: "lan", Version: pf.FlowNetFlow5},
		{ID: "flow_off", Name: "Old collector", Enabled: false, Device: "pflow2", Collector: "2001:db8::5", Port: 4739, Version: pf.FlowIPFIX},
	}
	fw.Authpf = &pf.Authpf{
		Enabled: true, SignIn: []string{"lan", "wan"},
		Message: "Welcome. You're signed in.\nSign out to close access.\n\n",
		Users: []pf.AuthpfUser{
			{ID: "u_alice", Name: "alice", Description: "Alice", Keys: []string{sshKey(1, "alice@laptop"), "  " + sshKey(2, "alice@phone")}},
			{ID: "u_bob", Name: "bob", Keys: []string{sshKey(3, "bob")}, Banned: "Access suspended; see IT.\n"},
			{ID: "u_carol", Name: "carol", Keys: []string{}, Banned: "Gone"},
		},
	}

	m.DHCP = []pf.DHCPScope{
		{Iface: "lan", Enabled: true, RangeStart: "192.168.1.100", RangeEnd: "192.168.1.199", LeaseHours: 12, DNS: pf.DNSModeSelf,
			Reservations: []pf.Reservation{
				{ID: "res1", Hostname: "printer", MAC: "00:11:22:33:44:55", IP: "192.168.1.200"},
				{ID: "res2", Hostname: "scanner", MAC: "00:11:22:33:44:56", IP: "192.168.1.201"},
			}},
		{Iface: "iot", Enabled: true, RangeStart: "192.168.20.100", RangeEnd: "192.168.20.199", LeaseHours: 24, DNS: pf.DNSModeCustom,
			DNSServers:   []string{"9.9.9.9", "149.112.112.112"},
			Reservations: []pf.Reservation{{ID: "res3", Hostname: "camera", MAC: "00:11:22:33:44:57", IP: "192.168.20.50"}}},
		{Iface: "lab", Enabled: true, RangeStart: "172.16.5.10", RangeEnd: "172.16.5.20", LeaseHours: 1, DNS: pf.DNSModeSelf},
		{Iface: "old", Enabled: false, RangeStart: "192.168.40.100", RangeEnd: "192.168.40.199", LeaseHours: 12, DNS: pf.DNSModeSelf},
	}

	m.DNS = pf.DNS{
		Enabled: true, Mode: pf.ResolverModeForward, Forwarders: []string{"9.9.9.9", "2620:fe::fe"}, ForwardTLS: true, DNSSEC: true,
		RegisterReservations: true, RegisterDynamicLeases: true, RewriteInvalidLeaseNames: true,
		Overrides: []pf.HostOverride{
			{ID: "o1", Host: "nas", Domain: "office.arpa", IP: "192.168.1.10", Description: "File server"},
			{ID: "o2", Host: "nas6", Domain: "office.arpa", IP: "2001:db8::10"},
			{ID: "o3", Host: "build", Domain: "lab.internal", IP: "172.16.5.10"},
		},
		Zones: []pf.DNSZone{
			{Name: "office.arpa", Type: pf.DNSZoneTransparent},
			{Name: "lab.internal", Type: pf.DNSZoneStatic},
			{Name: "corp.example.com", Type: pf.DNSZoneTransparent},
		},
		Records: []pf.DNSRecord{
			{ID: "d1", Name: "www.office.arpa", Type: pf.DNSRecordCNAME, Value: "nas.office.arpa"},
			{ID: "d2", Name: "docs.corp.example.com", Type: pf.DNSRecordCNAME, Value: "docs.example.net", TTL: num(300)},
			{ID: "d3", Name: "office.arpa", Type: pf.DNSRecordMX, Value: "mail.office.arpa", Priority: num(10)},
			{ID: "d4", Name: "office.arpa", Type: pf.DNSRecordTXT, Value: "v=spf1 mx -all"},
			{ID: "d5", Name: "_long.office.arpa", Type: pf.DNSRecordTXT, Value: strings.Repeat("0123456789", 30)},
			{ID: "d6", Name: "_sip._tcp.office.arpa", Type: pf.DNSRecordSRV, Value: "pbx.office.arpa", Priority: num(10), Weight: num(5), Port: num(5060)},
			{ID: "d7", Name: "_imap._tcp.office.arpa", Type: pf.DNSRecordSRV, Value: ".", Priority: num(0), Weight: num(0), Port: num(0)},
			{ID: "d8", Name: "office.arpa", Type: pf.DNSRecordCAA, Tag: "issue", Value: "letsencrypt.org"},
			{ID: "d9", Name: "192.168.1.50", Type: pf.DNSRecordPTR, Value: "printer2.office.arpa", TTL: num(600)},
			{ID: "d10", Name: "192.168.1.1", Type: pf.DNSRecordPTR, Value: "gateway.office.arpa"},
			{ID: "d11", Name: "2001:db8::50", Type: pf.DNSRecordPTR, Value: "v6host.office.arpa"},
		},
		Blocklists: []pf.DNSBlocklist{
			{ID: "ads", Name: "Ads", URL: "https://lists.example.com/ads.txt", Enabled: true, RefreshHours: num(24)},
			{ID: "old-list", Name: "Old list", URL: "https://lists.example.com/old.txt", Enabled: false},
		},
		Blocked:     []string{"ads.example.com", "*.tracker.example.net"},
		Allowed:     []string{"ok.example.com", "*.cdn.example.org"},
		BlockAnswer: pf.BlockAnswerNXDomain,
		Activity:    &pf.DNSActivity{Enabled: true, Devices: true, Days: 14, DeviceDays: 7, DetailDays: 3, MaxDevices: 64},
	}
	return m
}

// ---------- focused variants ----------

// dnsRecursive asks the root servers itself, without DNSSEC, and
// answers on the networks listed; its own blocked names are answered
// with nothing (0.0.0.0, ::) rather than "no such name".
func dnsRecursive(devs Devices) *pf.Model {
	m := base(devs)
	m.Interfaces = append(m.Interfaces, pf.Iface{ID: "guest", Name: "Guest", Device: devs.Spare[0], Role: pf.RoleOPT, Enabled: true,
		IPv4: static("192.168.30.1", 24), IPv6: pf.IPv6None})
	m.DNS = pf.DNS{Enabled: true, Interfaces: []string{"lan"}, Mode: pf.ResolverModeRecursive, RewriteInvalidLeaseNames: true,
		Blocklists: []pf.DNSBlocklist{{ID: "ads", Name: "Ads", URL: "https://lists.example.com/ads.txt", Enabled: true}},
		Blocked:    []string{"ads.example.com"},
		Activity:   &pf.DNSActivity{Enabled: false, Days: 7}}
	m.DHCP = []pf.DHCPScope{{Iface: "lan", Enabled: true, RangeStart: "192.168.1.100", RangeEnd: "192.168.1.199", LeaseHours: 12, DNS: pf.DNSModeSelf}}
	return m
}

// dnsForwardPlain forwards over plain DNS.
func dnsForwardPlain(devs Devices) *pf.Model {
	m := base(devs)
	m.DNS = pf.DNS{Enabled: true, Mode: pf.ResolverModeForward, Forwarders: []string{"9.9.9.9", "149.112.112.112"}, DNSSEC: true}
	return m
}

// dnsThroughExit sends every lookup to a VPN provider's resolvers.
func dnsThroughExit(devs Devices) *pf.Model {
	m := everything(devs)
	for i := range m.Interfaces {
		if e := m.Interfaces[i].WireGuard; e != nil && e.Exit != nil {
			e.Exit.DNS = []string{"10.66.0.1", "10.66.0.3"}
		}
	}
	return m
}

// systemDNS is the firewall's own lookups set as d says.
func systemDNS(devs Devices, d pf.SystemDNS) *pf.Model {
	m := base(devs)
	m.System.DNS = &d
	return m
}

// unmanaged leaves DHCP, DNS and time as they're configured by hand.
func unmanaged(devs Devices) *pf.Model {
	m := base(devs)
	m.System.Unmanaged = []string{pf.AreaDHCP, pf.AreaDNS, pf.AreaNTP}
	m.System.NTP = &pf.NTPSettings{Constraints: []pf.NTPConstraint{{URL: "https://www.example.com/"}}}
	m.DHCP = []pf.DHCPScope{{Iface: "lan", Enabled: false, RangeStart: "192.168.1.100", RangeEnd: "192.168.1.199", LeaseHours: 12, DNS: pf.DNSModeSelf}}
	m.DNS.Blocked = []string{"ads.example.com"}
	return m
}

// bareVLANs carries n VLANs on the LAN port, which isn't an interface of
// the model itself.
func bareVLANs(devs Devices, n int) *pf.Model {
	m := base(devs)
	m.Interfaces = []pf.Iface{wanIface(devs)}
	for i := range n {
		tag := 10 + i
		id := "lan"
		if i > 0 {
			id = fmt.Sprintf("vlan_%d", tag)
		}
		m.Interfaces = append(m.Interfaces, pf.Iface{ID: id, Name: fmt.Sprintf("VLAN %d", tag), Device: fmt.Sprintf("vlan%d", tag),
			Role: pf.RoleLAN, Enabled: true, IPv4: static(fmt.Sprintf("192.168.%d.1", tag), 24), IPv6: pf.IPv6None,
			VLAN: &pf.VLANConfig{Parent: devs.Port, Tag: tag}})
	}
	return m
}

// staticOnly has no interface addressed by DHCP or SLAAC: a fixed
// default gateway (/etc/mygate), and self written plainly. The device
// the suite reaches the machine on isn't in it, so OPF leaves its
// hostname.if alone; a rule on the device lets SSH in.
func staticOnly(devs Devices) *pf.Model {
	m := base(devs)
	m.Interfaces = []pf.Iface{
		{ID: "edge", Name: "Edge", Device: devs.Spare[0], Role: pf.RoleWAN, Enabled: true, IPv4: static("198.51.100.2", 24), IPv6: pf.IPv6None, BlockBogons: true},
		lanIface(devs),
	}
	m.Routing = pf.Routing{DefaultGateway: "gw_edge", Gateways: []pf.Gateway{{ID: "gw_edge", Name: "Edge", Iface: "edge", Address: "198.51.100.1"}}}
	m.Firewall.Rules = []pf.Rule{sshIn(nil, []string{devs.WAN})}
	return m
}

// dhcpInside has an inside network addressed by DHCP and a split-tunnel
// device, so "your networks" has a network pf works out as it loads.
func dhcpInside(devs Devices) *pf.Model {
	m := base(devs)
	m.Interfaces = append(m.Interfaces,
		pf.Iface{ID: "guest", Name: "Guest", Device: devs.Spare[0], Role: pf.RoleOPT, Enabled: true, IPv4: dhcp, IPv6: pf.IPv6None},
		pf.Iface{ID: "remote", Name: "Remote access", Device: "wg0", Role: pf.RoleVPN, Enabled: true, IPv4: static("10.8.0.1", 24), IPv6: pf.IPv6None,
			WireGuard: &pf.WireGuard{ListenPort: 51820, PublicKey: wgKey(1), Peers: []pf.Peer{
				{ID: "p1", Name: "Laptop", PublicKey: wgKey(11), Address: "10.8.0.2/32", ClientRoutes: pf.ClientRoutesSplit},
			}}},
		// The LAN leaving through a way out: what it sends to the guest
		// network, which pf learns with the lease, stays home.
		pf.Iface{ID: "provider", Name: "Provider", Device: "wg2", Role: pf.RoleVPN, Enabled: true, IPv4: static("10.66.0.2", 32), IPv6: pf.IPv6None,
			WireGuard: &pf.WireGuard{PublicKey: wgKey(3), Exit: &pf.Exit{
				PublicKey: wgKey(31), Endpoint: "192.0.2.81:51820", Keepalive: num(25), From: []string{"lan"},
			}}})
	return m
}

// routeToDHCP routes through a gateway learned by DHCP, whose address
// OPF doesn't know until the lease comes.
func routeToDHCP(devs Devices) *pf.Model {
	m := base(devs)
	m.Firewall.Rules = append(m.Firewall.Rules, form("lan-via-wan", []string{"lan"}, func(r *pf.Rule) {
		r.Family, r.Protocol, r.Port = pf.FamilyInet, pf.ProtoTCP, "443"
		r.Source, r.Gateway = ifEP("lan", pf.PartNetwork), "gw_wan"
	}))
	return m
}

// aggregateLACP has an aggr(4) of the spare ports, LACP with nothing to
// answer it, carrying an untagged network and a VLAN.
func aggregateLACP(devs Devices) *pf.Model {
	m := base(devs)
	m.Interfaces = append(m.Interfaces,
		pf.Iface{ID: "bond", Name: "Bond", Device: "aggr0", Role: pf.RoleOPT, Enabled: true, IPv4: static("172.16.6.1", 24), IPv6: pf.IPv6None, MTU: num(1400),
			Aggregate: &pf.AggregateConfig{Ports: devs.Spare[:2], LACPPassive: true, LACPFast: true}},
		pf.Iface{ID: "bond_vlan", Name: "Bond VLAN", Device: "vlan60", Role: pf.RoleOPT, Enabled: true, IPv4: static("172.16.60.1", 24), IPv6: pf.IPv6None,
			VLAN: &pf.VLANConfig{Parent: "aggr0", Tag: 60}})
	return m
}

// trunkFailover has a trunk(4) of the spare ports, failing over from the
// first.
func trunkFailover(devs Devices) *pf.Model {
	m := base(devs)
	m.Interfaces = append(m.Interfaces,
		pf.Iface{ID: "pair_link", Name: "Paired link", Device: "trunk0", Role: pf.RoleOPT, Enabled: true, IPv4: static("172.16.7.1", 24), IPv6: pf.IPv6None,
			Aggregate: &pf.AggregateConfig{Ports: devs.Spare[:2], Proto: pf.TrunkFailover}})
	return m
}

// endpoints has every kind of endpoint, with every modifier.
func endpoints(devs Devices) *pf.Model {
	m := base(devs)
	m.Firewall.Aliases = []pf.Alias{{ID: "a1", Name: "nets", Type: pf.AliasNetworks, Entries: []string{"192.0.2.0/24", "2001:db8::/32"}}}
	eps := []pf.Endpoint{
		anyEP,
		selfEP(),
		{Type: pf.EndpointSelf, Not: true},
		{Type: pf.EndpointSelf, Part: pf.PartNetwork},
		{Type: pf.EndpointSelf, NoAlias: true},
		{Type: pf.EndpointSelf, Dynamic: no()},
		{Type: pf.EndpointSelf, Dynamic: yes()},
		ifEP("lan", pf.PartAddress),
		ifEP("lan", pf.PartNetwork),
		ifEP("lan", pf.PartBroadcast),
		ifEP("wan", pf.PartPeer),
		{Type: pf.EndpointIface, Iface: "lan", Part: pf.PartNetwork, NoAlias: true},
		{Type: pf.EndpointIface, Iface: "lan", Not: true},
		{Type: pf.EndpointIface, Group: "egress"},
		{Type: pf.EndpointIface, Group: "egress", Part: pf.PartNetwork, NoAlias: true},
		{Type: pf.EndpointIface, Group: devs.LAN, Dynamic: yes()},
		hostEP("192.0.2.1"),
		hostEP("2001:db8::1"),
		{Type: pf.EndpointHost, Value: "192.0.2.2", Not: true},
		netEP("192.0.2.0/25"),
		netEP("2001:db8:1::/48"),
		{Type: pf.EndpointNetwork, Value: "192.0.2.128/25", Not: true},
		aliasEP("nets"),
		{Type: pf.EndpointAlias, Alias: "nets", Not: true},
	}
	for i, e := range eps {
		m.Firewall.Rules = append(m.Firewall.Rules,
			form(fmt.Sprintf("from-%d", i), []string{"lan"}, func(r *pf.Rule) { r.Source = e }),
			form(fmt.Sprintf("to-%d", i), []string{"lan"}, func(r *pf.Rule) { r.Direction, r.Destination = pf.DirectionOut, e }))
	}
	return m
}

// ---------- the files ----------

// Files are the files OPF writes for a model, as the appliance writes
// them: GenerateFiles's, with OPF's lines merged into the files it
// shares with the admin as live has them (rc.conf.local, sysctl.conf,
// /etc/hosts, and sshd_config when there is one), and each enabled DNS
// blocklist's zone (here from a small sample list). live maps a path to
// the file on the machine; a missing path is a machine without it.
func Files(m *pf.Model, live map[string]string) []pf.GeneratedFile {
	files := pf.GenerateFiles(m)
	for i, f := range files {
		switch f.Path {
		case pf.RcPath:
			// One it can't set its lines in is left as generated
			// (appliance's plannedLive).
			if merged, err := pf.MergeRcConfLocal(live[pf.RcPath], m); err == nil {
				files[i].Content = merged
			}
		case pf.SysctlPath:
			files[i].Content = pf.MergeSysctlConf(live[pf.SysctlPath], m)
		case pf.HostsPath:
			files[i].Content = pf.MergeHosts(live[pf.HostsPath], m)
		}
	}
	if sshd := live[pf.SshdPath]; strings.TrimSpace(sshd) != "" {
		files = append(files, pf.GeneratedFile{Path: pf.SshdPath, Content: pf.MergeSshdConfig(sshd, m)})
	}
	if m.DNS.Enabled && !pf.Unmanaged(m, pf.AreaDNS) {
		for _, l := range m.DNS.Blocklists {
			if l.Enabled {
				files = append(files, pf.GeneratedFile{
					Path:    pf.DNSListZonePath(l.ID, m.DNS.BlockAnswer),
					Content: pf.RPZZone(pf.WithApexes(sampleBlocked), pf.WithApexes(sampleAllowed), m.DNS.BlockAnswer),
				})
			}
		}
	}
	return files
}

// A downloaded list's names, as the appliance keeps them.
var (
	sampleBlocked = []string{"ads.example.com", "*.track.example.net", "Mixed.Example.ORG."}
	sampleAllowed = []string{"*.ok.example.com"}
)
