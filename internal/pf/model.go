// Package pf provides parsing and generation of pf.conf and related
// OpenBSD configuration files from the OPF model.
package pf

// Model is the top-level configuration. This matches the TypeScript
// Model type in ui/src/model/types.ts and is stored as /var/opf/config.json.
type Model struct {
	System     SystemSettings `json:"system"`
	Interfaces []Iface        `json:"interfaces"`
	Routing    Routing        `json:"routing"`
	Firewall   Firewall       `json:"firewall"`
	DHCP       []DHCPScope    `json:"dhcp"`
	DNS        DNS            `json:"dns"`
}

type SystemSettings struct {
	Hostname   string   `json:"hostname"`
	Domain     string   `json:"domain"`
	Timezone   string   `json:"timezone"`
	NTPServers []string `json:"ntpServers"`
}

type IfaceRole string

const (
	RoleWAN IfaceRole = "wan"
	RoleLAN IfaceRole = "lan"
	RoleOPT IfaceRole = "opt"
	RoleVPN IfaceRole = "vpn"
)

type IPv4Mode string

const (
	IPv4DHCP   IPv4Mode = "dhcp"
	IPv4Static IPv4Mode = "static"
	IPv4None   IPv4Mode = "none"
)

type IPv4Config struct {
	Mode    IPv4Mode `json:"mode"`
	Address string   `json:"address,omitempty"`
	Prefix  *int     `json:"prefix,omitempty"`
	Gateway string   `json:"gateway,omitempty"`
}

type IPv6Mode string

const (
	IPv6SLAAC IPv6Mode = "slaac"
	IPv6None  IPv6Mode = "none"
)

type VLANConfig struct {
	Parent string `json:"parent"`
	Tag    int    `json:"tag"`
}

type Iface struct {
	ID           string      `json:"id"`
	Name         string      `json:"name"`
	Device       string      `json:"device"`
	Role         IfaceRole   `json:"role"`
	Enabled      bool        `json:"enabled"`
	IPv4         IPv4Config  `json:"ipv4"`
	IPv6         IPv6Mode    `json:"ipv6"`
	MTU          *int        `json:"mtu,omitempty"`
	VLAN         *VLANConfig `json:"vlan,omitempty"`
	BlockPrivate bool        `json:"blockPrivate,omitempty"`
	BlockBogons  bool        `json:"blockBogons,omitempty"`
	// WireGuard is set on every VPN interface (role vpn, device wgN):
	// each is its own tunnel.
	WireGuard *WireGuard `json:"wireguard,omitempty"`
}

// ---------- Firewall ----------

type RuleAction string

const (
	ActionPass   RuleAction = "pass"
	ActionBlock  RuleAction = "block"
	ActionReject RuleAction = "reject"
	ActionMatch  RuleAction = "match"
)

type Direction string

const (
	DirectionIn  Direction = "in"
	DirectionOut Direction = "out"
	DirectionAny Direction = "any"
)

type Family string

const (
	FamilyInet  Family = "inet"
	FamilyInet6 Family = "inet6"
	FamilyAny   Family = "any"
)

type Protocol string

const (
	ProtoAny    Protocol = "any"
	ProtoTCP    Protocol = "tcp"
	ProtoUDP    Protocol = "udp"
	ProtoTCPUDP Protocol = "tcp/udp"
	ProtoICMP   Protocol = "icmp"
	ProtoICMP6  Protocol = "icmp6"
	ProtoESP    Protocol = "esp"
	ProtoGRE    Protocol = "gre"
)

type EndpointType string

const (
	EndpointAny     EndpointType = "any"
	EndpointSelf    EndpointType = "self"
	EndpointIface   EndpointType = "iface" // an interface's addresses or networks; see Endpoint
	EndpointHost    EndpointType = "host"
	EndpointNetwork EndpointType = "network"
	EndpointAlias   EndpointType = "alias"
)

// IfacePart is the interface modifier: which of an interface's
// addresses an iface endpoint means (pf.conf(5), "Interface names …
// can have modifiers appended").
type IfacePart string

const (
	PartAddress   IfacePart = ""          // the interface's own addresses
	PartNetwork   IfacePart = "network"   // :network, the attached networks
	PartBroadcast IfacePart = "broadcast" // :broadcast
	PartPeer      IfacePart = "peer"      // :peer, for point-to-point links
)

type Endpoint struct {
	Type EndpointType `json:"type"`
	Not  bool         `json:"not,omitempty"`

	// For iface, exactly one of Iface, a model interface id written as
	// $id, and Group, an interface group such as egress (or an interface
	// OPF doesn't manage) written as-is. Part, NoAlias and Dynamic also
	// apply to self, which pf treats like an interface name.
	Iface   string    `json:"iface,omitempty"`
	Group   string    `json:"group,omitempty"`
	Part    IfacePart `json:"part,omitempty"`
	NoAlias bool      `json:"noAlias,omitempty"` // :0, leave out alias addresses
	// Dynamic puts the reference in parentheses, so pf follows address
	// changes without a ruleset reload. Nil lets the generator choose:
	// dynamic for groups and for interfaces addressed by DHCP or SLAAC.
	Dynamic *bool `json:"dynamic,omitempty"`

	Value string `json:"value,omitempty"` // for host, network
	Alias string `json:"alias,omitempty"` // for alias
}

type StateMode string

const (
	StateModeKeep     StateMode = "keep"
	StateModeModulate StateMode = "modulate"
	StateModeSynproxy StateMode = "synproxy"
	StateModeNone     StateMode = "none"
)

type StatePolicy string

const (
	StatePolicyIfBound  StatePolicy = "if-bound"
	StatePolicyFloating StatePolicy = "floating"
)

type SrcConnRate struct {
	Count   int `json:"count"`
	Seconds int `json:"seconds"`
}

type StateOptions struct {
	Mode           StateMode    `json:"mode"`
	MaxStates      *int         `json:"maxStates,omitempty"`
	MaxSrcConn     *int         `json:"maxSrcConn,omitempty"`
	MaxSrcConnRate *SrcConnRate `json:"maxSrcConnRate,omitempty"`
	Overload       string       `json:"overload,omitempty"`
	FlushGlobal    bool         `json:"flushGlobal,omitempty"`
	Sloppy         bool         `json:"sloppy,omitempty"`
	Policy         StatePolicy  `json:"policy,omitempty"`
}

type LogMode string

const (
	LogOff LogMode = "off"
	LogOn  LogMode = "on"
	LogAll LogMode = "all"
)

type BlockReturn string

const (
	BlockReturnDrop   BlockReturn = "drop"
	BlockReturnReturn BlockReturn = "return"
	BlockReturnRST    BlockReturn = "return-rst"
	BlockReturnICMP   BlockReturn = "return-icmp"
	BlockReturnICMP6  BlockReturn = "return-icmp6"
)

// Rule is either a FormRule or a RawRule. Use the Kind field to
// determine which fields are valid.
type Rule struct {
	// Common fields
	ID         string   `json:"id"`
	Kind       string   `json:"kind"` // "form" or "raw"
	Enabled    bool     `json:"enabled"`
	Interfaces []string `json:"interfaces"`
	// Groups are interface groups (egress, wg, …) or interfaces OPF
	// doesn't manage, written into the "on" clause as-is. A rule with
	// any groups is a floating rule.
	Groups      []string `json:"groups,omitempty"`
	Description string   `json:"description"`

	// RawRule fields
	Text string `json:"text,omitempty"`

	// FormRule fields
	Action         RuleAction    `json:"action,omitempty"`
	Direction      Direction     `json:"direction,omitempty"`
	Quick          bool          `json:"quick,omitempty"`
	Family         Family        `json:"family,omitempty"`
	Protocol       Protocol      `json:"protocol,omitempty"`
	Source         Endpoint      `json:"source,omitzero"`
	SourcePort     string        `json:"sourcePort,omitempty"`
	Destination    Endpoint      `json:"destination,omitzero"`
	Port           string        `json:"port,omitempty"`
	Log            LogMode       `json:"log,omitempty"`
	TCPFlags       string        `json:"tcpFlags,omitempty"`
	ICMPType       string        `json:"icmpType,omitempty"`
	State          *StateOptions `json:"state,omitempty"`
	Gateway        string        `json:"gateway,omitempty"`
	ReplyTo        string        `json:"replyTo,omitempty"`
	RTable         *int          `json:"rtable,omitempty"`
	Tag            string        `json:"tag,omitempty"`
	Tagged         string        `json:"tagged,omitempty"`
	Prio           *int          `json:"prio,omitempty"`
	OSFingerprint  string        `json:"osFingerprint,omitempty"`
	Probability    *int          `json:"probability,omitempty"`
	Once           bool          `json:"once,omitempty"`
	BlockReturn    BlockReturn   `json:"blockReturn,omitempty"`
	ReturnRstTTL   *int          `json:"returnRstTtl,omitempty"`
	ReturnICMPCode string        `json:"returnIcmpCode,omitempty"`
}

// IsForm returns true if this is a FormRule.
func (r *Rule) IsForm() bool {
	return r.Kind == "form"
}

// IsRaw returns true if this is a RawRule.
func (r *Rule) IsRaw() bool {
	return r.Kind == "raw"
}

type PortForward struct {
	ID           string   `json:"id"`
	Enabled      bool     `json:"enabled"`
	Iface        string   `json:"iface"`
	Protocol     Protocol `json:"protocol"`
	Source       Endpoint `json:"source"`
	ExternalPort string   `json:"externalPort"`
	Target       string   `json:"target"`
	TargetPort   string   `json:"targetPort"`
	Reflection   bool     `json:"reflection"`
	Log          bool     `json:"log"`
	Description  string   `json:"description"`
}

type TranslationType string

const (
	TranslationIfaddr  TranslationType = "ifaddr"
	TranslationAddress TranslationType = "address"
	TranslationNone    TranslationType = "none"
)

type Translation struct {
	Type  TranslationType `json:"type"`
	Value string          `json:"value,omitempty"`
}

type PoolMode string

const (
	PoolRoundRobin PoolMode = "round-robin"
	PoolSourceHash PoolMode = "source-hash"
	PoolRandom     PoolMode = "random"
)

type NATRule struct {
	ID          string      `json:"id"`
	Enabled     bool        `json:"enabled"`
	Iface       string      `json:"iface"`
	Source      Endpoint    `json:"source"`
	Destination Endpoint    `json:"destination"`
	Translation Translation `json:"translation"`
	Pool        PoolMode    `json:"pool,omitempty"`
	StaticPort  bool        `json:"staticPort"`
	Description string      `json:"description"`
}

type NATMode string

const (
	NATModeAuto   NATMode = "auto"
	NATModeHybrid NATMode = "hybrid"
	NATModeManual NATMode = "manual"
)

type OutboundNAT struct {
	Mode  NATMode   `json:"mode"`
	Rules []NATRule `json:"rules"`
}

type AliasType string

const (
	AliasHosts    AliasType = "hosts"
	AliasNetworks AliasType = "networks"
	AliasPorts    AliasType = "ports"
	AliasTable    AliasType = "table"
	AliasURL      AliasType = "url"
)

type Alias struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Type         AliasType `json:"type"`
	Entries      []string  `json:"entries"`
	URL          string    `json:"url,omitempty"`
	RefreshHours *int      `json:"refreshHours,omitempty"`
	Description  string    `json:"description"`
}

type BlockPolicy string

const (
	BlockPolicyDrop   BlockPolicy = "drop"
	BlockPolicyReturn BlockPolicy = "return"
)

type StatePolicyOption string

const (
	StatePolicyOptionFloating StatePolicyOption = "floating"
	StatePolicyOptionIfBound  StatePolicyOption = "if-bound"
)

type Optimization string

const (
	OptNormal       Optimization = "normal"
	OptHighLatency  Optimization = "high-latency"
	OptSatellite    Optimization = "satellite"
	OptAggressive   Optimization = "aggressive"
	OptConservative Optimization = "conservative"
)

type Syncookies string

const (
	SyncookiesNever    Syncookies = "never"
	SyncookiesAdaptive Syncookies = "adaptive"
	SyncookiesAlways   Syncookies = "always"
)

type ScrubOptions struct {
	Enabled  bool `json:"enabled"`
	MaxMss   *int `json:"maxMss,omitempty"`
	RandomID bool `json:"randomId"`
	NoDf     bool `json:"noDf"`
}

type FirewallOptions struct {
	BlockPolicy     BlockPolicy       `json:"blockPolicy"`
	StatePolicy     StatePolicyOption `json:"statePolicy"`
	Optimization    Optimization      `json:"optimization"`
	MaxStates       int               `json:"maxStates"`
	Syncookies      Syncookies        `json:"syncookies"`
	Scrub           ScrubOptions      `json:"scrub"`
	LogDefaultBlock bool              `json:"logDefaultBlock"`
}

type CustomPf struct {
	Options      string `json:"options"`
	BeforeFilter string `json:"beforeFilter"`
	AfterFilter  string `json:"afterFilter"`
}

type Firewall struct {
	Rules       []Rule          `json:"rules"`
	Forwards    []PortForward   `json:"forwards"`
	OutboundNAT OutboundNAT     `json:"outboundNat"`
	Aliases     []Alias         `json:"aliases"`
	Options     FirewallOptions `json:"options"`
	Custom      CustomPf        `json:"custom"`
}

// ---------- Routing ----------

type Gateway struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Iface       string `json:"iface"`
	Address     string `json:"address"` // "dhcp" or an IP
	Monitor     string `json:"monitor,omitempty"`
	Description string `json:"description"`
}

type StaticRoute struct {
	ID          string `json:"id"`
	Enabled     bool   `json:"enabled"`
	Network     string `json:"network"`
	Gateway     string `json:"gateway"` // gateway id
	Description string `json:"description"`
}

type Routing struct {
	DefaultGateway string        `json:"defaultGateway"`
	Gateways       []Gateway     `json:"gateways"`
	Routes         []StaticRoute `json:"routes"`
}

// ---------- Services ----------

type Reservation struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
	MAC      string `json:"mac"`
	IP       string `json:"ip"`
}

type DNSMode string

const (
	DNSModeSelf   DNSMode = "self"
	DNSModeCustom DNSMode = "custom"
)

type DHCPScope struct {
	Iface        string        `json:"iface"`
	Enabled      bool          `json:"enabled"`
	RangeStart   string        `json:"rangeStart"`
	RangeEnd     string        `json:"rangeEnd"`
	LeaseHours   int           `json:"leaseHours"`
	DNS          DNSMode       `json:"dns"`
	DNSServers   []string      `json:"dnsServers"`
	Reservations []Reservation `json:"reservations"`
}

type HostOverride struct {
	ID          string `json:"id"`
	Host        string `json:"host"`
	Domain      string `json:"domain"`
	IP          string `json:"ip"`
	Description string `json:"description"`
}

type ResolverMode string

const (
	ResolverModeRecursive ResolverMode = "recursive"
	ResolverModeForward   ResolverMode = "forward"
)

type DNS struct {
	Enabled    bool         `json:"enabled"`
	Mode       ResolverMode `json:"mode"`
	Forwarders []string     `json:"forwarders"`
	ForwardTLS bool         `json:"forwardTls"`
	DNSSEC     bool         `json:"dnssec"`
	// RegisterReservations puts each DHCP reservation's name in DNS.
	RegisterReservations bool `json:"registerReservations"`
	// RegisterDynamicLeases also registers the names clients ask for
	// with dynamic leases (package leases), at runtime through
	// unbound-control.
	RegisterDynamicLeases bool           `json:"registerDynamicLeases"`
	Overrides             []HostOverride `json:"overrides"`
}

type ClientRoutes string

const (
	ClientRoutesSplit ClientRoutes = "split"
	ClientRoutesFull  ClientRoutes = "full"
	ClientRoutesSite  ClientRoutes = "site"
)

type Peer struct {
	ID           string       `json:"id"`
	Name         string       `json:"name"`
	PublicKey    string       `json:"publicKey"`
	Address      string       `json:"address"`
	Networks     []string     `json:"networks"`
	Endpoint     string       `json:"endpoint,omitempty"`
	Keepalive    *int         `json:"keepalive,omitempty"`
	ClientRoutes ClientRoutes `json:"clientRoutes"`
}

// WireGuard is one tunnel, what its interface's hostname.wgN sets up.
// The tunnel's address and whether it's up are the interface's.
type WireGuard struct {
	ListenPort int    `json:"listenPort"`
	PublicKey  string `json:"publicKey"`
	Peers      []Peer `json:"peers"`
}

// Tunnels returns the VPN interfaces, each with its WireGuard settings.
func (m *Model) Tunnels() []*Iface {
	var out []*Iface
	for i := range m.Interfaces {
		if m.Interfaces[i].Role == RoleVPN && m.Interfaces[i].WireGuard != nil {
			out = append(out, &m.Interfaces[i])
		}
	}
	return out
}

// ---------- Parse Results ----------

type ParseError struct {
	Line    int    `json:"line"`
	Column  int    `json:"column"`
	Message string `json:"message"`
}

type Warning struct {
	Line    int    `json:"line"`
	Message string `json:"message"`
}

type ParseResult struct {
	Rules    []Rule       `json:"rules"`
	Errors   []ParseError `json:"errors"`
	Warnings []Warning    `json:"warnings"`
}

// ---------- Generation ----------

// Origin tracks where a generated line came from.
type Origin struct {
	Label string `json:"label"`
	To    string `json:"to"`
}

// PfLine is a single line of generated pf.conf with optional origin.
type PfLine struct {
	Text   string  `json:"text"`
	Origin *Origin `json:"origin,omitempty"`
}

// GeneratedFile is a config file produced from the model.
type GeneratedFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// hasInterface reports whether id is a model interface.
func (m *Model) hasInterface(id string) bool {
	for _, i := range m.Interfaces {
		if i.ID == id {
			return true
		}
	}
	return false
}

// deviceID returns the id of the model interface for a device such as
// em0, or "".
func (m *Model) deviceID(device string) string {
	for _, i := range m.Interfaces {
		if i.Device == device {
			return i.ID
		}
	}
	return ""
}
