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
	// Notifications are where OPF sends its events; absent, nowhere.
	Notifications *Notifications `json:"notifications,omitempty"`
}

// Notifications are the webhooks OPF sends events to.
type Notifications struct {
	Webhooks []Webhook `json:"webhooks"`
}

// Webhook is where to send events and which. Its URL and signing key
// aren't here: they're secrets, kept apart from the model so they're
// never in an API answer, the history or its diffs (appliance's
// webhook secrets).
type Webhook struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	// Kinds are the kinds of event it gets (EventKinds); none, all.
	Kinds []string `json:"kinds,omitempty"`
	// ProblemsOnly sends only events that are something going wrong.
	ProblemsOnly bool `json:"problemsOnly,omitempty"`
	// Format is how an event is sent: WebhookJSON (the default), or as
	// a message for Slack, Discord or ntfy.
	Format string `json:"format,omitempty"`
}

// Webhook formats.
const (
	WebhookJSON    = ""
	WebhookSlack   = "slack"
	WebhookDiscord = "discord"
	WebhookNtfy    = "ntfy"
)

// EventKinds are the kinds of event OPF records (appliance's Event).
var EventKinds = []string{"opf", "link", "address", "gateway", "device", "vpn", "service", "list", "updates", "commit", "login"}

// MaxWebhooks bounds Notifications.Webhooks.
const MaxWebhooks = 16

type SystemSettings struct {
	Hostname   string   `json:"hostname"`
	Domain     string   `json:"domain"`
	Timezone   string   `json:"timezone"`
	NTPServers []string `json:"ntpServers"`
	// Graphs caps how many of each thing the graphs keep a history of;
	// unset, OPF's defaults (appliance.GraphDefaults).
	Graphs *GraphLimits `json:"graphs,omitempty"`
}

// GraphLimits are how many interfaces, gateways, VPN devices, DHCP
// networks and firewall rules the graphs keep; each unset one is the
// default, and 0 keeps none. More costs memory, which System › General
// shows.
type GraphLimits struct {
	Interfaces   *int `json:"interfaces,omitempty"`
	Gateways     *int `json:"gateways,omitempty"`
	VPNDevices   *int `json:"vpnDevices,omitempty"`
	DHCPNetworks *int `json:"dhcpNetworks,omitempty"`
	Rules        *int `json:"rules,omitempty"`
}

// MaxGraphItems bounds each of GraphLimits.
const MaxGraphItems = 10000

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
	// Antispoof blocks traffic claiming to come from this interface's
	// network arriving anywhere else (pf's antispoof).
	Antispoof bool `json:"antispoof,omitempty"`
	// Masquerade, on a LAN or optional interface: traffic from OPF's
	// other networks (VPN devices, say) leaving through it takes its
	// address, for a network whose router doesn't know OPF's other
	// networks: OPF behind an existing router, as a VPN server reached
	// through a port forward. A WAN always does this.
	Masquerade bool `json:"masquerade,omitempty"`
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
	// dynamic for interfaces and groups; self only when an interface's
	// addresses can change.
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
	Enabled       bool `json:"enabled"`
	MaxMss        *int `json:"maxMss,omitempty"`
	RandomID      bool `json:"randomId"`
	NoDf          bool `json:"noDf"`
	MinTTL        *int `json:"minTtl,omitempty"`
	ReassembleTCP bool `json:"reassembleTcp,omitempty"`
}

// FirewallOptions are pf.conf(5)'s "set" options. For every optional
// one, leaving it out means pf's own default.
type FirewallOptions struct {
	BlockPolicy     BlockPolicy       `json:"blockPolicy"`
	StatePolicy     StatePolicyOption `json:"statePolicy"`
	Optimization    Optimization      `json:"optimization"`
	MaxStates       int               `json:"maxStates"`
	Syncookies      Syncookies        `json:"syncookies"`
	Scrub           ScrubOptions      `json:"scrub"`
	LogDefaultBlock bool              `json:"logDefaultBlock"`

	// SyncookiesStart and SyncookiesEnd are adaptive syncookies'
	// thresholds, as percentages of the state table (pf: 25 and 12).
	SyncookiesStart *int `json:"syncookiesStart,omitempty"`
	SyncookiesEnd   *int `json:"syncookiesEnd,omitempty"`
	// Limits are the other `set limit` values (MaxStates is states).
	Limits Limits `json:"limits,omitzero"`
	// Timeouts are `set timeout` values by pf's name for them
	// (tcp.established, adaptive.start, …); see TimeoutNames.
	Timeouts map[string]int `json:"timeouts,omitempty"`
	// StateDefaults are state options every rule gets (set
	// state-defaults): see StateDefaultNames.
	StateDefaults []string `json:"stateDefaults,omitempty"`
	// Reassemble is "yes" or "no" (set reassemble); ReassembleNoDf
	// also clears the don't-fragment bit of reassembled packets.
	Reassemble     string `json:"reassemble,omitempty"`
	ReassembleNoDf bool   `json:"reassembleNoDf,omitempty"`
	// RulesetOptimization is none, basic or profile.
	RulesetOptimization string `json:"rulesetOptimization,omitempty"`
	// Debug is the level pf logs at: emerg … debug.
	Debug string `json:"debug,omitempty"`
	// HostID identifies this firewall to pfsync (set hostid).
	HostID *uint32 `json:"hostId,omitempty"`
	// Fingerprints is the OS fingerprint file (pf: /etc/pf.os).
	Fingerprints string `json:"fingerprints,omitempty"`
	// LogInterface is the interface pf keeps statistics for: an
	// interface id, "none", or empty for the WAN.
	LogInterface string `json:"logInterface,omitempty"`
	// SkipOn are interfaces or groups pf doesn't filter at all, besides
	// lo. Anything listed here is wide open.
	SkipOn []string `json:"skipOn,omitempty"`
}

// Limits are `set limit` values; nil is pf's default.
type Limits struct {
	SrcNodes     *int `json:"srcNodes,omitempty"`
	Frags        *int `json:"frags,omitempty"`
	Tables       *int `json:"tables,omitempty"`
	TableEntries *int `json:"tableEntries,omitempty"`
	PktdelayPkts *int `json:"pktdelayPkts,omitempty"`
	Anchors      *int `json:"anchors,omitempty"`
}

// TimeoutNames are `set timeout`'s keys, in pf.conf(5)'s order.
// adaptive.start and adaptive.end are state counts; the rest seconds.
var TimeoutNames = []string{
	"tcp.first", "tcp.opening", "tcp.established", "tcp.closing", "tcp.finwait", "tcp.closed", "tcp.tsdiff",
	"udp.first", "udp.single", "udp.multiple",
	"icmp.first", "icmp.error",
	"other.first", "other.single", "other.multiple",
	"frag", "interval", "src.track",
	"adaptive.start", "adaptive.end",
}

// StateDefaultNames are the state options set state-defaults may hold.
var StateDefaultNames = []string{"no-sync", "pflow", "sloppy"}

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
	RegisterDynamicLeases bool `json:"registerDynamicLeases"`
	// RewriteInvalidLeaseNames turns a dynamic lease's hostname that
	// isn't a valid DNS label into one ("Priya's iPad" → priyas-ipad);
	// off, such leases get no name. It's meant to be on by default, but
	// a model that leaves it out has it off, so anything that creates a
	// model (the sample, import, the first-run wizard) must set it.
	RewriteInvalidLeaseNames bool           `json:"rewriteInvalidLeaseNames"`
	Overrides                []HostOverride `json:"overrides"`
	// Records are the other local records: aliases, mail servers, text
	// and the rest (see dnsrecords.go). Zones say how a domain answers
	// names without one.
	Records []DNSRecord `json:"records,omitempty"`
	Zones   []DNSZone   `json:"zones,omitempty"`

	// Blocklists are lists of names to block (ads, trackers), downloaded
	// by OPF and loaded into unbound as response policy zones.
	Blocklists []DNSBlocklist `json:"blocklists,omitempty"`
	// Blocked and Allowed are names of your own, exact ("ads.example.com")
	// or with everything under them ("*.example.com"). Allowed wins over
	// every list; Blocked is blocked whatever the lists say.
	Blocked []string `json:"blocked,omitempty"`
	Allowed []string `json:"allowed,omitempty"`
	// BlockAnswer is how a blocked name is answered: "" (0.0.0.0 and
	// ::, as Pi-hole does, since some apps retry harder or change
	// resolver on NXDOMAIN) or "nxdomain" (no such name).
	BlockAnswer BlockAnswer `json:"blockAnswer,omitempty"`
}

// DNSBlocklist is a list of names the resolver blocks, in any of the
// formats DNS blockers use: hosts files, plain names, the domain rules
// of adblock lists, or RPZ zones.
type DNSBlocklist struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	URL     string `json:"url"`
	Enabled bool   `json:"enabled"`
	// RefreshHours is how often it's downloaded again; nil is 24.
	RefreshHours *int `json:"refreshHours,omitempty"`
}

type BlockAnswer string

const (
	BlockAnswerNull     BlockAnswer = ""
	BlockAnswerNXDomain BlockAnswer = "nxdomain"
)

type ClientRoutes string

const (
	ClientRoutesSplit ClientRoutes = "split"
	ClientRoutesFull  ClientRoutes = "full"
	ClientRoutesSite  ClientRoutes = "site"
	// ClientRoutesVPN keeps the device to its tunnel: it reaches the
	// tunnel's network, and of OPF only DNS there, whatever rules or its
	// own configuration say; its configuration routes only the tunnel.
	ClientRoutesVPN ClientRoutes = "vpn"
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
	// PresharedKey names the preshared key the device and the tunnel
	// share too (wgpsk), when they do: an id for its file (WGPSKPath),
	// never the key. A new key gets a new id, so a revert finds the old.
	PresharedKey string `json:"presharedKey,omitempty"`
}

// WireGuard is one tunnel, what its interface's hostname.wgN sets up.
// The tunnel's address and whether it's up are the interface's.
type WireGuard struct {
	ListenPort int    `json:"listenPort"`
	PublicKey  string `json:"publicKey"`
	// PublicEndpoint is where devices reach the tunnel, as host or
	// host:port: a name or address, through a router's port forward
	// when OPF is behind one. Empty, devices' configurations use the
	// WAN's address and ListenPort.
	PublicEndpoint string `json:"publicEndpoint,omitempty"`
	// ReachableFrom lists interfaces (LAN or optional) whose networks
	// may start connections to the tunnel's devices: OPF translates them
	// to its own address on the tunnel, so a device that only routes the
	// tunnel (and only accepts packets from it) can answer. The networks
	// behind its site-to-site peers aren't included: they're routed with
	// their real addresses. Behind another router, that router needs a
	// route to the tunnel through OPF.
	ReachableFrom []string `json:"reachableFrom,omitempty"`
	Peers         []Peer   `json:"peers"`
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
