// The configuration model. This is what the appliance stores (as
// /var/opf/config.json) and generates every OpenBSD config file from.

export type Section = 'system' | 'interfaces' | 'routing' | 'firewall' | 'dhcp' | 'dns' | 'wireguard' | 'notifications';

export type IfaceRole = 'wan' | 'lan' | 'opt' | 'vpn';

export interface Iface {
  id: string; // stable key, also used as the pf macro name
  name: string; // what people see: "WAN", "LAN", "IoT"
  device: string; // em0, vlan20, wg0
  role: IfaceRole;
  enabled: boolean;
  ipv4: { mode: 'dhcp' | 'static' | 'none'; address?: string; prefix?: number; gateway?: string };
  ipv6: 'slaac' | 'none';
  mtu?: number;
  vlan?: { parent: string; tag: number };
  blockPrivate?: boolean; // WAN only
  blockBogons?: boolean; // WAN only
  antispoof?: boolean; // pf antispoof for the interface's network; fixed addresses only
  /** LAN or optional: traffic from OPF's other networks leaving here takes this interface's address. */
  masquerade?: boolean;
  wireguard?: WireGuard; // VPN interfaces (wgN) only: each is its own tunnel
}

/** A VPN interface, with its tunnel. */
export type Tunnel = Iface & { wireguard: WireGuard };

/**
 * Where OPF meets the internet: the WAN, or without one the interface
 * its default gateway is on (OPF behind another router, as a VPN server
 * reached through a port forward).
 */
export function upstream(m: Model): Iface | undefined {
  const wan = m.interfaces.find((i) => i.enabled && i.role === 'wan');
  if (wan) return wan;
  const gw = m.routing.gateways.find((g) => g.id === m.routing.defaultGateway);
  return m.interfaces.find((i) => i.enabled && i.id === gw?.iface && i.role !== 'vpn');
}

export const tunnels = (m: Model): Tunnel[] => m.interfaces.filter((i): i is Tunnel => i.role === 'vpn' && !!i.wireguard);

// ---------- Firewall ----------

export type RuleAction = 'pass' | 'block' | 'reject' | 'match';
export type Direction = 'in' | 'out' | 'any';
export type Family = 'inet' | 'inet6' | 'any';
export type Protocol = 'any' | 'tcp' | 'udp' | 'tcp/udp' | 'icmp' | 'icmp6' | 'esp' | 'gre';

// Which of an interface's addresses an iface endpoint means; pf.conf(5)
// "interface modifiers". Undefined is the interface's own addresses.
export type IfacePart = 'network' | 'broadcast' | 'peer';

export type EndpointTarget =
  | { type: 'any' }
  | SelfEndpoint
  | IfaceEndpoint
  | { type: 'host'; value: string }
  | { type: 'network'; value: string }
  | { type: 'alias'; alias: string };

// Interface modifiers, shared by interface references and self.
export interface IfaceModifiers {
  part?: IfacePart;
  noAlias?: boolean; // :0, leave out alias addresses
  // In parentheses, so rules follow address changes. Undefined: dynamic
  // for groups and DHCP/SLAAC interfaces, fixed for static ones.
  dynamic?: boolean;
}

// An interface reference: ($lan:network), ($wan), egress:broadcast…
export interface IfaceEndpoint extends IfaceModifiers {
  type: 'iface';
  iface?: string; // a model interface id, written as $id
  group?: string; // or an interface group (egress) / unmanaged interface, written as-is
}

// Every address of this firewall; pf takes the same modifiers as for
// interfaces (self:network, (self)). Undefined dynamic follows address
// changes when any interface is addressed by DHCP or SLAAC.
export interface SelfEndpoint extends IfaceModifiers {
  type: 'self';
}

export type Endpoint = EndpointTarget & { not?: boolean };

export interface StateOptions {
  mode: 'keep' | 'modulate' | 'synproxy' | 'none';
  maxStates?: number;
  maxSrcConn?: number;
  maxSrcConnRate?: { count: number; seconds: number };
  overload?: string; // table alias to add offenders to
  flushGlobal?: boolean;
  sloppy?: boolean;
  policy?: 'if-bound' | 'floating';
}

interface RuleBase {
  id: string;
  enabled: boolean;
  // Interfaces the rule applies to. One entry puts it on that
  // interface's tab; none or several make it a floating rule.
  interfaces: string[];
  // Interface groups (egress, wg…) or unmanaged interfaces, written as-is.
  // Any groups make the rule floating.
  groups?: string[];
  description: string;
}

export type BlockReturn = 'drop' | 'return' | 'return-rst' | 'return-icmp' | 'return-icmp6';

export interface FormRule extends RuleBase {
  kind: 'form';
  action: RuleAction;
  direction: Direction;
  quick: boolean;
  family: Family;
  protocol: Protocol;
  source: Endpoint;
  sourcePort?: string; // pf port syntax: "443", "8000:8080", "> 1023", "!= 22", "alias:web"
  destination: Endpoint;
  port?: string;
  log: 'off' | 'on' | 'all';
  tcpFlags?: string; // default S/SA
  icmpType?: string;
  state?: StateOptions;
  gateway?: string; // route-to, a gateway id
  replyTo?: string; // reply-to, a gateway id
  rtable?: number;
  tag?: string;
  tagged?: string;
  prio?: number;
  osFingerprint?: string;
  probability?: number; // percent
  once?: boolean;
  // Block return options (only for action: 'block')
  blockReturn?: BlockReturn;
  returnRstTtl?: number;
  returnIcmpCode?: string;
}

// A rule written directly in pf syntax.
export interface RawRule extends RuleBase {
  kind: 'raw';
  text: string;
}

export type Rule = FormRule | RawRule;

// A rule before it has an id.
export type RuleInput = Omit<FormRule, 'id'> | Omit<RawRule, 'id'>;

export interface PortForward {
  id: string;
  enabled: boolean;
  iface: string;
  protocol: 'tcp' | 'udp' | 'tcp/udp';
  source: Endpoint; // who may use it
  externalPort: string;
  target: string;
  targetPort: string;
  reflection: boolean; // also works from inside the network
  log: boolean;
  description: string;
}

export interface NatRule {
  id: string;
  enabled: boolean;
  iface: string; // outgoing interface
  source: Endpoint;
  destination: Endpoint;
  translation: { type: 'ifaddr' } | { type: 'address'; value: string } | { type: 'none' };
  pool?: 'round-robin' | 'source-hash' | 'random';
  staticPort: boolean;
  description: string;
}

export interface Alias {
  id: string;
  name: string;
  // hosts/networks/ports: fixed lists. table: filled at runtime, e.g. by
  // overload. url: downloaded list refreshed on a schedule.
  type: 'hosts' | 'networks' | 'ports' | 'table' | 'url';
  entries: string[];
  url?: string;
  refreshHours?: number;
  description: string;
}

export interface FirewallOptions {
  blockPolicy: 'drop' | 'return';
  statePolicy: 'floating' | 'if-bound';
  optimization: 'normal' | 'high-latency' | 'satellite' | 'aggressive' | 'conservative';
  maxStates: number;
  syncookies: 'never' | 'adaptive' | 'always';
  scrub: { enabled: boolean; maxMss?: number; randomId: boolean; noDf: boolean; minTtl?: number; reassembleTcp?: boolean };
  logDefaultBlock: boolean;
  // The rest are optional: left out, pf's default applies.
  syncookiesStart?: number; // % of the state table (pf: 25)
  syncookiesEnd?: number; // (pf: 12)
  limits?: Partial<Record<'srcNodes' | 'frags' | 'tables' | 'tableEntries' | 'pktdelayPkts' | 'anchors', number>>;
  timeouts?: Record<string, number>; // by pf's name: tcp.established, adaptive.start, …
  stateDefaults?: ('no-sync' | 'pflow' | 'sloppy')[];
  reassemble?: 'yes' | 'no';
  reassembleNoDf?: boolean;
  rulesetOptimization?: 'none' | 'basic' | 'profile';
  debug?: 'emerg' | 'alert' | 'crit' | 'err' | 'warning' | 'notice' | 'info' | 'debug';
  hostId?: number;
  fingerprints?: string;
  logInterface?: string; // interface id, 'none', or unset for the WAN
  skipOn?: string[]; // interfaces or groups pf doesn't filter, besides lo
}

/** set timeout's keys, in pf.conf(5)'s order (internal/pf TimeoutNames). */
export const timeoutNames = [
  'tcp.first', 'tcp.opening', 'tcp.established', 'tcp.closing', 'tcp.finwait', 'tcp.closed', 'tcp.tsdiff',
  'udp.first', 'udp.single', 'udp.multiple', 'icmp.first', 'icmp.error', 'other.first', 'other.single', 'other.multiple',
  'frag', 'interval', 'src.track', 'adaptive.start', 'adaptive.end',
] as const;

export interface CustomPf {
  options: string; // after the set lines
  beforeFilter: string; // before generated filter rules
  afterFilter: string; // at the very end
}

export interface Firewall {
  rules: Rule[];
  forwards: PortForward[];
  outboundNat: { mode: 'auto' | 'hybrid' | 'manual'; rules: NatRule[] };
  aliases: Alias[];
  options: FirewallOptions;
  custom: CustomPf;
}

// ---------- Routing ----------

export interface Gateway {
  id: string;
  name: string;
  iface: string;
  address: string | 'dhcp';
  monitor?: string; // address to ping for health
  description: string;
}

export interface StaticRoute {
  id: string;
  enabled: boolean;
  network: string;
  gateway: string; // gateway id
  description: string;
}

export interface Routing {
  defaultGateway: string;
  gateways: Gateway[];
  routes: StaticRoute[];
}

// ---------- Services ----------

export interface Reservation {
  id: string;
  hostname: string;
  mac: string;
  ip: string;
}

export interface DhcpScope {
  iface: string;
  enabled: boolean;
  rangeStart: string;
  rangeEnd: string;
  leaseHours: number;
  dns: 'self' | 'custom';
  dnsServers: string[];
  reservations: Reservation[];
}

export interface HostOverride {
  id: string;
  host: string;
  domain: string;
  ip: string;
  description: string;
}

export type DnsRecordType = 'CNAME' | 'MX' | 'TXT' | 'SRV' | 'PTR' | 'CAA';

/**
 * A local record beyond host names. `name` is the full name without the
 * final dot, or for a PTR the address; `value` is what the type points
 * at (the alias's target, the mail server, the text, the SRV target or
 * "." for none, the PTR's name, what a CAA allows).
 */
export interface DnsRecord {
  id: string;
  name: string;
  type: DnsRecordType;
  value: string;
  /** MX preference, SRV priority. */
  priority?: number;
  weight?: number;
  port?: number;
  /** CAA: issue, issuewild or iodef. */
  tag?: string;
  /** Seconds; absent is 3600. */
  ttl?: number;
  description?: string;
}

/** How a domain answers names it has no record for: only yours (static), or yours and then the internet's (transparent). */
export interface DnsZone {
  name: string;
  type: 'static' | 'transparent';
}

export interface Dns {
  enabled: boolean;
  /** The interfaces the resolver answers on; empty, every inside one with a fixed address. */
  interfaces?: string[];
  mode: 'recursive' | 'forward';
  forwarders: string[];
  forwardTls: boolean;
  dnssec: boolean;
  /** Put each DHCP reservation's name in DNS. */
  registerReservations: boolean;
  /** Also register the names devices ask for with dynamic leases. */
  registerDynamicLeases: boolean;
  /** Turn names that aren't valid ("Priya's iPad") into valid ones instead of refusing them. */
  rewriteInvalidLeaseNames: boolean;
  overrides: HostOverride[];
  records?: DnsRecord[];
  /** The system's domain is static unless listed here. */
  zones?: DnsZone[];
  /** Lists of names to block, downloaded and loaded into unbound as response policy zones. */
  blocklists?: DnsBlocklist[];
  /** Your own names, exact or "*.name" (the name and everything under it). Allowed wins over every list. */
  blocked?: string[];
  allowed?: string[];
  /** How a blocked name is answered: 0.0.0.0 and :: (the default, as Pi-hole does) or "no such name". */
  blockAnswer?: '' | 'nxdomain';
}

export interface DnsBlocklist {
  id: string;
  name: string;
  url: string;
  enabled: boolean;
  /** How often it's downloaded again; 24 when unset. */
  refreshHours?: number;
}

export interface Peer {
  id: string;
  name: string;
  publicKey: string;
  address: string; // the peer's tunnel address, /32
  networks: string[]; // networks behind the peer, routed into the tunnel
  endpoint?: string;
  keepalive?: number;
  clientRoutes: 'split' | 'vpn' | 'full' | 'site'; // what the peer sends through the tunnel; vpn: only the tunnel, and kept to it
  /** The id of a preshared key it shares with the tunnel, kept on the firewall; never the key. */
  presharedKey?: string;
}

// A tunnel's settings. Its address and whether it's up are its
// interface's.
export interface WireGuard {
  listenPort: number;
  publicKey: string;
  /** Where devices reach the tunnel, host or host:port, through a router's port forward; empty uses the WAN's address. */
  publicEndpoint?: string;
  /** LAN or optional interfaces whose networks may start connections to the tunnel's devices, translated to OPF's tunnel address. */
  reachableFrom?: string[];
  peers: Peer[];
  /** A way out rather than in: OPF is a client of a VPN provider, and the networks in from leave through it. */
  exit?: Exit;
}

/** A tunnel to a VPN provider that some networks leave through, appearing at the provider's address. */
export interface Exit {
  /** The provider's end. */
  publicKey: string;
  endpoint: string;
  presharedKey?: string;
  keepalive?: number;
  /** LAN or optional interfaces whose networks leave through it. */
  from: string[];
  /** The provider's resolvers: OPF's resolver asks them, through the tunnel. */
  dns?: string[];
}

export interface SystemSettings {
  hostname: string;
  domain: string;
  timezone: string;
  ntpServers: string[];
  /** How many of each thing the graphs keep a history of; unset, OPF's default, and 0 keeps none. */
  graphs?: GraphLimits;
}

export interface GraphLimits {
  interfaces?: number;
  gateways?: number;
  vpnDevices?: number;
  dhcpNetworks?: number;
  rules?: number;
}

/** Where OPF sends its events. A webhook's URL and key are secrets, not in the model (PUT /api/webhooks/{id}/secret). */
export interface Webhook {
  id: string;
  name: string;
  enabled: boolean;
  /** The kinds of event it gets; none, all. */
  kinds?: string[];
  problemsOnly?: boolean;
  /** How events are sent: OPF's JSON (absent), or as Slack, Discord or ntfy messages. */
  format?: 'slack' | 'discord' | 'ntfy';
}

export interface Model {
  notifications?: { webhooks: Webhook[] };
  system: SystemSettings;
  interfaces: Iface[];
  routing: Routing;
  firewall: Firewall;
  dhcp: DhcpScope[];
  dns: Dns;
}

export interface Change {
  id: number;
  section: Section;
  summary: string;
  /** The section as this change left it, to notice a later change undoing it. */
  after?: string;
}

export interface HistoryEntry {
  id: string;
  time: number;
  status: 'applying' | 'pending' | 'applied' | 'confirmed' | 'reverted' | 'failed';
  message: string;
  author?: string;
  changes: Change[];
}
