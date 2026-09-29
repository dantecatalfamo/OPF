// The configuration model. This is what the appliance stores (as
// /var/opf/config.json) and generates every OpenBSD config file from.

export type Section = 'system' | 'interfaces' | 'routing' | 'firewall' | 'dhcp' | 'dns' | 'wireguard';

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
  wireguard?: WireGuard; // VPN interfaces (wgN) only: each is its own tunnel
}

/** A VPN interface, with its tunnel. */
export type Tunnel = Iface & { wireguard: WireGuard };

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

// An interface reference: $lan:network, ($wan), (egress:network:0)…
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

export interface Dns {
  enabled: boolean;
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
}

export interface Peer {
  id: string;
  name: string;
  publicKey: string;
  address: string; // the peer's tunnel address, /32
  networks: string[]; // networks behind the peer, routed into the tunnel
  endpoint?: string;
  keepalive?: number;
  clientRoutes: 'split' | 'full' | 'site'; // what the peer sends through the tunnel
}

// A tunnel's settings. Its address and whether it's up are its
// interface's.
export interface WireGuard {
  listenPort: number;
  publicKey: string;
  peers: Peer[];
}

export interface SystemSettings {
  hostname: string;
  domain: string;
  timezone: string;
  ntpServers: string[];
}

export interface Model {
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
}

export interface HistoryEntry {
  id: string;
  time: number;
  status: 'applying' | 'pending' | 'applied' | 'confirmed' | 'reverted' | 'failed';
  message: string;
  changes: Change[];
}
