// The configuration model. This is what the appliance stores (as
// /var/opf/config.json) and generates every OpenBSD config file from.

export type Section = 'system' | 'interfaces' | 'firewall' | 'dhcp' | 'dns' | 'wireguard';

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
}

export type RuleAction = 'pass' | 'block' | 'reject';
export type Protocol = 'any' | 'tcp' | 'udp' | 'tcp/udp' | 'icmp';

export type Endpoint =
  | { type: 'any' }
  | { type: 'self' } // this firewall
  | { type: 'net'; iface: string } // "LAN network"
  | { type: 'host'; value: string }
  | { type: 'network'; value: string }
  | { type: 'alias'; alias: string };

export interface Rule {
  id: string;
  iface: string;
  enabled: boolean;
  action: RuleAction;
  protocol: Protocol;
  source: Endpoint;
  destination: Endpoint;
  port?: string; // "443", "8000-8080" or "alias:web_ports"
  log: boolean;
  description: string;
}

export interface PortForward {
  id: string;
  enabled: boolean;
  iface: string;
  protocol: 'tcp' | 'udp' | 'tcp/udp';
  externalPort: string;
  target: string;
  targetPort: string;
  description: string;
}

export interface Alias {
  id: string;
  name: string;
  type: 'hosts' | 'networks' | 'ports';
  entries: string[];
  description: string;
}

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
  registerLeases: boolean;
  overrides: HostOverride[];
}

export interface Peer {
  id: string;
  name: string;
  publicKey: string;
  address: string;
  endpoint?: string;
  keepalive?: number;
}

export interface WireGuard {
  enabled: boolean;
  listenPort: number;
  address: string; // tunnel address with prefix, e.g. 10.8.0.1/24
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
  firewall: { rules: Rule[]; forwards: PortForward[]; aliases: Alias[] };
  dhcp: DhcpScope[];
  dns: Dns;
  wireguard: WireGuard;
}

export interface Change {
  id: number;
  section: Section;
  summary: string;
}

export interface HistoryEntry {
  id: string;
  time: number;
  user: string;
  changes: Change[];
  status: 'confirmed' | 'applied' | 'reverted';
  before: Model;
  after: Model;
}
