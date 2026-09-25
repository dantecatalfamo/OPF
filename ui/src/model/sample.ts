// Example data for the preview build: a small office gateway. None of
// this is anyone's real configuration.
import type { FormRule, HistoryEntry, Model } from './types';

export function formRule(r: Partial<FormRule> & Pick<FormRule, 'id' | 'interfaces' | 'description'>): FormRule {
  return {
    kind: 'form', enabled: true, action: 'pass', direction: 'in', quick: true, family: 'inet', protocol: 'any',
    source: { type: 'any' }, destination: { type: 'any' }, log: 'off', ...r,
  };
}

export const sampleModel: Model = {
  system: {
    hostname: 'gw',
    domain: 'office.arpa',
    timezone: 'America/New_York',
    ntpServers: ['pool.ntp.org'],
  },
  interfaces: [
    { id: 'wan', name: 'WAN', device: 'em0', role: 'wan', enabled: true, ipv4: { mode: 'dhcp' }, ipv6: 'slaac', blockPrivate: true, blockBogons: true },
    { id: 'lan', name: 'LAN', device: 'em1', role: 'lan', enabled: true, ipv4: { mode: 'static', address: '192.168.1.1', prefix: 24 }, ipv6: 'none' },
    { id: 'iot', name: 'IoT', device: 'vlan20', role: 'opt', enabled: true, ipv4: { mode: 'static', address: '192.168.20.1', prefix: 24 }, ipv6: 'none', vlan: { parent: 'em1', tag: 20 } },
    { id: 'wg', name: 'WireGuard', device: 'wg0', role: 'vpn', enabled: true, ipv4: { mode: 'static', address: '10.8.0.1', prefix: 24 }, ipv6: 'none' },
  ],
  routing: {
    defaultGateway: 'gw_wan',
    gateways: [
      { id: 'gw_wan', name: 'WAN_DHCP', iface: 'wan', address: 'dhcp', monitor: '9.9.9.9', description: 'Provided by the ISP' },
      { id: 'gw_wh', name: 'WAREHOUSE', iface: 'wg', address: '10.8.0.10', monitor: '10.20.0.1', description: 'Warehouse router over WireGuard' },
    ],
    routes: [
      { id: 'rt1', enabled: true, network: '10.20.0.0/16', gateway: 'gw_wh', description: 'Warehouse LAN' },
    ],
  },
  firewall: {
    rules: [
      formRule({
        id: 'r10', interfaces: [], action: 'block', source: { type: 'alias', alias: 'bruteforce' }, log: 'on',
        description: 'Drop hosts caught brute-forcing SSH',
      }),
      {
        id: 'r11', kind: 'raw', enabled: true, interfaces: [],
        text: 'match out on egress proto udp from 192.168.1.60 to any port 5060 set prio 6',
        description: 'Give the desk phone’s calls priority',
      },
      formRule({ id: 'r1', interfaces: ['wan'], protocol: 'udp', destination: { type: 'self' }, port: '51820', description: 'Allow WireGuard clients' }),
      formRule({
        id: 'r9', interfaces: ['wan'], protocol: 'tcp', destination: { type: 'ifaddr', iface: 'wan' }, port: '22', log: 'on',
        state: { mode: 'keep', maxSrcConn: 10, maxSrcConnRate: { count: 3, seconds: 30 }, overload: 'bruteforce', flushGlobal: true },
        description: 'SSH from anywhere, with brute-force protection',
      }),
      formRule({ id: 'r2', interfaces: ['wan'], action: 'block', source: { type: 'alias', alias: 'blocklist' }, log: 'on', description: 'Drop known-bad networks' }),
      formRule({ id: 'r3', interfaces: ['lan'], source: { type: 'net', iface: 'lan' }, description: 'Allow LAN to anywhere' }),
      formRule({
        id: 'r12', interfaces: ['lan'], enabled: false, source: { type: 'host', value: '192.168.1.25' },
        destination: { type: 'net', iface: 'lan', not: true }, gateway: 'gw_wh',
        description: 'Send the build server’s internet traffic through the warehouse',
      }),
      formRule({ id: 'r4', interfaces: ['iot'], protocol: 'tcp/udp', source: { type: 'net', iface: 'iot' }, destination: { type: 'self' }, port: '53', description: 'Allow DNS from IoT devices' }),
      formRule({ id: 'r5', interfaces: ['iot'], action: 'block', source: { type: 'net', iface: 'iot' }, destination: { type: 'alias', alias: 'internal' }, log: 'on', description: 'Keep IoT devices off the other networks' }),
      formRule({ id: 'r6', interfaces: ['iot'], source: { type: 'net', iface: 'iot' }, state: { mode: 'keep', maxStates: 2000 }, description: 'Allow IoT internet access' }),
      formRule({ id: 'r7', interfaces: ['wg'], source: { type: 'net', iface: 'wg' }, destination: { type: 'net', iface: 'lan' }, description: 'Remote access to the LAN' }),
      formRule({ id: 'r8', interfaces: ['wg'], source: { type: 'network', value: '10.20.0.0/16' }, destination: { type: 'net', iface: 'lan' }, description: 'Warehouse LAN to the office LAN' }),
      formRule({ id: 'r13', interfaces: ['wg'], source: { type: 'net', iface: 'wg' }, destination: { type: 'alias', alias: 'internal', not: true }, description: 'VPN devices to the internet' }),
    ],
    forwards: [
      {
        id: 'f1', enabled: true, iface: 'wan', protocol: 'tcp', source: { type: 'any' }, externalPort: '443',
        target: '192.168.1.20', targetPort: '443', reflection: true, log: false, description: 'File server web access',
      },
      {
        id: 'f2', enabled: true, iface: 'wan', protocol: 'tcp', source: { type: 'alias', alias: 'contractors' }, externalPort: '2222',
        target: '192.168.1.25', targetPort: '22', reflection: false, log: true, description: 'Build server SSH for contractors',
      },
    ],
    outboundNat: {
      mode: 'hybrid',
      rules: [
        {
          id: 'n1', enabled: true, iface: 'wan', source: { type: 'host', value: '192.168.1.60' }, destination: { type: 'any' },
          translation: { type: 'ifaddr' }, staticPort: true, description: 'Desk phone keeps its source ports (SIP)',
        },
      ],
    },
    aliases: [
      { id: 'a1', name: 'blocklist', type: 'url', entries: [], url: 'https://lists.example.org/drop.txt', refreshHours: 24, description: 'Downloaded list of networks with repeated abuse' },
      { id: 'a4', name: 'bruteforce', type: 'table', entries: [], description: 'Filled automatically by the SSH rule' },
      { id: 'a5', name: 'internal', type: 'networks', entries: ['192.168.0.0/16', '10.0.0.0/8'], description: 'All private office networks' },
      { id: 'a6', name: 'contractors', type: 'hosts', entries: ['198.51.100.14', '198.51.100.15'], description: 'Contractor office addresses' },
      { id: 'a2', name: 'servers', type: 'hosts', entries: ['192.168.1.20', '192.168.1.25'], description: 'File and build servers' },
      { id: 'a3', name: 'web', type: 'ports', entries: ['80', '443'], description: 'HTTP and HTTPS' },
    ],
    options: {
      blockPolicy: 'drop',
      statePolicy: 'floating',
      optimization: 'normal',
      maxStates: 100_000,
      syncookies: 'adaptive',
      scrub: { enabled: true, maxMss: 1440, randomId: true, noDf: true },
      logDefaultBlock: true,
    },
    custom: {
      options: '',
      beforeFilter: '# Example: keep ICMP path-MTU discovery working everywhere\npass quick inet proto icmp icmp-type { echoreq unreach }',
      afterFilter: '',
    },
  },
  dhcp: [
    {
      iface: 'lan', enabled: true, rangeStart: '192.168.1.100', rangeEnd: '192.168.1.199', leaseHours: 24, dns: 'self', dnsServers: [],
      reservations: [
        { id: 'd1', hostname: 'files', mac: '00:1b:21:3a:4f:10', ip: '192.168.1.20' },
        { id: 'd2', hostname: 'build', mac: '00:1b:21:3a:4f:22', ip: '192.168.1.25' },
        { id: 'd3', hostname: 'printer', mac: 'a4:5d:36:0c:81:9e', ip: '192.168.1.40' },
        { id: 'd4', hostname: 'deskphone', mac: '80:5e:c0:12:9a:31', ip: '192.168.1.60' },
      ],
    },
    { iface: 'iot', enabled: true, rangeStart: '192.168.20.100', rangeEnd: '192.168.20.250', leaseHours: 12, dns: 'self', dnsServers: [], reservations: [] },
  ],
  dns: {
    enabled: true,
    mode: 'recursive',
    forwarders: ['9.9.9.9', '149.112.112.112'],
    forwardTls: true,
    dnssec: true,
    registerLeases: true,
    overrides: [
      { id: 'h1', host: 'files', domain: 'office.arpa', ip: '192.168.1.20', description: 'File server' },
      { id: 'h2', host: 'wiki', domain: 'office.arpa', ip: '192.168.1.25', description: 'Team wiki' },
    ],
  },
  wireguard: {
    enabled: true,
    listenPort: 51820,
    address: '10.8.0.1/24',
    publicKey: 'kq3Xw0pY6m2VhT8cQf1LzR5nB7dJ4sA9gE0uWiOyHl8=',
    peers: [
      { id: 'p1', name: 'Priya phone', publicKey: 'Zr8LmQ2vX5cT1nB9dF4hJ7kW0pS3gA6eY2uIoRtCy1E=', address: '10.8.0.2/32', networks: [], keepalive: 25, clientRoutes: 'full' },
      { id: 'p2', name: 'Sam laptop', publicKey: 'Bv4NqW7eR1tY5uI9oP3aS6dF0gH2jK8lZxCvMnQwE5o=', address: '10.8.0.3/32', networks: [], keepalive: 25, clientRoutes: 'split' },
      { id: 'p3', name: 'Warehouse router', publicKey: 'Hc2Kx9mL5nP8qR1sT4vW7yZ0aB3dE6fG9hJ2kM5nP8=', address: '10.8.0.10/32', networks: ['10.20.0.0/16'], endpoint: 'warehouse.example.net:51820', keepalive: 25, clientRoutes: 'site' },
    ],
  },
};

const hour = 3600_000;

function withRuleEnabled(m: Model, id: string, enabled: boolean): Model {
  return { ...m, firewall: { ...m.firewall, rules: m.firewall.rules.map((r) => (r.id === id ? { ...r, enabled } : r)) } };
}

// A little history so the History page has something to show.
export function sampleHistory(now: number): HistoryEntry[] {
  const prev = withRuleEnabled(sampleModel, 'r5', false);
  return [
    {
      id: '20260925-141203', time: now - 3 * hour, user: 'admin', status: 'confirmed',
      changes: [{ id: 1, section: 'firewall', summary: 'Enabled rule “Keep IoT devices off the other networks” on IoT' }],
      before: prev, after: sampleModel,
    },
    {
      id: '20260924-093340', time: now - 28 * hour, user: 'admin', status: 'reverted',
      changes: [{ id: 2, section: 'interfaces', summary: 'LAN: address set to 10.0.0.1/24' }],
      before: prev, after: prev,
    },
    {
      id: '20260922-161512', time: now - 3 * 24 * hour, user: 'admin', status: 'applied',
      changes: [
        { id: 3, section: 'routing', summary: 'Added route 10.20.0.0/16 via WAREHOUSE' },
        { id: 4, section: 'wireguard', summary: 'Added VPN device “Warehouse router” (10.8.0.10/32)' },
      ],
      before: prev, after: prev,
    },
  ];
}
