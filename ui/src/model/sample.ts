// Example data for the preview build: a small office gateway. None of
// this is anyone's real configuration.
import type { HistoryEntry, Model } from './types';

export const sampleModel: Model = {
  system: {
    hostname: 'gw',
    domain: 'office.arpa',
    timezone: 'America/New_York',
    ntpServers: ['pool.ntp.org'],
  },
  interfaces: [
    {
      id: 'wan', name: 'WAN', device: 'em0', role: 'wan', enabled: true,
      ipv4: { mode: 'dhcp' }, ipv6: 'slaac', blockPrivate: true, blockBogons: true,
    },
    {
      id: 'lan', name: 'LAN', device: 'em1', role: 'lan', enabled: true,
      ipv4: { mode: 'static', address: '192.168.1.1', prefix: 24 }, ipv6: 'none',
    },
    {
      id: 'iot', name: 'IoT', device: 'vlan20', role: 'opt', enabled: true,
      ipv4: { mode: 'static', address: '192.168.20.1', prefix: 24 }, ipv6: 'none',
      vlan: { parent: 'em1', tag: 20 },
    },
    {
      id: 'wg', name: 'WireGuard', device: 'wg0', role: 'vpn', enabled: true,
      ipv4: { mode: 'static', address: '10.8.0.1', prefix: 24 }, ipv6: 'none',
    },
  ],
  firewall: {
    rules: [
      {
        id: 'r1', iface: 'wan', enabled: true, action: 'pass', protocol: 'udp',
        source: { type: 'any' }, destination: { type: 'self' }, port: '51820', log: false,
        description: 'Allow WireGuard clients',
      },
      {
        id: 'r2', iface: 'wan', enabled: true, action: 'block', protocol: 'any',
        source: { type: 'alias', alias: 'blocklist' }, destination: { type: 'any' }, log: true,
        description: 'Drop known-bad networks',
      },
      {
        id: 'r3', iface: 'lan', enabled: true, action: 'pass', protocol: 'any',
        source: { type: 'net', iface: 'lan' }, destination: { type: 'any' }, log: false,
        description: 'Allow LAN to anywhere',
      },
      {
        id: 'r4', iface: 'iot', enabled: true, action: 'pass', protocol: 'tcp/udp',
        source: { type: 'net', iface: 'iot' }, destination: { type: 'self' }, port: '53', log: false,
        description: 'Allow DNS from IoT devices',
      },
      {
        id: 'r5', iface: 'iot', enabled: true, action: 'block', protocol: 'any',
        source: { type: 'net', iface: 'iot' }, destination: { type: 'net', iface: 'lan' }, log: true,
        description: 'Keep IoT devices off the LAN',
      },
      {
        id: 'r6', iface: 'iot', enabled: true, action: 'pass', protocol: 'any',
        source: { type: 'net', iface: 'iot' }, destination: { type: 'any' }, log: false,
        description: 'Allow IoT internet access',
      },
      {
        id: 'r7', iface: 'wg', enabled: true, action: 'pass', protocol: 'any',
        source: { type: 'net', iface: 'wg' }, destination: { type: 'net', iface: 'lan' }, log: false,
        description: 'Remote access to the LAN',
      },
      {
        id: 'r8', iface: 'wg', enabled: false, action: 'pass', protocol: 'any',
        source: { type: 'net', iface: 'wg' }, destination: { type: 'any' }, log: false,
        description: 'Route all client traffic through the office',
      },
    ],
    forwards: [
      {
        id: 'f1', enabled: true, iface: 'wan', protocol: 'tcp', externalPort: '443',
        target: '192.168.1.20', targetPort: '443', description: 'File server web access',
      },
      {
        id: 'f2', enabled: true, iface: 'wan', protocol: 'tcp', externalPort: '2222',
        target: '192.168.1.25', targetPort: '22', description: 'Build server SSH',
      },
    ],
    aliases: [
      {
        id: 'a1', name: 'blocklist', type: 'networks', entries: ['198.51.100.0/24', '192.0.2.0/24'],
        description: 'Networks with repeated abuse',
      },
      {
        id: 'a2', name: 'servers', type: 'hosts', entries: ['192.168.1.20', '192.168.1.25'],
        description: 'File and build servers',
      },
      { id: 'a3', name: 'web', type: 'ports', entries: ['80', '443'], description: 'HTTP and HTTPS' },
    ],
  },
  dhcp: [
    {
      iface: 'lan', enabled: true, rangeStart: '192.168.1.100', rangeEnd: '192.168.1.199',
      leaseHours: 24, dns: 'self', dnsServers: [],
      reservations: [
        { id: 'd1', hostname: 'files', mac: '00:1b:21:3a:4f:10', ip: '192.168.1.20' },
        { id: 'd2', hostname: 'build', mac: '00:1b:21:3a:4f:22', ip: '192.168.1.25' },
        { id: 'd3', hostname: 'printer', mac: 'a4:5d:36:0c:81:9e', ip: '192.168.1.40' },
      ],
    },
    {
      iface: 'iot', enabled: true, rangeStart: '192.168.20.100', rangeEnd: '192.168.20.250',
      leaseHours: 12, dns: 'self', dnsServers: [], reservations: [],
    },
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
      { id: 'p1', name: 'Priya phone', publicKey: 'Zr8LmQ2vX5cT1nB9dF4hJ7kW0pS3gA6eY2uIoRtCy1E=', address: '10.8.0.2/32', keepalive: 25 },
      { id: 'p2', name: 'Sam laptop', publicKey: 'Bv4NqW7eR1tY5uI9oP3aS6dF0gH2jK8lZxCvMnQwE5o=', address: '10.8.0.3/32', keepalive: 25 },
      { id: 'p3', name: 'Warehouse router', publicKey: 'Hc2Kx9mL5nP8qR1sT4vW7yZ0aB3dE6fG9hJ2kM5nP8=', address: '10.8.0.10/32', endpoint: 'warehouse.example.net:51820' },
    ],
  },
};

const hour = 3600_000;

function withRuleDisabled(m: Model, id: string, enabled: boolean): Model {
  return {
    ...m,
    firewall: {
      ...m.firewall,
      rules: m.firewall.rules.map((r) => (r.id === id ? { ...r, enabled } : r)),
    },
  };
}

// A little history so the History page has something to show.
export function sampleHistory(now: number): HistoryEntry[] {
  const prev = withRuleDisabled(sampleModel, 'r5', false);
  return [
    {
      id: '20260925-141203', time: now - 3 * hour, user: 'admin', status: 'confirmed',
      changes: [{ id: 1, section: 'firewall', summary: 'Enabled rule “Keep IoT devices off the LAN” on IoT' }],
      before: prev, after: sampleModel,
    },
    {
      id: '20260924-093340', time: now - 28 * hour, user: 'admin', status: 'reverted',
      changes: [{ id: 2, section: 'interfaces', summary: 'Changed LAN address to 10.0.0.1/24' }],
      before: prev, after: prev,
    },
    {
      id: '20260922-161512', time: now - 3 * 24 * hour, user: 'admin', status: 'applied',
      changes: [
        { id: 3, section: 'dhcp', summary: 'Added reservation “printer” (192.168.1.40) on LAN' },
        { id: 4, section: 'dns', summary: 'Added host override wiki.office.arpa' },
      ],
      before: prev, after: prev,
    },
  ];
}
