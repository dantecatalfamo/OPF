// Runtime status, as the appliance would read it from pfctl, ifconfig,
// netstat and friends. Sample values for the preview build.

export interface IfaceStatus {
  up: boolean;
  mac: string;
  media: string;
  address?: string; // current address, including DHCP-assigned
  gateway?: string;
  rxBps: number;
  txBps: number;
}

export const ifaceStatus: Record<string, IfaceStatus> = {
  wan: { up: true, mac: '00:0d:b9:5e:21:a0', media: '1000baseT full-duplex', address: '203.0.113.24/24', gateway: '203.0.113.1', rxBps: 48_200_000, txBps: 6_100_000 },
  lan: { up: true, mac: '00:0d:b9:5e:21:a1', media: '1000baseT full-duplex', rxBps: 5_900_000, txBps: 46_800_000 },
  iot: { up: true, mac: '00:0d:b9:5e:21:a1', media: 'VLAN 20 on em1', rxBps: 180_000, txBps: 420_000 },
  wg: { up: true, mac: '—', media: 'WireGuard tunnel', rxBps: 310_000, txBps: 1_200_000 },
  wg1: { up: true, mac: '—', media: 'WireGuard tunnel', rxBps: 2_100_000, txBps: 900_000 },
};

export const systemInfo = {
  version: 'OpenBSD 7.8',
  arch: 'amd64',
  hardware: 'APU4D4 · AMD GX-412TC · 4 cores',
  bootedAt: Date.now() - (23 * 24 + 5) * 3600_000,
  memoryTotal: 4e9,
  memoryUsed: 1.3e9,
  diskTotal: 32e9,
  diskUsed: 4.1e9,
  patches: [
    { id: '013_unbound', description: 'unbound: fix denial of service with crafted DNS responses' },
    { id: '014_libssl', description: 'libssl: fix certificate verification bypass' },
  ],
};

export const pfStats = {
  states: 318,
  stateLimit: 100_000,
  blockedLastHour: 1_482,
  passedLastHour: 912_004,
};

export const ruleCounters: Record<string, { evaluations: number; states: number }> = {
  r1: { evaluations: 20_411, states: 3 },
  r2: { evaluations: 20_411, states: 0 },
  r3: { evaluations: 1_204_998, states: 241 },
  r4: { evaluations: 18_320, states: 12 },
  r5: { evaluations: 18_320, states: 0 },
  r6: { evaluations: 11_002, states: 38 },
  r7: { evaluations: 4_120, states: 9 },
  r8: { evaluations: 2_310, states: 6 },
  r9: { evaluations: 20_411, states: 1 },
  r10: { evaluations: 1_402_118, states: 0 },
  r11: { evaluations: 88_120, states: 2 },
  r12: { evaluations: 0, states: 0 },
  r13: { evaluations: 3_870, states: 17 },
};

// Deterministic pseudo-random so the preview looks the same each load.
function rng(seed: number) {
  let s = seed;
  return () => {
    s = (s * 1664525 + 1013904223) % 4294967296;
    return s / 4294967296;
  };
}

// A random walk that drifts back toward typical office levels.
export function stepTraffic(down: number, up: number, r: () => number = Math.random) {
  return {
    down: Math.max(3, Math.min(180, down + (r() - 0.5) * 26 + (55 - down) * 0.12)),
    up: Math.max(1, Math.min(40, up + (r() - 0.5) * 5 + (8 - up) * 0.12)),
  };
}

export interface TrafficPoint {
  time: string;
  download: number;
  upload: number;
}

export function trafficSeries(points = 60, seed = 7): TrafficPoint[] {
  const r = rng(seed);
  const now = Date.now();
  const out: TrafficPoint[] = [];
  let down = 40;
  let up = 6;
  for (let i = points - 1; i >= 0; i--) {
    ({ down, up } = stepTraffic(down, up, r));
    const t = new Date(now - i * 60_000);
    out.push({
      time: t.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      download: Math.round(down * 10) / 10,
      upload: Math.round(up * 10) / 10,
    });
  }
  return out;
}

export interface Lease {
  ip: string;
  mac: string;
  hostname: string;
  iface: string;
  expiresInMin: number;
}

export const leases: Lease[] = [
  { ip: '192.168.1.20', mac: '00:1b:21:3a:4f:10', hostname: 'files', iface: 'lan', expiresInMin: 1310 },
  { ip: '192.168.1.25', mac: '00:1b:21:3a:4f:22', hostname: 'build', iface: 'lan', expiresInMin: 1250 },
  { ip: '192.168.1.40', mac: 'a4:5d:36:0c:81:9e', hostname: 'printer', iface: 'lan', expiresInMin: 880 },
  { ip: '192.168.1.112', mac: '3c:22:fb:91:04:7d', hostname: 'priya-mbp', iface: 'lan', expiresInMin: 1402 },
  { ip: '192.168.1.118', mac: 'f0:18:98:2e:aa:13', hostname: 'sam-thinkpad', iface: 'lan', expiresInMin: 610 },
  { ip: '192.168.1.131', mac: '8c:85:90:4b:77:02', hostname: 'reception-pc', iface: 'lan', expiresInMin: 95 },
  { ip: '192.168.1.144', mac: 'b8:27:eb:5a:19:c4', hostname: 'door-display', iface: 'lan', expiresInMin: 1177 },
  { ip: '192.168.20.101', mac: '68:57:2d:10:e3:41', hostname: 'thermostat', iface: 'iot', expiresInMin: 402 },
  { ip: '192.168.20.102', mac: '50:02:91:7c:3a:0f', hostname: 'camera-front', iface: 'iot', expiresInMin: 655 },
  { ip: '192.168.20.103', mac: '50:02:91:7c:3a:1a', hostname: 'camera-dock', iface: 'iot', expiresInMin: 612 },
  { ip: '192.168.20.117', mac: 'd8:f1:5b:8e:22:90', hostname: 'tv-lobby', iface: 'iot', expiresInMin: 38 },
];

export const peerStatus: Record<string, { handshakeSecAgo: number | null; rx: number; tx: number; endpoint?: string }> = {
  p1: { handshakeSecAgo: 42, rx: 184_000_000, tx: 1_920_000_000, endpoint: '198.51.100.77:40212' },
  p2: { handshakeSecAgo: 3_900, rx: 42_000_000, tx: 310_000_000, endpoint: '192.0.2.140:51820' },
  p3: { handshakeSecAgo: 11, rx: 8_400_000_000, tx: 5_100_000_000, endpoint: 'warehouse.example.net:51820' },
};

export interface Connection {
  id: string;
  proto: 'tcp' | 'udp' | 'icmp';
  iface: string;
  source: string;
  destination: string;
  nat?: string;
  state: string;
  ageSec: number;
  bytes: number;
}

const hosts = ['192.168.1.112', '192.168.1.118', '192.168.1.131', '192.168.1.20', '192.168.20.101', '192.168.20.102', '10.8.0.2', '192.168.1.144'];
const remotes = ['140.82.112.4:443', '151.101.1.140:443', '9.9.9.9:853', '17.253.144.10:443', '52.94.236.248:443', '142.250.72.110:443', '104.16.132.229:443', '93.184.215.14:80'];

export function connections(): Connection[] {
  const r = rng(99);
  const out: Connection[] = [];
  for (let i = 0; i < 42; i++) {
    const src = hosts[Math.floor(r() * hosts.length)];
    const proto = r() < 0.78 ? 'tcp' : r() < 0.9 ? 'udp' : 'icmp';
    const dst = proto === 'icmp' ? remotes[Math.floor(r() * remotes.length)].split(':')[0] : remotes[Math.floor(r() * remotes.length)];
    const iface = src.startsWith('192.168.20.') ? 'iot' : src.startsWith('10.8.') ? 'wg' : 'lan';
    out.push({
      id: `s${1000 + i}`,
      proto,
      iface,
      source: proto === 'icmp' ? src : `${src}:${49152 + Math.floor(r() * 16000)}`,
      destination: dst,
      nat: `203.0.113.24:${50000 + Math.floor(r() * 15000)}`,
      state: proto === 'tcp' ? (r() < 0.85 ? 'ESTABLISHED' : 'FIN_WAIT_2') : proto === 'udp' ? 'MULTIPLE' : '0:0',
      ageSec: Math.floor(r() * 7200),
      bytes: Math.floor(r() * r() * 400_000_000),
    });
  }
  return out;
}

export interface LogEntry {
  id: string;
  time: string;
  action: 'block' | 'pass';
  iface: string;
  proto: string;
  source: string;
  destination: string;
  rule: string;
}

const attackers = ['198.51.100.23', '198.51.100.201', '185.220.101.4', '45.95.147.10', '162.142.125.9', '192.0.2.66'];
const ports = ['22', '23', '3389', '445', '8080', '5060', '1433', '443'];

export function logEntries(): LogEntry[] {
  const r = rng(3);
  const out: LogEntry[] = [];
  const now = Date.now();
  for (let i = 0; i < 36; i++) {
    const t = new Date(now - i * (8000 + r() * 40_000));
    const iot = r() < 0.18;
    out.push({
      id: `l${i}`,
      time: t.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
      action: 'block',
      iface: iot ? 'iot' : 'wan',
      proto: iot ? 'tcp' : r() < 0.8 ? 'tcp' : 'udp',
      source: iot ? `192.168.20.10${1 + Math.floor(r() * 3)}:${40000 + Math.floor(r() * 9000)}` : `${attackers[Math.floor(r() * attackers.length)]}:${1024 + Math.floor(r() * 60000)}`,
      destination: iot ? `192.168.1.${[20, 112, 118][Math.floor(r() * 3)]}:${['445', '22', '80'][Math.floor(r() * 3)]}` : `203.0.113.24:${ports[Math.floor(r() * ports.length)]}`,
      rule: iot ? 'Keep IoT devices off the LAN' : r() < 0.3 ? 'Drop known-bad networks' : 'Default: block incoming',
    });
  }
  return out;
}

export const gatewayStatus: Record<string, { online: boolean; address: string; rttMs: number; lossPct: number }> = {
  gw_wan: { online: true, address: '203.0.113.1', rttMs: 8.4, lossPct: 0 },
  gw_wh: { online: true, address: '10.8.0.10', rttMs: 23.1, lossPct: 0.5 },
};

export interface RouteEntry {
  destination: string;
  gateway: string;
  flags: string;
  iface: string;
  source: string;
}

// As `netstat -rn -f inet` would show it.
export const routingTable: RouteEntry[] = [
  { destination: 'default', gateway: '203.0.113.1', flags: 'UGS', iface: 'em0', source: 'DHCP' },
  { destination: '10.8.0/24', gateway: '10.8.0.1', flags: 'UCn', iface: 'wg0', source: 'Interface' },
  { destination: '10.20/16', gateway: '10.8.0.10', flags: 'UGS', iface: 'wg0', source: 'Static route' },
  { destination: '127/8', gateway: '127.0.0.1', flags: 'UGRS', iface: 'lo0', source: 'System' },
  { destination: '192.168.1/24', gateway: '192.168.1.1', flags: 'UCn', iface: 'em1', source: 'Interface' },
  { destination: '192.168.20/24', gateway: '192.168.20.1', flags: 'UCn', iface: 'vlan20', source: 'Interface' },
  { destination: '203.0.113/24', gateway: '203.0.113.24', flags: 'UCn', iface: 'em0', source: 'Interface' },
];
