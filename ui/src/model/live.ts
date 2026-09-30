// Runtime status, as the appliance would read it from pfctl, ifconfig,
// netstat and friends. Sample values for the preview build, which has no
// server: localApi answers the status calls with these, in the API's
// shapes, for its own live model.
import type { GatewaysResource, InterfaceState, InterfacesResource, SystemResource, UpdatesResource } from '../lib/api';
import type { Iface, Model } from './types';

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

export interface RouteEntry {
  destination: string;
  gateway: string;
  flags: string;
  iface: string;
  source: string;
}

// As `netstat -rn -f inet` would show it.
export const routingTable: RouteEntry[] = [
  { destination: 'default', gateway: '203.0.113.1', flags: 'UGS', iface: 'em0', source: 'dhcp' },
  { destination: '10.8.0/24', gateway: '10.8.0.1', flags: 'UCn', iface: 'wg0', source: 'interface' },
  { destination: '10.20/16', gateway: '10.8.0.10', flags: 'UGS', iface: 'wg0', source: 'static' },
  { destination: '127/8', gateway: '127.0.0.1', flags: 'UGRS', iface: 'lo0', source: 'interface' },
  { destination: '192.168.1/24', gateway: '192.168.1.1', flags: 'UCn', iface: 'em1', source: 'interface' },
  { destination: '192.168.20/24', gateway: '192.168.20.1', flags: 'UCn', iface: 'vlan20', source: 'interface' },
  { destination: '203.0.113/24', gateway: '203.0.113.24', flags: 'UCn', iface: 'em0', source: 'interface' },
];

export interface ARPEntry {
  ip: string;
  mac: string;
  iface: string;
  expires?: string;
  flags?: string;
  hostname?: string;
}

// As `arp -an` would show it.
export const arpTable: ARPEntry[] = [
  { ip: '203.0.113.1', mac: '00:0c:29:4a:12:8b', iface: 'em0', expires: 'permanent', hostname: 'gateway' },
  { ip: '192.168.1.20', mac: '00:1b:21:3a:4f:10', iface: 'em1', expires: '1142s', hostname: 'files' },
  { ip: '192.168.1.25', mac: '00:1b:21:3a:4f:22', iface: 'em1', expires: '892s', hostname: 'build' },
  { ip: '192.168.1.40', mac: 'a4:5d:36:0c:81:9e', iface: 'em1', expires: '445s', hostname: 'printer' },
  { ip: '192.168.1.112', mac: '3c:22:fb:91:04:7d', iface: 'em1', expires: '1201s', hostname: 'priya-mbp' },
  { ip: '192.168.1.118', mac: 'f0:18:98:2e:aa:13', iface: 'em1', expires: '623s', hostname: 'sam-thinkpad' },
  { ip: '192.168.1.131', mac: '8c:85:90:4b:77:02', iface: 'em1', expires: '95s', hostname: 'reception-pc' },
  { ip: '192.168.20.101', mac: '68:57:2d:10:e3:41', iface: 'vlan20', expires: '312s', hostname: 'thermostat' },
  { ip: '192.168.20.102', mac: '50:02:91:7c:3a:0f', iface: 'vlan20', expires: '518s' },
  { ip: '192.168.20.103', mac: '50:02:91:7c:3a:1a', iface: 'vlan20', expires: '412s' },
  { ip: '10.8.0.2', mac: '(incomplete)', iface: 'wg0', expires: '60s' },
];

// Seconds since the page loaded, and a counter growing at avg per second
// give or take, never backwards: traffic that moves, for the dashboard.
const started = Date.now();
function wander(seed: number, avg: number, t: number) {
  const w = (2 * Math.PI) / (60 + (seed % 90));
  return avg * t - (avg * 0.6 * (Math.cos(w * t + seed) - Math.cos(seed))) / w;
}

export function sampleSystem(): SystemResource {
  const t = (Date.now() - started) / 1000;
  const busy = 9 + 4 * Math.sin(t / 20);
  return {
    hostname: 'gw.office.arpa', release: '7.9', version: 'OpenBSD 7.9 (GENERIC.MP) #15: Sun Sep 27 02:47:36 MDT 2026',
    machine: 'amd64', cpuModel: 'AMD GX-412TC SOC', vendor: 'PC Engines', product: 'apu4', cpus: 4,
    bootedAt: new Date(started - (23 * 24 + 5) * 3600_000).toISOString(),
    load: [0.31, 0.28, 0.25],
    cpu: { user: busy * 0.6, nice: 0, system: busy * 0.3, spin: 0, interrupt: busy * 0.1, idle: 100 - busy },
    memory: { total: 4_261_412_864, free: 2_743_631_872, active: 657_620_992, inactive: 614_400_000 },
    swap: { total: 4_294_967_296, used: 0 },
    disks: [
      { device: '/dev/sd0a', mount: '/', total: 1_033_648_128, used: 134_187_008, available: 847_779_840 },
      { device: '/dev/sd0e', mount: '/var', total: 10_567_268_352, used: 1_669_541_888, available: 8_369_362_944 },
      { device: '/dev/sd0f', mount: '/usr', total: 5_283_805_184, used: 1_548_580_864, available: 3_471_034_368 },
    ],
    sensors: [{ device: 'km0', type: 'temp', index: 0, value: '51.17 degC', number: 51.17, unit: 'degC' }],
    time: { synced: true, stratum: 3, status: '4/4 peers valid, clock synced, stratum 3', source: '162.159.200.1', offsetMs: 0.41 },
    errors: [],
  };
}

export const sampleUpdates = (): UpdatesResource => ({ checkedAt: new Date(started).toISOString(), checking: false, patches: ['001_unbound', '002_libcrypto'] });

const traffic = (i: Iface): [number, number] =>
  i.role === 'wan' ? [6e6, 0.8e6] : i.role === 'vpn' ? [0.05e6, 0.15e6] : i.vlan ? [0.03e6, 0.06e6] : [0.7e6, 5.8e6];

export function sampleInterfaces(m: Model): InterfacesResource {
  const t = (Date.now() - started) / 1000;
  return {
    errors: [],
    interfaces: m.interfaces.map((i, n): InterfaceState => {
      const [rx, tx] = traffic(i);
      const rate = (avg: number, seed: number) => 8 * (wander(seed, avg, t + 1) - wander(seed, avg, t));
      return {
        name: i.device, flags: i.enabled ? ['UP', 'RUNNING'] : [], up: i.enabled, running: i.enabled,
        mac: i.wireguard ? undefined : `00:0d:b9:5e:21:${(0xa0 + n).toString(16)}`,
        media: i.wireguard ? undefined : '1000baseT full-duplex', status: i.wireguard ? undefined : i.enabled ? 'active' : 'no carrier',
        groups: [], ipv6: [],
        ipv4: i.ipv4.mode === 'static' && i.ipv4.address ? [`${i.ipv4.address}/${i.ipv4.prefix}`] : i.ipv4.mode === 'dhcp' ? ['203.0.113.24/24'] : [],
        vlan: i.vlan ? { id: i.vlan.tag, parent: i.vlan.parent } : undefined,
        wireguard: i.wireguard && {
          port: i.wireguard.listenPort, publicKey: i.wireguard.publicKey,
          peers: i.wireguard.peers.map((p, k) => ({
            publicKey: p.publicKey, description: p.name, allowedIps: [p.address, ...p.networks],
            ...(k === i.wireguard!.peers.length - 1 && k > 0
              ? { txBytes: 0, rxBytes: 0 }
              : { endpoint: `198.51.100.${70 + k}:${40212 + k}`, txBytes: 1.92e9 + wander(k, 40e3, t), rxBytes: 1.84e8 + wander(k + 7, 4e3, t), handshakeAgo: k === 0 ? Math.floor(t) % 120 : 3900 + Math.floor(t) }),
          })),
        },
        rxBps: i.enabled ? rate(rx, n * 13) : 0,
        txBps: i.enabled ? rate(tx, n * 13 + 5) : 0,
      };
    }),
  };
}

export function sampleGateways(m: Model): GatewaysResource {
  return {
    gateways: Object.fromEntries(m.routing.gateways.map((g, n) => [g.id, {
      address: g.monitor || (g.address === 'dhcp' ? '203.0.113.1' : g.address), online: true, lossPct: n ? 0.5 : 0, rttMs: n ? 23.1 : 8.4,
    }])),
  };
}
