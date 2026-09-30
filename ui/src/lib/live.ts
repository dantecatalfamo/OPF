// The running system's state, polled while a page shows it. Every part
// of the UI asking for the same thing shares one poller, and polling
// stops while the tab is hidden.
import { useEffect, useState } from 'react';
import { backend } from '../model/store';
import type { DnsBlockedResource, DnsStatsResource, FirewallLogResource, GatewaysResource, InterfaceState, InterfacesResource, PfStatesResource, PfStatusResource, RoutingTableResource, RuleCountersResource, SystemResource, UpdatesResource, WgPeerState } from './api';
import type { Iface, Peer } from '../model/types';

const sources = {
  system: { load: () => backend.system(), ms: 5000 },
  interfaces: { load: () => backend.interfaces(), ms: 3000 },
  gateways: { load: () => backend.gateways(), ms: 10_000 },
  // Quickly while a check runs, so its answer shows when it arrives.
  updates: { load: () => backend.updates(), ms: (d?: UpdatesResource) => (d?.checking ? 3000 : 60_000) },
  routes: { load: () => backend.routingTable(), ms: 30_000 },
  pfStatus: { load: () => backend.pfStatus(), ms: 5000 },
  pfStates: { load: () => backend.pfStates(), ms: 5000 },
  ruleCounters: { load: () => backend.ruleCounters(), ms: 10_000 },
  firewallLog: { load: () => backend.firewallLog(), ms: 10_000 },
  dnsStats: { load: () => backend.dnsStats(), ms: 5000 },
  dnsBlocked: { load: () => backend.dnsBlocked(), ms: 30_000 },
};

interface Types {
  system: SystemResource;
  interfaces: InterfacesResource;
  gateways: GatewaysResource;
  updates: UpdatesResource;
  routes: RoutingTableResource;
  pfStatus: PfStatusResource;
  pfStates: PfStatesResource;
  ruleCounters: RuleCountersResource;
  firewallLog: FirewallLogResource;
  dnsStats: DnsStatsResource;
  dnsBlocked: DnsBlockedResource;
}
type Key = keyof Types;

export interface Live<T> {
  data?: T; // the last answer, kept through a failed poll
  error?: string;
}

interface Poller {
  subs: Set<() => void>;
  state: Live<unknown>;
  timer?: ReturnType<typeof setTimeout>;
  inflight: boolean;
}
const pollers = new Map<Key, Poller>();

function poll(key: Key) {
  const p = pollers.get(key);
  if (!p || p.inflight) return;
  clearTimeout(p.timer);
  if (document.hidden) return; // resumed on visibilitychange
  p.inflight = true;
  sources[key].load().then(
    (data) => { p.state = { data }; },
    (e) => { p.state = { data: p.state.data, error: e instanceof Error ? e.message : String(e) }; },
  ).finally(() => {
    p.inflight = false;
    p.subs.forEach((f) => f());
    const ms = sources[key].ms;
    if (p.subs.size) p.timer = setTimeout(() => poll(key), typeof ms === 'function' ? ms(p.state.data as UpdatesResource) : ms);
  });
}

if (typeof document !== 'undefined') {
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) for (const k of pollers.keys()) poll(k);
  });
}

/** The latest answer for key, polled while the component is mounted. */
/** Asks for key again now, after a change (ending a connection, say). */
export function refreshLive(key: Key) {
  poll(key);
}

export function useLive<K extends Key>(key: K): Live<Types[K]> {
  let p = pollers.get(key);
  if (!p) {
    p = { subs: new Set(), state: {}, inflight: false };
    pollers.set(key, p);
  }
  const [state, setState] = useState(p.state as Live<Types[K]>);
  useEffect(() => {
    const poller = pollers.get(key)!;
    const update = () => setState(poller.state as Live<Types[K]>);
    poller.subs.add(update);
    if (poller.subs.size === 1) poll(key);
    else update();
    return () => {
      poller.subs.delete(update);
      if (!poller.subs.size) clearTimeout(poller.timer);
    };
  }, [key]);
  return state;
}

/** A model interface's live state, found by its device. */
export const ifaceState = (live: InterfacesResource | undefined, i: Pick<Iface, 'device'>): InterfaceState | undefined =>
  live?.interfaces.find((s) => s.name === i.device);

/** A VPN device's live state, found by its public key on its tunnel's interface. */
export function peerState(live: InterfacesResource | undefined, tunnel: Pick<Iface, 'device'>, p: Pick<Peer, 'publicKey'>): WgPeerState | undefined {
  return ifaceState(live, tunnel)?.wireguard?.peers.find((x) => x.publicKey === p.publicKey);
}

/** An interface's first IPv4 address without its prefix. */
export const firstIPv4 = (s: InterfaceState | undefined) => s?.ipv4[0]?.split('/')[0];

/** Whether a VPN device has shaken hands recently enough to count as connected. */
export const peerOnline = (s: WgPeerState | undefined) => s?.handshakeAgo !== undefined && s.handshakeAgo < 180;

/** The default route's gateway on a device: what DHCP gave it. */
export const defaultGateway = (routes: RoutingTableResource | undefined, device: string) =>
  routes?.ipv4.find((r) => r.destination === 'default' && r.iface === device)?.gateway;

/** What a link negotiated ("1000baseT full-duplex"), from ifconfig's media line. */
export function mediaLabel(s: InterfaceState | undefined): string | undefined {
  if (!s?.media) return s?.vlan ? `VLAN ${s.vlan.id} on ${s.vlan.parent}` : s?.wireguard ? 'WireGuard tunnel' : undefined;
  const active = s.media.match(/\(([^)]*)\)/)?.[1];
  return active && active !== 'none' ? active : s.media;
}
