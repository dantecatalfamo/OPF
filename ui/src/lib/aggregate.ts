// Aggregated links: one interface made of several ports, aggr(4) for
// LACP, trunk(4) for the other ways (pf.AggregateConfig).
import type { InterfacesResource, InterfaceState } from './api';
import type { Aggregate, Iface, Model, TrunkProto } from '../model/types';

/** How an aggregate uses its ports: LACP is an aggr, the rest trunks. */
export type AggregateMode = 'lacp' | TrunkProto;

export const modeOf = (a: Aggregate): AggregateMode => a.proto ?? 'lacp';

export const modeLabel: Record<AggregateMode, string> = {
  lacp: 'LACP',
  failover: 'Failover',
  loadbalance: 'Load balance',
  roundrobin: 'Round robin',
  broadcast: 'Broadcast',
  none: 'Nothing passes',
};

/** What each mode needs and does, for the form. */
export const modeHelp: Record<AggregateMode, string> = {
  lacp: 'Combines the ports into one faster link with a switch that supports LACP (802.3ad). Set the switch’s ports up as an LACP group too.',
  failover: 'Uses one port at a time, and moves to the next if its link goes down. Works with any switch, or two switches.',
  loadbalance: 'Spreads connections over the ports. The switch’s ports need to be a static link aggregation group.',
  roundrobin: 'Sends each packet through the next port. The switch’s ports need to be a static link aggregation group.',
  broadcast: 'Sends every packet through every port.',
  none: 'Passes no traffic, with the interface still up.',
};

/** The modes offered when making one: none passes nothing. */
export const offeredModes: AggregateMode[] = ['lacp', 'failover', 'loadbalance', 'roundrobin', 'broadcast'];

/** The aggregate's settings for a mode, keeping the ports. */
export function withMode(a: Aggregate, mode: AggregateMode): Aggregate {
  if (mode === 'lacp') return { ports: a.ports, ...(a.lacpPassive ? { lacpPassive: true } : {}), ...(a.lacpFast ? { lacpFast: true } : {}) };
  return { ports: a.ports, proto: mode };
}

/** The device for a mode: the interface's own when it's of that kind
 *  already, else the first free aggrN or trunkN. */
export function deviceFor(m: Model, mode: AggregateMode, current?: Iface): string {
  const kind = mode === 'lacp' ? 'aggr' : 'trunk';
  if (current?.device.startsWith(kind)) return current.device;
  for (let n = 0; ; n++) if (!m.interfaces.some((i) => i.device === `${kind}${n}`)) return `${kind}${n}`;
}

/** Every aggregate port in the model, with the interface it's a port of. */
export function portOwners(m: Model): Map<string, Iface> {
  const out = new Map<string, Iface>();
  for (const i of m.interfaces) for (const p of i.aggregate?.ports ?? []) out.set(p, i);
  return out;
}

// The kinds ifconfig creates: not ports (pf.ClonedKinds).
const cloned = /^(aggr|bpe|bridge|carp|egre|enc|eoip|erspan|etherip|gif|gre|lo|mgre|mpe|mpip|mpw|nvgre|pair|pflog|pflow|pfsync|ppp|pppoe|rport|sec|svlan|tap|tpmr|trunk|tun|veb|vether|vlan|vport|vxlan|wg)\d/;

/** The ports an aggregate can have: the machine's Ethernet ports that
 *  aren't an interface, a VLAN's parent or another aggregate's port. */
export function freePorts(m: Model, live: InterfacesResource | undefined, current?: Iface): InterfaceState[] {
  const owners = portOwners(m);
  return (live?.interfaces ?? []).filter((s) =>
    !!s.mac && !cloned.test(s.name) && !s.wireguard &&
    !m.interfaces.some((i) => i.device === s.name || i.vlan?.parent === s.name) &&
    (!owners.has(s.name) || owners.get(s.name)?.id === current?.id),
  ).sort((a, b) => a.name.localeCompare(b.name, undefined, { numeric: true }));
}

/** "LACP of em1 and em2", for cards and headers. */
export function describeAggregate(a: Aggregate): string {
  const ports = a.ports.length <= 1 ? a.ports.join('') : `${a.ports.slice(0, -1).join(', ')} and ${a.ports[a.ports.length - 1]}`;
  return `${modeLabel[modeOf(a)]} of ${ports}`;
}

/** What a port of a live aggregate is doing, from trunk(4)'s flags:
 *  carrying traffic, waiting (failover's spare), or not used (no link,
 *  or LACP hasn't agreed with the switch). */
export function portUse(agg: InterfaceState | undefined, port: string): { ok: boolean; label: string } | undefined {
  const p = agg?.trunk?.ports?.find((x) => x.name === port);
  if (!agg?.trunk || !p) return undefined;
  const f = new Set(p.flags);
  if (agg.trunk.proto === 'lacp') return f.has('distributing') ? { ok: true, label: 'In use' } : { ok: false, label: f.has('active') ? 'Waiting for LACP' : 'Not in use' };
  if (agg.trunk.proto === 'failover') {
    // The master is the first port; while it's down, trunk(4) uses the
    // next active one, which ifconfig doesn't mark.
    const masterUp = agg.trunk.ports?.some((x) => x.flags.includes('master') && x.flags.includes('active'));
    if (!f.has('active')) return { ok: false, label: 'Not in use' };
    return f.has('master') ? { ok: true, label: 'In use' } : { ok: true, label: masterUp ? 'Standby' : 'Up' };
  }
  return f.has('active') ? { ok: true, label: 'In use' } : { ok: false, label: 'Not in use' };
}
