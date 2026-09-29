// Deleting an interface: what refers to it, and the model without it.
// Validation refuses a model that refers to a missing interface or
// gateway, so everything that does has to go or change with it, and the
// user sees each before agreeing.
import type { Endpoint, Iface, Model, Rule } from '../model/types';
import { inSubnet, isIPv4, network } from './ip';

export interface Dependent {
  /** What it is, e.g. "Firewall rule “Allow DNS from IoT devices”". */
  what: string;
  /**
   * deleted and changed happen with the interface; edit is free text
   * (a raw rule, custom pf) that mentions it and that OPF can't change
   * safely. pf's check refuses the commit until it's edited.
   */
  effect: 'deleted' | 'changed' | 'edit';
  detail?: string;
}

const refersTo = (e: Endpoint | undefined, id: string) => e?.type === 'iface' && e.iface === id;
const mentions = (text: string, id: string) => new RegExp(`\\$${id}(?![A-Za-z0-9_])`).test(text);

// The interface's network as an alias entry would write it.
const netOf = (i: Iface | undefined) =>
  i?.ipv4.mode === 'static' && i.ipv4.address && i.ipv4.prefix !== undefined ? { cidr: `${network(i.ipv4.address, i.ipv4.prefix)}/${i.ipv4.prefix}`, address: i.ipv4.address, prefix: i.ipv4.prefix } : null;

// A WAN rule that only opens a tunnel's port: made by "Add tunnel", and
// pointless once the tunnel is gone.
function opensTunnelPort(m: Model, iface: Iface | undefined, r: Rule): boolean {
  const port = iface?.wireguard?.listenPort;
  if (!port || r.kind !== 'form' || r.protocol !== 'udp' || r.port !== String(port) || !r.interfaces.length) return false;
  const wans = new Set(m.interfaces.filter((i) => i.role === 'wan').map((i) => i.id));
  return r.interfaces.every((i) => wans.has(i));
}

/** Why the interface can't be deleted, if it can't. */
export function cannotDelete(m: Model, id: string): string | null {
  const gw = m.routing.gateways.find((g) => g.id === m.routing.defaultGateway);
  if (gw?.iface === id) return `It carries the default gateway (${gw.name}); choose another default gateway first.`;
  return null;
}

export function interfaceDependents(m: Model, id: string): Dependent[] {
  const out: Dependent[] = [];
  const iface = m.interfaces.find((i) => i.id === id);
  const name = iface?.name ?? id;
  const net = netOf(iface);
  const gateways = m.routing.gateways.filter((g) => g.iface === id);
  const gwIds = new Set(gateways.map((g) => g.id));

  if (m.dhcp.some((s) => s.iface === id)) out.push({ what: `DHCP server on ${name}`, effect: 'deleted' });
  for (const r of m.firewall.rules) {
    const label = `Firewall rule “${r.description || r.id}”`;
    const onIt = r.interfaces.includes(id);
    if (opensTunnelPort(m, iface, r)) {
      out.push({ what: label, effect: 'deleted', detail: `it opens the tunnel’s port, ${iface?.wireguard?.listenPort}` });
    } else if (r.kind === 'form' && (refersTo(r.source, id) || refersTo(r.destination, id))) {
      out.push({ what: label, effect: 'deleted', detail: `its addresses are ${name}’s` });
    } else if (onIt && r.interfaces.length === 1) {
      out.push({ what: label, effect: 'deleted' });
    } else if (onIt) {
      out.push({ what: label, effect: 'changed', detail: `no longer applies on ${name}` });
    } else if (r.kind === 'raw' && mentions(r.text, id)) {
      out.push({ what: label, effect: 'edit', detail: `its text mentions $${id}` });
    }
    if (r.kind === 'form' && ((r.gateway && gwIds.has(r.gateway)) || (r.replyTo && gwIds.has(r.replyTo))) && !onIt) {
      out.push({ what: label, effect: 'changed', detail: `no longer routed through ${name}` });
    }
  }
  for (const n of m.firewall.outboundNat.rules) {
    if (n.iface === id || refersTo(n.source, id) || refersTo(n.destination, id)) out.push({ what: `Outbound NAT rule “${n.description || n.id}”`, effect: 'deleted' });
  }
  for (const f of m.firewall.forwards) {
    if (f.iface === id || refersTo(f.source, id)) out.push({ what: `Port forward “${f.description || f.id}”`, effect: 'deleted' });
  }
  for (const g of gateways) out.push({ what: `Gateway ${g.name}`, effect: 'deleted' });
  for (const r of m.routing.routes) {
    if (gwIds.has(r.gateway)) out.push({ what: `Route to ${r.network}`, effect: 'deleted', detail: 'its gateway is on the interface' });
  }
  if (net) {
    for (const a of m.firewall.aliases) {
      if (a.type !== 'hosts' && a.type !== 'networks') continue;
      const exact = a.entries.filter((e) => e === net.cidr);
      const inside = a.entries.filter((e) => e !== net.cidr && isIPv4(e.split('/')[0]) && inSubnet(e.split('/')[0], net.address, net.prefix));
      if (exact.length && exact.length === a.entries.length) {
        out.push({ what: `Alias ${a.name}`, effect: 'edit', detail: `it only holds ${name}’s network, so it would be empty` });
      } else if (exact.length) {
        out.push({ what: `Alias ${a.name}`, effect: 'changed', detail: `loses ${net.cidr}` });
      }
      if (inside.length) out.push({ what: `Alias ${a.name}`, effect: 'edit', detail: `has addresses on ${name}’s network (${inside.join(', ')})` });
    }
  }
  const c = m.firewall.custom;
  for (const [text, where] of [[c.options, 'options'], [c.beforeFilter, 'rules before'], [c.afterFilter, 'rules after']] as const) {
    if (mentions(text, id)) out.push({ what: `Custom pf (${where})`, effect: 'edit', detail: `mentions $${id}` });
  }
  return out;
}

/** The model without the interface and with its dependents deleted or changed. */
export function withoutInterface(m: Model, id: string): Model {
  const iface = m.interfaces.find((i) => i.id === id);
  const net = netOf(iface);
  const gwIds = new Set(m.routing.gateways.filter((g) => g.iface === id).map((g) => g.id));
  const rules = m.firewall.rules
    .filter((r) => !opensTunnelPort(m, iface, r))
    .filter((r) => !(r.kind === 'form' && (refersTo(r.source, id) || refersTo(r.destination, id))))
    .filter((r) => !(r.interfaces.length === 1 && r.interfaces[0] === id))
    .map((r) => {
      const next = { ...r, interfaces: r.interfaces.filter((i) => i !== id) };
      if (next.kind === 'form') {
        if (next.gateway && gwIds.has(next.gateway)) next.gateway = undefined;
        if (next.replyTo && gwIds.has(next.replyTo)) next.replyTo = undefined;
      }
      return next;
    });
  return {
    ...m,
    interfaces: m.interfaces.filter((i) => i.id !== id),
    dhcp: m.dhcp.filter((s) => s.iface !== id),
    routing: {
      ...m.routing,
      gateways: m.routing.gateways.filter((g) => !gwIds.has(g.id)),
      routes: m.routing.routes.filter((r) => !gwIds.has(r.gateway)),
    },
    firewall: {
      ...m.firewall,
      rules,
      // Drop the network from aliases, unless that would empty one (the
      // dialog asks for that to be edited).
      aliases: m.firewall.aliases.map((a) => {
        if (!net || (a.type !== 'hosts' && a.type !== 'networks')) return a;
        const entries = a.entries.filter((e) => e !== net.cidr);
        return entries.length ? { ...a, entries } : a;
      }),
      forwards: m.firewall.forwards.filter((f) => f.iface !== id && !refersTo(f.source, id)),
      outboundNat: {
        ...m.firewall.outboundNat,
        rules: m.firewall.outboundNat.rules.filter((n) => n.iface !== id && !refersTo(n.source, id) && !refersTo(n.destination, id)),
      },
    },
  };
}
