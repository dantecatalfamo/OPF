// The firewall rules and port forwards that name a device: by one of
// its addresses, a network it's in, or an alias that holds either. For
// a device's page.
import type { Alias, Endpoint, Model } from '../model/types';
import { inSubnet, isCIDR, isIPv4 } from './ip';

export interface DeviceRule {
  kind: 'rule' | 'raw' | 'forward';
  id: string;
  enabled: boolean;
  description: string;
  /** How it names the device: "from it", "to it, by alias servers"… */
  how: string;
  /** The UI page that has it. */
  to: string;
  /** It names the address itself, not a network it's in. */
  exact: boolean;
}

// Whether a value (an address, a network, an alias entry) holds addr,
// and how to say so.
function holds(value: string, addr: string): string | undefined {
  const v = value.trim();
  if (v === addr || v === `${addr}/32`) return 'by its address';
  if (isCIDR(v)) {
    const [net, p] = v.split('/');
    if (isIPv4(net) && inSubnet(addr, net, Number(p))) return `by ${v}, a network it’s in`;
  }
  return undefined;
}

function endpointHolds(ep: Endpoint, addr: string, aliases: Alias[]): string | undefined {
  if (ep.not) return undefined; // “not this” isn't about it
  switch (ep.type) {
    case 'host':
    case 'network':
      return holds(ep.value, addr);
    case 'alias': {
      const a = aliases.find((x) => x.name === ep.alias);
      if (!a || (a.type !== 'hosts' && a.type !== 'networks')) return undefined;
      for (const e of a.entries) {
        const h = holds(e, addr);
        if (h) return h === 'by its address' ? `by alias ${a.name}, which lists its address` : `by alias ${a.name}, ${h.replace(/^by /, '')}`;
      }
      return undefined;
    }
  }
  return undefined;
}

/** The rules and port forwards that name one of addrs. */
export function rulesFor(m: Model, addrs: string[]): DeviceRule[] {
  const v4 = addrs.filter(isIPv4);
  if (!v4.length) return [];
  const out: DeviceRule[] = [];
  const page = (ifaces: string[], groups?: string[]) => (ifaces.length === 1 && !groups?.length ? `/firewall/rules/${ifaces[0]}` : '/firewall/rules');
  for (const r of m.firewall.rules) {
    if (r.kind === 'raw') {
      const a = v4.find((x) => new RegExp(`(^|[^0-9.])${x.replace(/\./g, '\\.')}([^0-9]|$)`).test(r.text));
      if (a) out.push({ kind: 'raw', id: r.id, enabled: r.enabled, description: r.description || r.text, how: 'written in pf, naming its address', to: page(r.interfaces, r.groups), exact: true });
      continue;
    }
    for (const a of v4) {
      const from = endpointHolds(r.source, a, m.firewall.aliases);
      const to = endpointHolds(r.destination, a, m.firewall.aliases);
      if (from || to) {
        const how = [from && `from it, ${from}`, to && `to it, ${to}`].filter(Boolean).join('; ');
        const exact = [from, to].some((h) => h && !h.includes('network it’s in'));
        out.push({ kind: 'rule', id: r.id, enabled: r.enabled, description: `${r.action === 'pass' ? 'Allow' : r.action === 'block' ? 'Block' : r.action}: ${r.description || 'no description'}`, how, to: page(r.interfaces, r.groups), exact });
        break;
      }
    }
  }
  for (const f of m.firewall.forwards) {
    if (v4.includes(f.target.trim())) {
      const iface = m.interfaces.find((i) => i.id === f.iface)?.name ?? f.iface;
      out.push({
        kind: 'forward', id: f.id, enabled: f.enabled, description: f.description || 'Port forward',
        how: `${f.protocol} ${f.externalPort} on ${iface} is sent to it${f.targetPort && f.targetPort !== f.externalPort ? `, port ${f.targetPort}` : ''}`,
        to: '/firewall/nat/forwards', exact: true,
      });
    }
  }
  // What names it first, then what covers a network it's in.
  return out.sort((a, b) => Number(b.exact) - Number(a.exact));
}
