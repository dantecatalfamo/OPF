// pf labels ("opf:<kind>:<id>", internal/pf.Label) back to what they
// were generated from, in the words and links the Ruleset page uses.
import type { Model } from '../model/types';
import { isFloating } from './rules';

export interface LabelOwner {
  text: string;
  to?: string;
}

const builtins: Record<string, (m: Model) => LabelOwner> = {
  'default-block': () => ({ text: 'Default block', to: '/firewall/settings' }),
  'self-out': () => ({ text: 'This firewall’s own traffic', to: '/firewall/settings' }),
  'anti-lockout': (m) => ({ text: 'Anti-lockout', to: `/interfaces/${m.interfaces.find((i) => i.role === 'lan')?.id ?? ''}` }),
  'block-private': (m) => ({ text: 'Block private networks', to: `/interfaces/${m.interfaces.find((i) => i.role === 'wan')?.id ?? ''}` }),
  'block-bogons': (m) => ({ text: 'Block bogon networks', to: `/interfaces/${m.interfaces.find((i) => i.role === 'wan')?.id ?? ''}` }),
};

/** What a label belongs to in the model, or undefined if it isn't OPF's or its object is gone. */
export function labelOwner(m: Model, label: string | undefined): LabelOwner | undefined {
  const match = label?.match(/^opf:([a-z-]+):([A-Za-z0-9_-]{1,32})$/);
  if (!match) return undefined;
  const [, kind, id] = match;
  const iface = m.interfaces.find((i) => i.id === id);
  switch (kind) {
    case 'rule': {
      const r = m.firewall.rules.find((x) => x.id === id);
      return r && { text: `Rule: ${r.description}`, to: `/firewall/rules/${isFloating(r) ? 'floating' : r.interfaces[0]}` };
    }
    case 'forward': {
      const f = m.firewall.forwards.find((x) => x.id === id);
      return f && { text: `Port forward: ${f.description}`, to: '/firewall/nat' };
    }
    case 'nat': {
      const n = m.firewall.outboundNat.rules.find((x) => x.id === id);
      return n && { text: `Outbound NAT: ${n.description}`, to: '/firewall/nat/outbound' };
    }
    case 'auto-nat':
      return iface && { text: `Automatic outbound NAT for ${iface.name}`, to: '/firewall/nat/outbound' };
    case 'split-tunnel':
      return iface && { text: `WireGuard: ${iface.name} (only your networks)`, to: `/services/wireguard/${iface.id}` };
    case 'antispoof':
      return iface && { text: `Antispoof: ${iface.name}`, to: `/interfaces/${iface.id}` };
    case 'builtin':
      return builtins[id]?.(m);
  }
  return undefined;
}
