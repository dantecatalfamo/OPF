// Who uses an alias: firewall rules (as source, destination, ports,
// their overload table, or in a raw rule's text), port forwards and
// outbound NAT rules, each with a link that opens it.
import type { Model, Rule } from '../model/types';
import { isFloating } from './rules';

export interface AliasUser {
  kind: 'rule' | 'forward' | 'nat';
  id: string;
  label: string;
  /** Where it is: "Rule on LAN", "Floating rule", "Port forward on WAN". */
  where: string;
  /** How it uses the alias: "source", "destination", "overload"... */
  how: string[];
  to: string;
}

const ifaceName = (m: Model, id: string) => m.interfaces.find((i) => i.id === id)?.name ?? id;

/** A rule's tab on the Rules page. */
export const ruleTab = (r: Rule) => (isFloating(r) ? 'floating' : r.interfaces[0]);

/** A link that opens a rule's editor: on its tab, or Sign-in access's for a rule for signed-in users. */
export const ruleLink = (m: Model, id: string): string => {
  const r = m.firewall.rules.find((x) => x.id === id);
  if (r?.authpf) return `/firewall/authpf?edit=${encodeURIComponent(id)}`;
  return r ? `/firewall/rules/${encodeURIComponent(ruleTab(r))}?edit=${encodeURIComponent(id)}` : '/firewall/rules';
};

export function aliasUsers(m: Model, name: string): AliasUser[] {
  const out: AliasUser[] = [];
  const isIt = (e: { type: string; alias?: string }) => e.type === 'alias' && e.alias === name;
  const port = `alias:${name}`;
  for (const r of m.firewall.rules) {
    const how: string[] = [];
    if (r.kind === 'raw') {
      if (r.text.includes(`<${name}>`)) how.push('in its text');
    } else {
      if (isIt(r.source)) how.push('source');
      if (isIt(r.destination)) how.push('destination');
      if (r.port === port) how.push('port');
      if (r.sourcePort === port) how.push('source port');
      if (r.state?.overload === name) how.push('overload');
    }
    if (how.length) {
      const where = r.authpf ? 'Rule for signed-in users' : isFloating(r) ? 'Floating rule' : `Rule on ${ifaceName(m, r.interfaces[0])}`;
      out.push({ kind: 'rule', id: r.id, label: r.description || `Rule ${r.id}`, where, how, to: ruleLink(m, r.id) });
    }
  }
  for (const f of m.firewall.forwards) {
    const how: string[] = [];
    if (isIt(f.source)) how.push('source');
    if (f.externalPort === port || f.targetPort === port) how.push('port');
    if (how.length) {
      out.push({ kind: 'forward', id: f.id, label: f.description || `Port forward ${f.id}`, where: `Port forward on ${ifaceName(m, f.iface)}`, how, to: `/firewall/nat/forwards?edit=${encodeURIComponent(f.id)}` });
    }
  }
  for (const r of m.firewall.outboundNat.rules) {
    const how: string[] = [];
    if (isIt(r.source)) how.push('source');
    if (isIt(r.destination)) how.push('destination');
    if (how.length) {
      out.push({ kind: 'nat', id: r.id, label: r.description || `Outbound NAT ${r.id}`, where: `Outbound NAT on ${ifaceName(m, r.iface)}`, how, to: `/firewall/nat/outbound?edit=${encodeURIComponent(r.id)}` });
    }
  }
  return out;
}
