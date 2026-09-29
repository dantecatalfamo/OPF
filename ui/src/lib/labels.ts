import type { Endpoint, Model, Protocol } from '../model/types';

export function ifaceName(m: Model, id: string): string {
  return m.interfaces.find((i) => i.id === id)?.name ?? id;
}

/** Maps a kernel device name (em0, vlan20) to its user-friendly name. */
export function deviceName(m: Model, device: string): string {
  return m.interfaces.find((i) => i.device === device)?.name ?? device;
}

export function endpointLabel(e: Endpoint, m: Model): string {
  const not = e.not ? 'Not ' : '';
  switch (e.type) {
    case 'any':
      return 'Any';
    case 'self': {
      const part = e.part ? ` ${e.part}s` : '';
      return `${not}This firewall${part}${e.noAlias ? ' (primary)' : ''}`;
    }
    case 'iface': {
      const name = e.iface ? ifaceName(m, e.iface) : e.group;
      return `${not}${name} ${e.part ?? 'address'}${e.noAlias ? ' (primary)' : ''}`;
    }
    case 'host':
    case 'network':
      return `${not}${e.value}`;
    case 'alias':
      return `${not}${e.alias}`;
  }
}

export const protocolLabel: Record<Protocol, string> = {
  any: 'Any',
  tcp: 'TCP',
  udp: 'UDP',
  'tcp/udp': 'TCP/UDP',
  icmp: 'ICMP',
  icmp6: 'ICMPv6',
  esp: 'ESP',
  gre: 'GRE',
};

const wellKnown: Record<string, string> = {
  '22': 'SSH', '53': 'DNS', '80': 'HTTP', '123': 'NTP', '443': 'HTTPS', '51820': 'WireGuard',
  '3389': 'RDP', '445': 'SMB', '25': 'SMTP', '993': 'IMAPS', '587': 'Submission',
};

export function portLabel(spec?: string): string {
  if (!spec) return 'Any';
  if (spec.startsWith('alias:')) return spec.slice(6);
  if (!/^\d+$/.test(spec)) return spec;
  return wellKnown[spec] ? `${spec} (${wellKnown[spec]})` : spec;
}

export const commonPorts = Object.entries(wellKnown).map(([value, name]) => ({ value, label: `${value} · ${name}` }));
