import { Checkbox, Group, Select, Stack, TextInput } from '@mantine/core';
import type { Endpoint, Model } from '../model/types';

type Kind = string; // 'any' | 'self' | 'net:<id>' | 'ifaddr:<id>' | 'host' | 'network' | 'alias:<name>'

function kindOf(e: Endpoint): Kind {
  switch (e.type) {
    case 'net':
      return `net:${e.iface}`;
    case 'ifaddr':
      return `ifaddr:${e.iface}`;
    case 'alias':
      return `alias:${e.alias}`;
    default:
      return e.type;
  }
}

function fromKind(kind: Kind, value: string, not: boolean): Endpoint {
  const n = not ? { not: true } : {};
  if (kind.startsWith('net:')) return { type: 'net', iface: kind.slice(4), ...n };
  if (kind.startsWith('ifaddr:')) return { type: 'ifaddr', iface: kind.slice(7), ...n };
  if (kind.startsWith('alias:')) return { type: 'alias', alias: kind.slice(6), ...n };
  if (kind === 'host' || kind === 'network') return { type: kind, value, ...n };
  if (kind === 'self') return { type: 'self', ...n };
  return { type: 'any' };
}

export function endpointOptions(m: Model) {
  return [
    { group: 'General', items: [{ value: 'any', label: 'Any' }, { value: 'self', label: 'This firewall (all addresses)' }] },
    { group: 'Networks', items: m.interfaces.map((i) => ({ value: `net:${i.id}`, label: `${i.name} network` })) },
    { group: 'Interface addresses', items: m.interfaces.map((i) => ({ value: `ifaddr:${i.id}`, label: `${i.name} address` })) },
    { group: 'Aliases', items: m.firewall.aliases.filter((a) => a.type !== 'ports').map((a) => ({ value: `alias:${a.name}`, label: a.name })) },
    { group: 'Custom', items: [{ value: 'host', label: 'Single address…' }, { value: 'network', label: 'Network (CIDR)…' }] },
  ];
}

export function validateEndpoint(e: Endpoint, isIPv4: (s: string) => boolean, isCIDR: (s: string) => boolean): string | null {
  if (e.type === 'host') return isIPv4(e.value) ? null : 'Enter an address like 192.168.1.50';
  if (e.type === 'network') return isCIDR(e.value) ? null : 'Enter a network like 192.168.1.0/24';
  return null;
}

export function EndpointField({ label, value, onChange, model, error }: {
  label: string; value: Endpoint; onChange: (e: Endpoint) => void; model: Model; error?: React.ReactNode;
}) {
  const kind = kindOf(value);
  const custom = value.type === 'host' || value.type === 'network';
  return (
    <Stack gap={6}>
      <Select
        label={label}
        data={endpointOptions(model)}
        value={kind}
        allowDeselect={false}
        searchable
        onChange={(k) => k && onChange(fromKind(k, custom ? value.value : '', !!value.not))}
      />
      {custom && (
        <TextInput
          aria-label={`${label} address`}
          placeholder={value.type === 'host' ? '192.168.1.50' : '192.168.1.0/24'}
          value={value.value}
          error={error}
          styles={{ input: { fontFamily: 'var(--mantine-font-family-monospace)' } }}
          onChange={(ev) => onChange({ ...value, value: ev.currentTarget.value })}
        />
      )}
      {value.type !== 'any' && (
        <Group>
          <Checkbox
            size="xs"
            label="Everything except this"
            checked={!!value.not}
            onChange={(ev) => onChange(fromKind(kind, custom ? value.value : '', ev.currentTarget.checked))}
          />
        </Group>
      )}
    </Stack>
  );
}
