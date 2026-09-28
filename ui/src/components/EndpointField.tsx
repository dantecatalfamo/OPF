import { Checkbox, Group, SegmentedControl, Select, Stack, Text, TextInput } from '@mantine/core';
import type { Endpoint, IfaceEndpoint, IfacePart, Model } from '../model/types';
import { ifaceDynamic } from '../model/generate';

// The picker's value: 'any' | 'self' | 'iface:<id>' | 'group:<name>' |
// 'group:' (a group typed in) | 'host' | 'network' | 'alias:<name>'
type Kind = string;

const knownGroups = [{ name: 'egress', label: 'egress (interfaces with a default route)' }];

function kindOf(e: Endpoint): Kind {
  switch (e.type) {
    case 'iface':
      if (e.iface) return `iface:${e.iface}`;
      return knownGroups.some((g) => g.name === e.group) ? `group:${e.group}` : 'group:';
    case 'alias':
      return `alias:${e.alias}`;
    default:
      return e.type;
  }
}

// Switching targets keeps the interface options, so "LAN network"
// becomes "IoT network" rather than "IoT address".
function fromKind(kind: Kind, prev: Endpoint): Endpoint {
  const n = prev.not ? { not: true } : {};
  const opts = prev.type === 'iface' ? { part: prev.part, noAlias: prev.noAlias, dynamic: prev.dynamic } : { part: 'network' as IfacePart };
  if (kind.startsWith('iface:')) return { type: 'iface', iface: kind.slice(6), ...opts, ...n };
  if (kind.startsWith('group:')) return { type: 'iface', group: kind.slice(6), ...opts, ...n };
  if (kind.startsWith('alias:')) return { type: 'alias', alias: kind.slice(6), ...n };
  if (kind === 'host' || kind === 'network') return { type: kind, value: prev.type === 'host' || prev.type === 'network' ? prev.value : '', ...n };
  if (kind === 'self') return { type: 'self', ...n };
  return { type: 'any' };
}

export function endpointOptions(m: Model) {
  return [
    { group: 'General', items: [{ value: 'any', label: 'Any' }, { value: 'self', label: 'This firewall (all addresses)' }] },
    { group: 'Interfaces', items: m.interfaces.map((i) => ({ value: `iface:${i.id}`, label: i.name })) },
    {
      group: 'Interface groups',
      items: [...knownGroups.map((g) => ({ value: `group:${g.name}`, label: g.label })), { value: 'group:', label: 'Other group or interface…' }],
    },
    { group: 'Aliases', items: m.firewall.aliases.filter((a) => a.type !== 'ports').map((a) => ({ value: `alias:${a.name}`, label: a.name })) },
    { group: 'Custom', items: [{ value: 'host', label: 'Single address…' }, { value: 'network', label: 'Network (CIDR)…' }] },
  ];
}

// Interface group names follow ifconfig(8): they can't end in a digit.
const isGroupName = (s: string) => /^[A-Za-z_][A-Za-z0-9_]{0,14}$/.test(s) && !/\d$/.test(s);
const isDeviceName = (s: string) => /^[a-z]+[0-9]+$/.test(s);

export function validateEndpoint(e: Endpoint, isIPv4: (s: string) => boolean, isCIDR: (s: string) => boolean): string | null {
  if (e.type === 'host') return isIPv4(e.value) ? null : 'Enter an address like 192.168.1.50';
  if (e.type === 'network') return isCIDR(e.value) ? null : 'Enter a network like 192.168.1.0/24';
  if (e.type === 'iface' && !e.iface) {
    const g = e.group ?? '';
    return isGroupName(g) || isDeviceName(g) ? null : 'Enter a group like egress or an interface like em2';
  }
  return null;
}

const partLabels: { value: IfacePart | 'address'; label: string }[] = [
  { value: 'address', label: 'Address' },
  { value: 'network', label: 'Network' },
  { value: 'broadcast', label: 'Broadcast' },
  { value: 'peer', label: 'Peer' },
];

function IfaceOptions({ value, onChange, model }: { value: IfaceEndpoint; onChange: (e: Endpoint) => void; model: Model }) {
  const auto = ifaceDynamic({ ...value, dynamic: undefined }, model);
  const help = {
    address: 'The addresses assigned to it.',
    network: 'The networks attached to it.',
    broadcast: 'Its broadcast addresses.',
    peer: 'The far end of a point-to-point link, such as a tunnel.',
  }[value.part ?? 'address'];
  return (
    <Stack gap={6}>
      <SegmentedControl
        size="xs"
        data={partLabels}
        value={value.part ?? 'address'}
        onChange={(p) => onChange({ ...value, part: p === 'address' ? undefined : (p as IfacePart) })}
      />
      <Text size="xs" c="dimmed">{help}</Text>
      <Group gap="md" align="flex-end">
        <Checkbox
          size="xs"
          label="Primary address only"
          title="Leave out alias addresses (:0)"
          checked={!!value.noAlias}
          onChange={(ev) => onChange({ ...value, noAlias: ev.currentTarget.checked || undefined })}
        />
        <Select
          size="xs"
          w={300}
          aria-label="Follow address changes"
          allowDeselect={false}
          value={value.dynamic === undefined ? 'auto' : value.dynamic ? 'yes' : 'no'}
          data={[
            { value: 'auto', label: `Follow address changes: automatic (${auto ? 'yes' : 'no'})` },
            { value: 'yes', label: 'Follow address changes: always' },
            { value: 'no', label: 'Follow address changes: never' },
          ]}
          onChange={(d) => onChange({ ...value, dynamic: d === 'auto' ? undefined : d === 'yes' })}
        />
      </Group>
    </Stack>
  );
}

export function EndpointField({ label, value, onChange, model, error }: {
  label: string; value: Endpoint; onChange: (e: Endpoint) => void; model: Model; error?: React.ReactNode;
}) {
  const kind = kindOf(value);
  const custom = value.type === 'host' || value.type === 'network';
  const typedGroup = kind === 'group:';
  return (
    <Stack gap={6}>
      <Select label={label} data={endpointOptions(model)} value={kind} allowDeselect={false} searchable onChange={(k) => k && onChange(fromKind(k, value))} />
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
      {typedGroup && value.type === 'iface' && (
        <TextInput
          aria-label={`${label} group or interface`}
          placeholder="wg or em2"
          value={value.group ?? ''}
          error={error}
          styles={{ input: { fontFamily: 'var(--mantine-font-family-monospace)' } }}
          onChange={(ev) => onChange({ ...value, group: ev.currentTarget.value })}
        />
      )}
      {value.type === 'iface' && <IfaceOptions value={value} onChange={onChange} model={model} />}
      {value.type !== 'any' && (
        <Checkbox
          size="xs"
          label="Everything except this"
          checked={!!value.not}
          onChange={(ev) => onChange({ ...value, not: ev.currentTarget.checked || undefined })}
        />
      )}
    </Stack>
  );
}
