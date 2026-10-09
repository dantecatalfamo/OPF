import { useState } from 'react';
import { Link } from 'react-router';
import { Alert, Anchor, Box, Card, Group, SegmentedControl, Select, Stack, Table, Text, TextInput, Tooltip } from '@mantine/core';
import { useMediaQuery } from '@mantine/hooks';
import { IconArrowRight, IconSearch } from '@tabler/icons-react';
import { useStore } from '../model/store';
import { deviceName } from '../lib/labels';
import { formatLogTime } from '../lib/format';
import { useLive } from '../lib/live';
import { labelOwner } from '../lib/pfLabels';
import type { DeviceInfo, FirewallLogEntry } from '../lib/api';
import type { Model } from '../model/types';
import { Mono, PageHeader } from '../components/ui';
import { HostName, NamesSwitch } from '../components/HostName';
import { hostOf, useReverseNames, useShowNames } from '../lib/reverseNames';
import { protoGroup } from '../lib/connections';
import { DirLabel, ProtoBadge } from '../components/ConnBadges';
import { AddressLink, useKnownDevices } from '../components/DeviceLink';

const actionColor: Record<string, string> = { block: 'red', pass: 'teal', match: 'gray' };
const actionText: Record<string, string> = { block: 'Blocked', pass: 'Allowed', match: 'Matched' };

/** The rule that logged an entry, in words, and why it's missing when it is. */
export function LogRule({ e, model }: { e: FirewallLogEntry; model: Model }) {
  const owner = labelOwner(model, e.label);
  if (e.rule < 0) {
    return (
      <Tooltip label="No rule logged this. pf did it itself, for example by dropping a packet with IP options." multiline w={260}>
        <Text size="sm" c="dimmed">pf’s default rule</Text>
      </Tooltip>
    );
  }
  if (owner) return owner.to ? <Anchor component={Link} to={owner.to} size="sm">{owner.text}</Anchor> : <Text size="sm">{owner.text}</Text>;
  const why = e.anchor
    ? `Rule ${e.rule} in anchor ${e.anchor}.`
    : e.label
      ? `Its label, ${e.label}, isn’t in the configuration any more.`
      : `pf rule ${e.rule}. The rules have been reloaded since, so which rule that was isn’t known.`;
  return (
    <Tooltip label={why} multiline w={260}>
      <Text size="sm" c="dimmed">{e.anchor ? `${e.anchor} rule ${e.rule}` : `pf rule ${e.rule}`}</Text>
    </Tooltip>
  );
}

const protoOf = (e: FirewallLogEntry) => (e.proto ? protoGroup(e.proto) : '');

/** Its protocol and pf's way, in or out on an interface: the badge
 *  first, its width fixed, so the rows line up. */
function LogWay({ e }: { e: FirewallLogEntry }) {
  const { applied } = useStore();
  return (
    <Group gap={8} wrap="nowrap">
      {e.proto ? <ProtoBadge proto={protoOf(e)} /> : <Box w={52} style={{ flexShrink: 0 }} />}
      <DirLabel dir={e.direction}>{e.direction === 'in' ? 'In' : 'Out'} on {deviceName(applied, e.iface)}</DirLabel>
    </Group>
  );
}

function LogEnd({ end, names, devices }: { end?: string; names: Map<string, string>; devices: Map<string, DeviceInfo> }) {
  if (!end) return <Mono c="dimmed">—</Mono>;
  return (
    <div>
      <AddressLink end={end} devices={devices} />
      <HostName addr={end} names={names} />
    </div>
  );
}

/** What pf did with it, in its colour: Blocked, Allowed, Matched. */
export const LogAction = ({ e }: { e: FirewallLogEntry }) => (
  <Text span size="sm" fw={500} c={actionColor[e.action] ?? 'dimmed'} style={{ whiteSpace: 'nowrap' }}>{actionText[e.action] ?? e.action}</Text>
);

/** When, the full date on hover. */
export function LogTime({ e }: { e: FirewallLogEntry }) {
  return (
    <Tooltip label={new Date(e.time).toLocaleString()}>
      <Text size="xs" c="dimmed" className="num" style={{ whiteSpace: 'nowrap' }}>{formatLogTime(e.time)}</Text>
    </Tooltip>
  );
}

// Why pf logged it when it wasn't a rule's match: a short or bad packet.
const LogReason = ({ e }: { e: FirewallLogEntry }) => (e.reason !== 'match' ? <Text size="xs" c="yellow">{e.reason}: {e.info}</Text> : null);

export function FirewallLog() {
  const { applied } = useStore();
  const { data, error } = useLive('firewallLog');
  // The table needs about 900 px beside the navigation.
  const wide = useMediaQuery('(min-width: 75em)') ?? true;
  const [q, setQ] = useState('');
  const [iface, setIface] = useState<string | null>(null);
  const [proto, setProto] = useState('all');
  const [dir, setDir] = useState('both');
  const [action, setAction] = useState('all');
  const devices = useKnownDevices();
  const entries = data?.entries ?? [];
  const filtered = !!q || !!iface || proto !== 'all' || dir !== 'both' || action !== 'all';
  const rows = entries.filter((e) => {
    if (iface && e.iface !== iface) return false;
    if (proto !== 'all' && protoOf(e) !== proto) return false;
    if (dir !== 'both' && e.direction !== dir) return false;
    if (action !== 'all' && e.action !== action) return false;
    if (!q) return true;
    const rule = labelOwner(applied, e.label)?.text ?? '';
    const device = (end?: string) => { const d = devices.get(hostOf(end) ?? ''); return d ? `${d.name ?? ''} ${d.mac ?? ''}` : ''; };
    return `${e.source ?? ''} ${e.destination ?? ''} ${rule} ${device(e.source)} ${device(e.destination)}`.toLowerCase().includes(q.toLowerCase());
  });
  const [showNames, setShowNames] = useShowNames();
  const names = useReverseNames(rows.flatMap((e) => [e.source, e.destination]), showNames);

  return (
    <>
      <PageHeader title="Firewall log" description="Traffic matched by rules that have logging turned on, newest first. Shows the last 500 entries pf has kept. In means a packet arriving on an interface, and out means a packet leaving by it." />
      {(error || data?.error) && <Alert color="red" variant="light" mb="md">{data?.error ?? error}</Alert>}
      <Group mb="md" gap="sm">
        <TextInput placeholder="Filter by address, device or rule" leftSection={<IconSearch size={16} />} value={q} onChange={(e) => setQ(e.currentTarget.value)} style={{ flex: '1 1 240px' }} />
        <SegmentedControl
          value={action}
          onChange={setAction}
          aria-label="Action"
          data={[{ value: 'all', label: 'Any' }, { value: 'block', label: 'Blocked' }, { value: 'pass', label: 'Allowed' }]}
        />
        <SegmentedControl
          value={proto}
          onChange={setProto}
          aria-label="Protocol"
          data={[{ value: 'all', label: 'All' }, { value: 'tcp', label: 'TCP' }, { value: 'udp', label: 'UDP' }, { value: 'icmp', label: 'ICMP' }]}
        />
        <SegmentedControl
          value={dir}
          onChange={setDir}
          aria-label="Way"
          data={[
            { value: 'both', label: 'In and out' },
            { value: 'in', label: <DirLabel dir="in">In</DirLabel> },
            { value: 'out', label: <DirLabel dir="out">Out</DirLabel> },
          ]}
        />
        <Select
          placeholder="All interfaces"
          clearable
          value={iface}
          onChange={setIface}
          aria-label="Interface"
          data={applied.interfaces.map((i) => ({ value: i.device, label: i.name }))}
          w={170}
        />
        <NamesSwitch checked={showNames} onChange={setShowNames} />
      </Group>
      <Card padding={0}>
        {wide ? (
          <Table highlightOnHover>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>When</Table.Th>
                <Table.Th>Direction</Table.Th>
                <Table.Th>From</Table.Th>
                <Table.Th>To</Table.Th>
                <Table.Th>Rule</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {rows.map((e, i) => (
                <Table.Tr key={`${e.time}-${i}`}>
                  <Table.Td>
                    <LogAction e={e} />
                    <LogTime e={e} />
                  </Table.Td>
                  <Table.Td><LogWay e={e} /></Table.Td>
                  <Table.Td style={{ whiteSpace: 'nowrap' }}><LogEnd end={e.source} names={names} devices={devices} /></Table.Td>
                  <Table.Td style={{ whiteSpace: 'nowrap' }}>
                    <LogEnd end={e.destination} names={names} devices={devices} />
                    <LogReason e={e} />
                  </Table.Td>
                  <Table.Td miw={150}><LogRule e={e} model={applied} /></Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        ) : (
          // Too narrow for the columns: each entry in two lines.
          <Stack gap={0}>
            {rows.map((e, n) => (
              <Stack key={`${e.time}-${n}`} gap={4} px="md" py="sm" style={n ? { borderTop: '1px solid var(--mantine-color-default-border)' } : undefined}>
                <Group gap={10} wrap="wrap" align="flex-start" style={{ rowGap: 2 }}>
                  <LogAction e={e} />
                  <LogWay e={e} />
                </Group>
                <Group gap={8} wrap="wrap" align="flex-start" style={{ rowGap: 2 }}>
                  <LogEnd end={e.source} names={names} devices={devices} />
                  <IconArrowRight size={16} color="var(--mantine-color-dimmed)" style={{ marginTop: 2, flexShrink: 0 }} />
                  <LogEnd end={e.destination} names={names} devices={devices} />
                </Group>
                <LogReason e={e} />
                <Group gap={6} wrap="wrap" style={{ rowGap: 2 }}>
                  <LogTime e={e} />
                  <Text size="xs" c="dimmed">·</Text>
                  <LogRule e={e} model={applied} />
                </Group>
              </Stack>
            ))}
          </Stack>
        )}
        {data && rows.length === 0 && (
          <Text size="sm" c="dimmed" ta="center" py="xl">{entries.length ? 'No entries match.' : 'Nothing has been logged yet.'}</Text>
        )}
      </Card>
      {entries.length > 0 && (
        <Text size="xs" c="dimmed" mt="sm">Showing {rows.length.toLocaleString()} of {entries.length.toLocaleString()}{filtered ? ' that match' : ''}</Text>
      )}
    </>
  );
}
