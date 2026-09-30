import { useMemo, useState } from 'react';
import { Link } from 'react-router';
import { ActionIcon, Alert, Anchor, Badge, Card, Group, SegmentedControl, Stack, Table, Text, TextInput, Tooltip } from '@mantine/core';
import { useMediaQuery } from '@mantine/hooks';
import { notifications } from '@mantine/notifications';
import { IconSearch, IconX } from '@tabler/icons-react';
import { backend, useStore } from '../model/store';
import { formatBytes, formatDuration } from '../lib/format';
import { deviceName } from '../lib/labels';
import { refreshLive, useLive } from '../lib/live';
import { labelOwner } from '../lib/pfLabels';
import type { PfState } from '../lib/api';
import { Mono, PageHeader } from '../components/ui';

const protoGroup = (p: string) => (p === 'ipv6-icmp' ? 'icmp' : p);

// pf's state names for each side ("ESTABLISHED:FIN_WAIT_2") as one word
// for the table; the raw pair is in the tooltip.
function stateLabel(state: string): string {
  const sides = state.split(':');
  if (sides.every((x) => x === 'ESTABLISHED')) return 'Open';
  if (sides.some((x) => /FIN_WAIT|CLOSING|TIME_WAIT|CLOSED/.test(x))) return 'Closing';
  if (sides.some((x) => /SYN_SENT|SYN_RCVD|LISTEN/.test(x))) return 'Opening';
  if (sides.some((x) => x === 'MULTIPLE')) return 'Active';
  if (sides.some((x) => x === 'SINGLE')) return 'One-way';
  if (sides.some((x) => x === 'NO_TRAFFIC')) return 'Waiting';
  return state;
}

function Proto({ c }: { c: PfState }) {
  const { applied } = useStore();
  return (
    <Group gap={6} wrap="nowrap">
      <Badge color="gray" w={52}>{protoGroup(c.proto).toUpperCase()}</Badge>
      <Text size="xs" c="dimmed" style={{ whiteSpace: 'nowrap' }}>{c.direction === 'in' ? 'In' : 'Out'}{c.iface !== 'all' ? ` on ${deviceName(applied, c.iface)}` : ''}</Text>
    </Group>
  );
}

function From({ c }: { c: PfState }) {
  return (
    <div>
      <Mono>{c.source}</Mono>
      {c.translated && c.direction === 'out' && <Text size="xs" c="dimmed">leaves as <Mono c="dimmed">{c.translated}</Mono></Text>}
    </div>
  );
}

function To({ c }: { c: PfState }) {
  return (
    <div>
      <Mono>{c.destination}</Mono>
      {c.translated && c.direction === 'in' && <Text size="xs" c="dimmed">sent to <Mono c="dimmed">{c.translated}</Mono></Text>}
    </div>
  );
}

function AllowedBy({ c }: { c: PfState }) {
  const { applied } = useStore();
  const owner = labelOwner(applied, c.label);
  if (!owner) return <Text size="sm" c="dimmed">{c.rule >= 0 ? `pf rule ${c.rule}` : '—'}</Text>;
  return owner.to ? <Anchor component={Link} to={owner.to} size="sm">{owner.text}</Anchor> : <Text size="sm">{owner.text}</Text>;
}

function State({ c }: { c: PfState }) {
  return (
    <Tooltip label={c.state}>
      <Text size="xs" c="dimmed" style={{ whiteSpace: 'nowrap' }}>{stateLabel(c.state)}</Text>
    </Tooltip>
  );
}

function Close({ c, onClose }: { c: PfState; onClose: (c: PfState) => void }) {
  return (
    <Tooltip label="Close connection">
      <ActionIcon variant="subtle" color="gray" aria-label="Close connection" onClick={() => onClose(c)}>
        <IconX size={16} />
      </ActionIcon>
    </Tooltip>
  );
}

export function Connections() {
  // The table needs about 820 px beside the navigation.
  const wide = useMediaQuery('(min-width: 75em)') ?? true;
  const { data, error } = useLive('pfStates');
  const [closed, setClosed] = useState<Set<string>>(new Set());
  const [q, setQ] = useState('');
  const [proto, setProto] = useState('all');

  const rows = useMemo(
    () =>
      (data?.states ?? [])
        .filter((c) => !closed.has(c.id))
        .filter((c) => proto === 'all' || protoGroup(c.proto) === proto)
        .filter((c) => !q || `${c.source} ${c.destination} ${c.translated ?? ''}`.includes(q.trim()))
        .sort((a, b) => b.bytes - a.bytes),
    [data, closed, q, proto],
  );

  const close = async (c: PfState) => {
    try {
      await backend.killState(c);
      setClosed((s) => new Set(s).add(c.id));
      notifications.show({ message: `Closed ${c.source} → ${c.destination}` });
      refreshLive('pfStates');
    } catch (e) {
      notifications.show({ color: 'red', title: 'Couldn’t close the connection', message: e instanceof Error ? e.message : String(e) });
    }
  };

  const count = data ? data.states.length : undefined;
  return (
    <>
      <PageHeader
        title="Connections"
        description={
          count === undefined
            ? 'Reading pf’s state table…'
            : `${count.toLocaleString()}${data?.truncated ? '+' : ''} entries in pf’s state table. A connection through the firewall has one on each side. Closing one ends it at once; the device can reconnect if the rules allow.`
        }
      />
      {(error || data?.error) && <Alert color="red" variant="light" mb="md">{data?.error ?? error}</Alert>}
      {data?.truncated && <Alert color="yellow" variant="light" mb="md">Showing the first {data.states.length.toLocaleString()}. Filter to find a particular one.</Alert>}
      <Group mb="md" gap="sm">
        <TextInput placeholder="Filter by address" leftSection={<IconSearch size={16} />} value={q} onChange={(e) => setQ(e.currentTarget.value)} style={{ flex: '1 1 240px' }} />
        <SegmentedControl
          value={proto}
          onChange={setProto}
          data={[{ value: 'all', label: 'All' }, { value: 'tcp', label: 'TCP' }, { value: 'udp', label: 'UDP' }, { value: 'icmp', label: 'ICMP' }]}
        />
      </Group>
      <Card padding={0}>
        {wide ? (
          <Table highlightOnHover striped>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Protocol</Table.Th>
                <Table.Th>From</Table.Th>
                <Table.Th>To</Table.Th>
                <Table.Th>Allowed by</Table.Th>
                <Table.Th ta="right">Age</Table.Th>
                <Table.Th ta="right">Data</Table.Th>
                <Table.Th />
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {rows.map((c) => (
                <Table.Tr key={c.id}>
                  <Table.Td><Proto c={c} /></Table.Td>
                  <Table.Td style={{ whiteSpace: 'nowrap' }}><From c={c} /></Table.Td>
                  <Table.Td style={{ whiteSpace: 'nowrap' }}><To c={c} /></Table.Td>
                  <Table.Td miw={150}><AllowedBy c={c} /></Table.Td>
                  <Table.Td ta="right">
                    <Text size="sm" className="num" style={{ whiteSpace: 'nowrap' }}>{formatDuration(c.ageSec)}</Text>
                    <State c={c} />
                  </Table.Td>
                  <Table.Td ta="right"><Text size="sm" className="num" style={{ whiteSpace: 'nowrap' }}>{formatBytes(c.bytes)}</Text></Table.Td>
                  <Table.Td w={44}><Close c={c} onClose={close} /></Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        ) : (
          // Too narrow for the columns: each connection in two lines.
          <Stack gap={0}>
            {rows.map((c, n) => (
              <Group key={c.id} wrap="nowrap" align="flex-start" gap="sm" px="md" py="sm" style={n ? { borderTop: '1px solid var(--mantine-color-default-border)' } : undefined}>
                <Stack gap={4} style={{ flex: 1, minWidth: 0 }}>
                  <Group gap={8} wrap="wrap" align="flex-start" style={{ rowGap: 2 }}>
                    <Proto c={c} />
                    <From c={c} />
                    <Text size="sm" c="dimmed">→</Text>
                    <To c={c} />
                  </Group>
                  <Group gap={6} wrap="wrap" style={{ rowGap: 2 }}>
                    <AllowedBy c={c} />
                    <Text size="xs" c="dimmed" className="num">· {formatDuration(c.ageSec)} · {formatBytes(c.bytes)} ·</Text>
                    <State c={c} />
                  </Group>
                </Stack>
                <Close c={c} onClose={close} />
              </Group>
            ))}
          </Stack>
        )}
        {data && rows.length === 0 && <Text size="sm" c="dimmed" ta="center" py="xl">{data.states.length ? 'No connections match.' : 'No connections.'}</Text>}
      </Card>
    </>
  );
}
