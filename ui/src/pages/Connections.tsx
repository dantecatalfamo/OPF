import { useMemo, useState } from 'react';
import { Link } from 'react-router';
import { ActionIcon, Alert, Anchor, Badge, Card, Group, SegmentedControl, Table, Text, TextInput, Tooltip } from '@mantine/core';
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

export function Connections() {
  const { applied } = useStore();
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
        <Table.ScrollContainer minWidth={960}>
          <Table highlightOnHover striped>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Protocol</Table.Th>
                <Table.Th>From</Table.Th>
                <Table.Th>To</Table.Th>
                <Table.Th>Allowed by</Table.Th>
                <Table.Th>State</Table.Th>
                <Table.Th ta="right">Age</Table.Th>
                <Table.Th ta="right">Data</Table.Th>
                <Table.Th />
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {rows.map((c) => {
                const owner = labelOwner(applied, c.label);
                return (
                  <Table.Tr key={c.id}>
                    <Table.Td>
                      <Group gap={6} wrap="nowrap">
                        <Badge color="gray" w={52}>{protoGroup(c.proto).toUpperCase()}</Badge>
                        <Text size="xs" c="dimmed">{c.direction === 'in' ? 'In' : 'Out'}{c.iface !== 'all' ? ` on ${deviceName(applied, c.iface)}` : ''}</Text>
                      </Group>
                    </Table.Td>
                    <Table.Td>
                      <Mono>{c.source}</Mono>
                      {c.translated && c.direction === 'out' && <Text size="xs" c="dimmed">leaves as <Mono c="dimmed">{c.translated}</Mono></Text>}
                    </Table.Td>
                    <Table.Td>
                      <Mono>{c.destination}</Mono>
                      {c.translated && c.direction === 'in' && <Text size="xs" c="dimmed">sent to <Mono c="dimmed">{c.translated}</Mono></Text>}
                    </Table.Td>
                    <Table.Td>
                      {owner ? (
                        owner.to ? <Anchor component={Link} to={owner.to} size="sm">{owner.text}</Anchor> : <Text size="sm">{owner.text}</Text>
                      ) : (
                        <Text size="sm" c="dimmed">{c.rule >= 0 ? `pf rule ${c.rule}` : '—'}</Text>
                      )}
                    </Table.Td>
                    <Table.Td><Text size="xs" c="dimmed" className="mono">{c.state}</Text></Table.Td>
                    <Table.Td ta="right"><Text size="sm" className="num">{formatDuration(c.ageSec)}</Text></Table.Td>
                    <Table.Td ta="right"><Text size="sm" className="num" style={{ whiteSpace: "nowrap" }}>{formatBytes(c.bytes)}</Text></Table.Td>
                    <Table.Td w={44}>
                      <Tooltip label="Close connection">
                        <ActionIcon variant="subtle" color="gray" aria-label="Close connection" onClick={() => close(c)}>
                          <IconX size={16} />
                        </ActionIcon>
                      </Tooltip>
                    </Table.Td>
                  </Table.Tr>
                );
              })}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
        {data && rows.length === 0 && <Text size="sm" c="dimmed" ta="center" py="xl">{data.states.length ? 'No connections match.' : 'No connections.'}</Text>}
      </Card>
    </>
  );
}
