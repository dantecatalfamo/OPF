import { useMemo, useState } from 'react';
import { ActionIcon, Badge, Card, Group, SegmentedControl, Table, Text, TextInput, Tooltip } from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { IconSearch, IconX } from '@tabler/icons-react';
import { useStore } from '../model/store';
import { connections, pfStats } from '../model/live';
import { formatBytes, formatDuration } from '../lib/format';
import { ifaceName } from '../lib/labels';
import { Mono, PageHeader } from '../components/ui';

export function Connections() {
  const { applied } = useStore();
  const [all, setAll] = useState(connections);
  const [q, setQ] = useState('');
  const [proto, setProto] = useState('all');

  const rows = useMemo(
    () =>
      all
        .filter((c) => proto === 'all' || c.proto === proto)
        .filter((c) => !q || `${c.source} ${c.destination}`.includes(q.trim()))
        .sort((a, b) => b.bytes - a.bytes),
    [all, q, proto],
  );

  return (
    <>
      <PageHeader
        title="Connections"
        description={`${pfStats.states} open connections through the firewall. Closing one ends it immediately; the device can reconnect if the rules allow.`}
      />
      <Group mb="md" gap="sm">
        <TextInput placeholder="Filter by address" leftSection={<IconSearch size={16} />} value={q} onChange={(e) => setQ(e.currentTarget.value)} style={{ flex: '1 1 240px' }} />
        <SegmentedControl
          value={proto}
          onChange={setProto}
          data={[{ value: 'all', label: 'All' }, { value: 'tcp', label: 'TCP' }, { value: 'udp', label: 'UDP' }, { value: 'icmp', label: 'ICMP' }]}
        />
      </Group>
      <Card padding={0}>
        <Table.ScrollContainer minWidth={860}>
          <Table highlightOnHover striped>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Protocol</Table.Th>
                <Table.Th>From</Table.Th>
                <Table.Th>To</Table.Th>
                <Table.Th>State</Table.Th>
                <Table.Th ta="right">Age</Table.Th>
                <Table.Th ta="right">Data</Table.Th>
                <Table.Th />
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {rows.map((c) => (
                <Table.Tr key={c.id}>
                  <Table.Td>
                    <Group gap={6} wrap="nowrap">
                      <Badge color="gray" w={52}>{c.proto.toUpperCase()}</Badge>
                      <Text size="xs" c="dimmed">{ifaceName(applied, c.iface)}</Text>
                    </Group>
                  </Table.Td>
                  <Table.Td><Mono>{c.source}</Mono></Table.Td>
                  <Table.Td><Mono>{c.destination}</Mono></Table.Td>
                  <Table.Td><Text size="xs" c="dimmed" className="mono">{c.state}</Text></Table.Td>
                  <Table.Td ta="right"><Text size="sm" className="num">{formatDuration(c.ageSec)}</Text></Table.Td>
                  <Table.Td ta="right"><Text size="sm" className="num">{formatBytes(c.bytes)}</Text></Table.Td>
                  <Table.Td w={44}>
                    <Tooltip label="Close connection">
                      <ActionIcon
                        variant="subtle"
                        color="gray"
                        aria-label="Close connection"
                        onClick={() => {
                          setAll((a) => a.filter((x) => x.id !== c.id));
                          notifications.show({ message: `Closed ${c.source} → ${c.destination}` });
                        }}
                      >
                        <IconX size={16} />
                      </ActionIcon>
                    </Tooltip>
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
        {rows.length === 0 && <Text size="sm" c="dimmed" ta="center" py="xl">No connections match.</Text>}
      </Card>
    </>
  );
}
