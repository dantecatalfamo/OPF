import { useMemo, useState } from 'react';
import { Badge, Card, Group, Select, Table, Text, TextInput } from '@mantine/core';
import { IconSearch } from '@tabler/icons-react';
import { useStore } from '../model/store';
import { logEntries } from '../model/live';
import { ifaceName } from '../lib/labels';
import { Mono, PageHeader } from '../components/ui';

export function FirewallLog() {
  const { applied } = useStore();
  const entries = useMemo(logEntries, []);
  const [q, setQ] = useState('');
  const [iface, setIface] = useState<string | null>(null);
  const rows = entries.filter((e) => (!iface || e.iface === iface) && (!q || `${e.source} ${e.destination} ${e.rule}`.toLowerCase().includes(q.toLowerCase())));

  return (
    <>
      <PageHeader title="Firewall log" description="Traffic matched by rules that have logging turned on, newest first." />
      <Group mb="md" gap="sm">
        <TextInput placeholder="Filter by address or rule" leftSection={<IconSearch size={16} />} value={q} onChange={(e) => setQ(e.currentTarget.value)} style={{ flex: '1 1 240px' }} />
        <Select
          placeholder="All interfaces"
          clearable
          value={iface}
          onChange={setIface}
          data={applied.interfaces.map((i) => ({ value: i.id, label: i.name }))}
          w={180}
        />
      </Group>
      <Card padding={0}>
        <Table.ScrollContainer minWidth={820}>
          <Table highlightOnHover>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Time</Table.Th>
                <Table.Th>Action</Table.Th>
                <Table.Th>Interface</Table.Th>
                <Table.Th>From</Table.Th>
                <Table.Th>To</Table.Th>
                <Table.Th>Rule</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {rows.map((e) => (
                <Table.Tr key={e.id}>
                  <Table.Td><Text size="sm" className="num">{e.time}</Text></Table.Td>
                  <Table.Td><Badge color={e.action === 'block' ? 'red' : 'teal'}>{e.action === 'block' ? 'Blocked' : 'Allowed'}</Badge></Table.Td>
                  <Table.Td><Text size="sm">{ifaceName(applied, e.iface)}</Text></Table.Td>
                  <Table.Td><Mono>{e.source}</Mono></Table.Td>
                  <Table.Td>
                    <Mono>{e.destination}</Mono> <Text span size="xs" c="dimmed">{e.proto.toUpperCase()}</Text>
                  </Table.Td>
                  <Table.Td><Text size="sm" c="dimmed">{e.rule}</Text></Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      </Card>
    </>
  );
}
