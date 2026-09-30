import { useState } from 'react';
import { Link } from 'react-router';
import { Alert, Anchor, Badge, Card, Group, Select, Table, Text, TextInput, Tooltip } from '@mantine/core';
import { IconSearch } from '@tabler/icons-react';
import { useStore } from '../model/store';
import { deviceName } from '../lib/labels';
import { formatLogTime } from '../lib/format';
import { useLive } from '../lib/live';
import { labelOwner } from '../lib/pfLabels';
import type { FirewallLogEntry } from '../lib/api';
import type { Model } from '../model/types';
import { Mono, PageHeader } from '../components/ui';

const actionColor: Record<string, string> = { block: 'red', pass: 'teal', match: 'gray' };
const actionText: Record<string, string> = { block: 'Blocked', pass: 'Allowed', match: 'Matched' };

/** The rule that logged an entry, in words, and why it's missing when it is. */
export function LogRule({ e, model }: { e: FirewallLogEntry; model: Model }) {
  const owner = labelOwner(model, e.label);
  if (e.rule < 0) {
    return (
      <Tooltip label="No rule: pf itself, such as dropping a packet with IP options." multiline w={260}>
        <Text size="sm" c="dimmed">pf’s default rule</Text>
      </Tooltip>
    );
  }
  if (owner) return owner.to ? <Anchor component={Link} to={owner.to} size="sm">{owner.text}</Anchor> : <Text size="sm">{owner.text}</Text>;
  const why = e.anchor
    ? `Rule ${e.rule} in anchor ${e.anchor}.`
    : e.label
      ? `Labelled ${e.label}, which isn’t in the configuration any more.`
      : `pf rule ${e.rule}. The rules have been reloaded since, so which rule that was isn’t known.`;
  return (
    <Tooltip label={why} multiline w={260}>
      <Text size="sm" c="dimmed">{e.anchor ? `${e.anchor} rule ${e.rule}` : `pf rule ${e.rule}`}</Text>
    </Tooltip>
  );
}

export function FirewallLog() {
  const { applied } = useStore();
  const { data, error } = useLive('firewallLog');
  const [q, setQ] = useState('');
  const [iface, setIface] = useState<string | null>(null);
  const entries = data?.entries ?? [];
  const rows = entries.filter((e) => {
    if (iface && e.iface !== iface) return false;
    if (!q) return true;
    const rule = labelOwner(applied, e.label)?.text ?? '';
    return `${e.source ?? ''} ${e.destination ?? ''} ${rule}`.toLowerCase().includes(q.toLowerCase());
  });

  return (
    <>
      <PageHeader title="Firewall log" description="Traffic matched by rules that have logging turned on, newest first. The last 500 entries pf has kept." />
      {(error || data?.error) && <Alert color="red" variant="light" mb="md">{data?.error ?? error}</Alert>}
      <Group mb="md" gap="sm">
        <TextInput placeholder="Filter by address or rule" leftSection={<IconSearch size={16} />} value={q} onChange={(e) => setQ(e.currentTarget.value)} style={{ flex: '1 1 240px' }} />
        <Select
          placeholder="All interfaces"
          clearable
          value={iface}
          onChange={setIface}
          data={applied.interfaces.map((i) => ({ value: i.device, label: i.name }))}
          w={180}
        />
      </Group>
      <Card padding={0}>
        <Table.ScrollContainer minWidth={860}>
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
              {rows.map((e, i) => (
                <Table.Tr key={`${e.time}-${i}`}>
                  <Table.Td>
                    <Tooltip label={new Date(e.time).toLocaleString()}>
                      <Text size="sm" className="num" style={{ whiteSpace: 'nowrap' }}>{formatLogTime(e.time)}</Text>
                    </Tooltip>
                  </Table.Td>
                  <Table.Td><Badge color={actionColor[e.action] ?? 'gray'}>{actionText[e.action] ?? e.action}</Badge></Table.Td>
                  <Table.Td><Text size="sm">{deviceName(applied, e.iface)} <Text span size="xs" c="dimmed">{e.direction}</Text></Text></Table.Td>
                  <Table.Td><Mono>{e.source ?? '—'}</Mono></Table.Td>
                  <Table.Td>
                    <Mono>{e.destination ?? '—'}</Mono> {e.proto && <Text span size="xs" c="dimmed">{e.proto.toUpperCase()}</Text>}
                    {e.reason !== 'match' && <Text size="xs" c="yellow">{e.reason}: {e.info}</Text>}
                  </Table.Td>
                  <Table.Td><LogRule e={e} model={applied} /></Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
        {data && rows.length === 0 && (
          <Text size="sm" c="dimmed" ta="center" py="xl">{entries.length ? 'No entries match.' : 'Nothing has been logged yet.'}</Text>
        )}
      </Card>
    </>
  );
}
