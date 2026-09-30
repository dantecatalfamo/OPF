// System › General › Graphs: how many of each thing the graphs keep a
// history of, what that can cost in memory, and how many there are now.
// The caps are in the model (system.graphs), so they're reviewed,
// applied and kept in history like any other setting.
import { useEffect, useState } from 'react';
import { Alert, Button, Card, Group, NumberInput, Stack, Table, Text } from '@mantine/core';
import { IconAlertTriangle } from '@tabler/icons-react';
import { backend, useStore } from '../model/store';
import { useLive } from '../lib/live';
import type { GraphGroup } from '../lib/api';
import type { GraphLimits } from '../model/types';
import { formatBytes } from '../lib/format';
import { SectionTitle } from '../components/ui';

const kinds: { key: keyof GraphLimits; label: string; each: string }[] = [
  { key: 'interfaces', label: 'Interfaces', each: 'in and out' },
  { key: 'gateways', label: 'Gateways', each: 'latency and loss' },
  { key: 'vpnDevices', label: 'VPN devices', each: 'traffic and handshakes' },
  { key: 'dhcpNetworks', label: 'DHCP networks', each: 'leases in use' },
  { key: 'rules', label: 'Firewall rules', each: 'matches, 10-minute detail' },
];

export function GraphSettings() {
  const { staged, edit } = useStore();
  const { data: sys } = useLive('system');
  const [groups, setGroups] = useState<GraphGroup[]>();
  useEffect(() => {
    let live = true;
    const load = () => backend.metrics([], 60).then((m) => live && setGroups(m.groups), () => {});
    load();
    const t = setInterval(load, 30_000);
    return () => { live = false; clearInterval(t); };
  }, []);
  const saved = staged.system.graphs ?? {};
  const [values, setValues] = useState<GraphLimits>(saved);
  useEffect(() => setValues(staged.system.graphs ?? {}), [staged.system.graphs]);

  const group = (k: string) => groups?.find((g) => g.name === k);
  const cap = (k: keyof GraphLimits) => values[k] ?? group(k)?.default ?? 0;
  const system = group('system');
  const total = kinds.reduce((n, k) => n + cap(k.key) * (group(k.key)?.itemBytes ?? 0), system ? system.max * system.itemBytes : 0);
  const physmem = sys?.memory?.total;
  const dirty = kinds.some((k) => values[k.key] !== saved[k.key]);
  const invalid = kinds.some((k) => values[k.key] !== undefined && (values[k.key]! < 0 || values[k.key]! > 10000 || !Number.isInteger(values[k.key])));

  const save = () => {
    const next: GraphLimits = {};
    for (const k of kinds) if (values[k.key] !== undefined) next[k.key] = values[k.key];
    const changed = kinds.filter((k) => values[k.key] !== saved[k.key]).map((k) => `${k.label.toLowerCase()} ${values[k.key] ?? `default (${group(k.key)?.default ?? '?'})`}`);
    edit('system', `Graphs keep: ${changed.join(', ')}`, (m) => ({ ...m, system: { ...m.system, graphs: Object.keys(next).length ? next : undefined } }));
  };

  return (
    <Card>
      <SectionTitle>Graphs</SectionTitle>
      <Stack gap="sm">
        <Text size="sm" c="dimmed">
          How many of each thing the graphs keep a month of history for. Each kind has its own limit, so many rules never crowd out the interfaces. A larger limit costs memory; it’s shown at its most, and a typical firewall uses far less. Leave one empty for the default.
        </Text>
        <Table.ScrollContainer minWidth={480}>
          <Table verticalSpacing={6}>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Keep</Table.Th>
                <Table.Th w={130}>At most</Table.Th>
                <Table.Th ta="right">Recorded</Table.Th>
                <Table.Th ta="right">Memory, at most</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {kinds.map((k) => {
                const g = group(k.key);
                return (
                  <Table.Tr key={k.key}>
                    <Table.Td>
                      <Text size="sm">{k.label}</Text>
                      <Text size="xs" c="dimmed">{k.each}</Text>
                    </Table.Td>
                    <Table.Td>
                      <NumberInput
                        size="xs"
                        min={0}
                        max={10000}
                        allowDecimal={false}
                        placeholder={g?.default !== undefined ? String(g.default) : ''}
                        value={values[k.key] ?? ''}
                        onChange={(v) => setValues((x) => ({ ...x, [k.key]: v === '' ? undefined : Number(v) }))}
                        aria-label={`${k.label} kept`}
                      />
                    </Table.Td>
                    <Table.Td ta="right">
                      <Text size="sm" className="num" c={g?.refused ? 'yellow' : undefined}>{g ? `${g.items}${g.refused ? ', full' : ''}` : '…'}</Text>
                    </Table.Td>
                    <Table.Td ta="right"><Text size="sm" c="dimmed" className="num">{g ? formatBytes(cap(k.key) * g.itemBytes) : '…'}</Text></Table.Td>
                  </Table.Tr>
                );
              })}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
        {groups && (
          <Text size="xs" c="dimmed">
            With the system’s own graphs (CPU, memory, pf, DNS, time), up to {formatBytes(total)} of memory{physmem ? ` of ${formatBytes(physmem)}` : ''}, and about as much on disk at most.
          </Text>
        )}
        {groups?.some((g) => g.refused) && (
          <Alert color="yellow" variant="light" p="sm" icon={<IconAlertTriangle size={16} />}>
            Some are full: there are more than they keep, and the rest aren’t recorded. Raise the limit to graph them all.
          </Alert>
        )}
        {physmem && total > physmem * 0.25 && (
          <Alert color="yellow" variant="light" p="sm" icon={<IconAlertTriangle size={16} />}>
            At their most these would take over a quarter of this machine’s memory.
          </Alert>
        )}
        <Group justify="flex-end">
          <Button onClick={save} disabled={!dirty || invalid}>Save</Button>
        </Group>
      </Stack>
    </Card>
  );
}
