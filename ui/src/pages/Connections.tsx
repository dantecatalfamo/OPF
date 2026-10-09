import { useEffect, useState } from 'react';
import { Link } from 'react-router';
import { ActionIcon, Alert, Anchor, Button, Card, Group, SegmentedControl, Select, Stack, Table, Text, TextInput, Tooltip } from '@mantine/core';
import { useMediaQuery } from '@mantine/hooks';
import { notifications } from '@mantine/notifications';
import { IconArrowRight, IconSearch, IconX } from '@tabler/icons-react';
import { backend, useStore } from '../model/store';
import { formatBytes, formatDuration } from '../lib/format';
import { deviceName } from '../lib/labels';
import { labelOwner } from '../lib/pfLabels';
import type { DeviceInfo, PfState, PfStatesRequest, PfStatesResource } from '../lib/api';
import { Mono, PageHeader } from '../components/ui';
import { HostName, NamesSwitch } from '../components/HostName';
import { useReverseNames, useShowNames } from '../lib/reverseNames';
import { protoGroup, stateKinds, stateWord } from '../lib/connections';
import { StateTip } from '../components/StateTip';
import { DirLabel, ProtoBadge } from '../components/ConnBadges';
import { AddressLink, useKnownDevices } from '../components/DeviceLink';

function Proto({ c }: { c: PfState }) {
  const { applied } = useStore();
  return (
    <Group gap={8} wrap="nowrap">
      <ProtoBadge proto={protoGroup(c.proto)} />
      <DirLabel dir={c.direction === 'in' ? 'in' : 'out'}>{c.direction === 'in' ? 'In' : 'Out'}{c.iface !== 'all' ? ` on ${deviceName(applied, c.iface)}` : ''}</DirLabel>
    </Group>
  );
}

type Ends = { c: PfState; names: Map<string, string>; devices: Map<string, DeviceInfo> };

function From({ c, names, devices }: Ends) {
  return (
    <div>
      <AddressLink end={c.source} devices={devices} />
      <HostName addr={c.source} names={names} />
      {c.translated && c.direction === 'out' && <Text size="xs" c="dimmed">leaves as <Mono c="dimmed">{c.translated}</Mono></Text>}
    </div>
  );
}

function To({ c, names, devices }: Ends) {
  return (
    <div>
      <AddressLink end={c.destination} devices={devices} />
      <HostName addr={c.destination} names={names} />
      {c.translated && c.direction === 'in' && <Text size="xs" c="dimmed">sent to <Mono c="dimmed">{c.translated}</Mono></Text>}
    </div>
  );
}

/** The rule that let a state in, linked to it. */
export function AllowedBy({ c }: { c: PfState }) {
  const { applied } = useStore();
  const owner = labelOwner(applied, c.label);
  if (!owner) return <Text size="sm" c="dimmed">{c.rule >= 0 ? `pf rule ${c.rule}` : '—'}</Text>;
  return owner.to ? <Anchor component={Link} to={owner.to} size="sm">{owner.text}</Anchor> : <Text size="sm">{owner.text}</Text>;
}

function State({ c }: { c: PfState }) {
  return (
    <StateTip state={c.state} direction={c.direction === 'in' ? 'in' : 'out'}>
      <Text size="xs" c="dimmed" style={{ whiteSpace: 'nowrap' }}>{stateWord(c.state, c.kind)}</Text>
    </StateTip>
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

// A page of connections, and how often it's asked for again.
const PAGE = 200;
const POLL_MS = 10_000;

export function Connections() {
  // The table needs about 820 px beside the navigation.
  const wide = useMediaQuery('(min-width: 75em)') ?? true;
  // A page at a time, filtered on the firewall: a table of thousands of
  // states would be too much to send every few seconds, and to read.
  const [q, setQ] = useState('');
  const [query, setQuery] = useState(''); // q, once typing pauses
  const [proto, setProto] = useState('all');
  const [kind, setKind] = useState<string | null>(null);
  const [dir, setDir] = useState('both');
  const [limit, setLimit] = useState(PAGE);
  const [data, setData] = useState<PfStatesResource>();
  const [error, setError] = useState<string>();
  const [closed, setClosed] = useState<Set<string>>(new Set());
  const [tick, setTick] = useState(0);
  useEffect(() => {
    const t = setTimeout(() => setQuery(q.trim()), 300);
    return () => clearTimeout(t);
  }, [q]);
  useEffect(() => setLimit(PAGE), [query, proto, dir, kind]);
  useEffect(() => {
    let live = true;
    const req: PfStatesRequest = { query: query || undefined, proto: proto === 'all' ? undefined : (proto as PfStatesRequest['proto']), direction: dir === 'both' ? undefined : (dir as 'in' | 'out'), state: (kind ?? undefined) as PfStatesRequest['state'], limit };
    const load = () => {
      if (document.hidden) return;
      backend.pfStates(req).then(
        (d) => { if (live) { setData(d); setError(undefined); } },
        (e) => live && setError(e instanceof Error ? e.message : String(e)),
      );
    };
    load();
    const t = setInterval(load, POLL_MS);
    return () => { live = false; clearInterval(t); };
  }, [query, proto, dir, kind, limit, tick]);
  const rows = (data?.states ?? []).filter((c) => !closed.has(c.id));
  const [showNames, setShowNames] = useShowNames();
  const names = useReverseNames(rows.flatMap((c) => [c.source, c.destination]), showNames);
  const devices = useKnownDevices();

  const close = async (c: PfState) => {
    try {
      await backend.killState(c);
      setClosed((s) => new Set(s).add(c.id));
      notifications.show({ message: `Closed the connection from ${c.source} to ${c.destination}` });
      setTick((n) => n + 1);
    } catch (e) {
      notifications.show({ color: 'red', title: 'Couldn’t close the connection', message: e instanceof Error ? e.message : String(e) });
    }
  };

  const count = data?.read;
  return (
    <>
      <PageHeader
        title="Connections"
        description={
          count === undefined
            ? 'Reading pf’s state table…'
            : `${count.toLocaleString()}${data?.truncated ? '+' : ''} entries in pf’s state table, the busiest first. A connection through the firewall has one on each side. Closing one ends it at once; the device can reconnect if the rules allow.`
        }
      />
      {(error || data?.error) && <Alert color="red" variant="light" mb="md">{data?.error ?? error}</Alert>}
      {data?.truncated && <Alert color="yellow" variant="light" mb="md">The table has more than {data.read.toLocaleString()} entries; OPF reads that many, so a filter may not find a newer one.</Alert>}
      <Group mb="md" gap="sm">
        <TextInput placeholder="Filter by address" leftSection={<IconSearch size={16} />} value={q} onChange={(e) => setQ(e.currentTarget.value)} style={{ flex: '1 1 240px' }} />
        <SegmentedControl
          value={proto}
          onChange={setProto}
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
          placeholder="Any state"
          clearable
          w={190}
          value={kind}
          onChange={setKind}
          aria-label="State"
          data={stateKinds.map((k) => ({ value: k.value, label: `${k.label} · ${(data?.byKind?.[k.value] ?? 0).toLocaleString()}` }))}
          renderOption={({ option }) => {
            const k = stateKinds.find((x) => x.value === option.value)!;
            return (
              <Stack gap={0}>
                <Text size="sm">{option.label}</Text>
                <Text size="xs" c="dimmed">{k.help}</Text>
              </Stack>
            );
          }}
        />
        <NamesSwitch checked={showNames} onChange={setShowNames} />
      </Group>
      <Card padding={0}>
        {wide ? (
          <Table highlightOnHover striped>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Protocol and way</Table.Th>
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
                  <Table.Td style={{ whiteSpace: 'nowrap' }}><From c={c} names={names} devices={devices} /></Table.Td>
                  <Table.Td style={{ whiteSpace: 'nowrap' }}><To c={c} names={names} devices={devices} /></Table.Td>
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
                    <From c={c} names={names} devices={devices} />
                    <IconArrowRight size={16} color="var(--mantine-color-dimmed)" style={{ marginTop: 2, flexShrink: 0 }} />
                    <To c={c} names={names} devices={devices} />
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
        {data && rows.length === 0 && <Text size="sm" c="dimmed" ta="center" py="xl">{query || proto !== 'all' || dir !== 'both' || kind ? 'No connections match.' : 'No connections.'}</Text>}
      </Card>
      {data && data.total > 0 && (
        <Group justify="space-between" mt="sm">
          <Text size="xs" c="dimmed">
            Showing {rows.length.toLocaleString()} of {data.total.toLocaleString()}{query || proto !== 'all' || dir !== 'both' || kind ? ' that match' : ''}
          </Text>
          {data.total > data.states.length && limit < 1000 && (
            <Button size="compact-sm" variant="subtle" onClick={() => setLimit((n) => Math.min(1000, n + PAGE))}>Show {Math.min(PAGE, data.total - data.states.length)} more</Button>
          )}
        </Group>
      )}
    </>
  );
}
