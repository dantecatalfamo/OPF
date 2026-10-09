// Firewall › Statistics: everything pf counts. pfctl -s info's tables
// and counters, its memory limits against what's used, its timeouts,
// and each interface's traffic. pf keeps totals since it was enabled
// (its own Rate column is that total over the whole time), so the rate
// here is between this answer and the last, a few seconds apart.
import { useEffect, useRef, useState } from 'react';
import { Link } from 'react-router';
import { Alert, Anchor, Badge, Card, Grid, Group, Progress, SimpleGrid, Stack, Switch, Table, Text, Tooltip } from '@mantine/core';
import { backend, useStore } from '../model/store';
import { formatBytes, formatDuration } from '../lib/format';
import { deviceName } from '../lib/labels';
import type { PfInterfaceStats, PfStatsResource } from '../lib/api';
import { Mono, PageHeader, SectionTitle } from '../components/ui';
import { StartedTip } from '../components/StartedTip';

const POLL_MS = 5000;

interface Counter {
  name: string;
  help: string;
  /** A sign of trouble when it's rising. */
  trouble?: boolean;
  to?: string;
  /** What the link says: where it goes. */
  toLabel?: string;
}

// pfctl's Counters, in its order: each a reason pf matched or dropped a
// packet (pf's PFRES_*).
const counters: Counter[] = [
  { name: 'match', help: 'Packets that matched a rule: the ordinary work of filtering.' },
  { name: 'bad-offset', help: 'Packets dropped for a bad IP header offset.', trouble: true },
  { name: 'fragment', help: 'Fragments dropped: overlapping, too many or too late to put back together.', trouble: true },
  { name: 'short', help: 'Packets dropped as too short to read their headers.', trouble: true },
  { name: 'normalize', help: 'Packets dropped by normalization (scrub): bad flags or options.', to: '/firewall/settings#scrub', toLabel: 'Scrub settings' },
  { name: 'memory', help: 'Packets dropped because pf ran out of memory for them.', trouble: true, to: '/firewall/settings#limits', toLabel: 'Limits' },
  { name: 'bad-timestamp', help: 'TCP packets dropped for a timestamp outside the connection’s.', trouble: true },
  { name: 'congestion', help: 'Packets dropped because the network stack’s queue was full: the firewall is falling behind.', trouble: true },
  { name: 'ip-option', help: 'Packets dropped for carrying IP options, which pf refuses unless a rule allows them.' },
  { name: 'proto-cksum', help: 'Packets dropped for a bad TCP, UDP or ICMP checksum.', trouble: true },
  { name: 'state-mismatch', help: 'Packets that belonged to a connection but not to its TCP window: late, duplicated or forged.' },
  { name: 'state-insert', help: 'New connections that couldn’t be added to the state table, usually a duplicate of one there.', trouble: true },
  { name: 'state-limit', help: 'New connections refused because the state table, or a rule’s max states, was full.', trouble: true, to: '/firewall/settings#limits', toLabel: 'Limits' },
  { name: 'src-limit', help: 'New connections refused by a rule’s limits on one source (max-src-states, max-src-conn…).' },
  { name: 'synproxy', help: 'TCP handshakes pf answered itself for a synproxy rule.' },
  { name: 'translate', help: 'Packets NAT found no free address or port for.', trouble: true, to: '/firewall/nat', toLabel: 'NAT' },
  { name: 'no-route', help: 'Packets a route-to rule had no route for.', trouble: true },
];

// pfctl's Limit Counters: rules' limits, each time one took effect.
const limitCounters: Counter[] = [
  { name: 'max states per rule', help: 'A rule refused a connection at its max states.' },
  { name: 'max-src-states', help: 'A rule refused a source at its max-src-states.' },
  { name: 'max-src-nodes', help: 'A rule refused a new source at its max-src-nodes.' },
  { name: 'max-src-conn', help: 'A source reached a rule’s max-src-conn.' },
  { name: 'max-src-conn-rate', help: 'A source connected faster than a rule’s max-src-conn-rate.' },
  { name: 'overload table insertion', help: 'Addresses put in an overload table, as brute-force protection does.', to: '/firewall/aliases', toLabel: 'Aliases' },
  { name: 'overload flush states', help: 'Connections ended when their source was put in an overload table with flush.' },
  { name: 'synfloods detected', help: 'Times the half-open connections passed the adaptive syncookies watermark.' },
  { name: 'syncookies sent', help: 'Handshakes answered with a syncookie instead of a state.' },
  { name: 'syncookies validated', help: 'Syncookies that came back right and became connections.' },
];

const pools: { name: string; label: string; help: string; to?: string }[] = [
  { name: 'states', label: 'Connections (states)', help: 'Full, new connections are refused until old ones end.', to: '/firewall/settings#limits' },
  { name: 'src-nodes', label: 'Source nodes', help: 'One for each source a rule tracks (source limits, sticky addresses).', to: '/firewall/settings#limits' },
  { name: 'frags', label: 'Fragments', help: 'Fragments held while pf puts packets back together.' },
  { name: 'tables', label: 'Tables', help: 'Address tables: aliases, blocklists, OPF’s own.', to: '/firewall/settings#limits' },
  { name: 'table-entries', label: 'Table entries', help: 'Addresses and networks in all the tables together.', to: '/firewall/settings#limits' },
  { name: 'pktdelay-pkts', label: 'Delayed packets', help: 'Packets held by rules that delay them.' },
  { name: 'anchors', label: 'Anchors', help: 'Rule sets inside the main one: sign-in access’s, among others.' },
];

const timeoutHelp: Record<string, string> = {
  'tcp.first': 'A TCP connection after its first packet',
  'tcp.opening': 'Before the other end has answered',
  'tcp.established': 'An open TCP connection, idle',
  'tcp.closing': 'After the first FIN',
  'tcp.finwait': 'After both ends have sent FIN',
  'tcp.closed': 'After a reset',
  'tcp.tsdiff': 'How far a TCP timestamp may be off',
  'udp.first': 'UDP after the first packet',
  'udp.single': 'UDP when only one end has sent',
  'udp.multiple': 'UDP when both ends have sent',
  'icmp.first': 'ICMP after the first packet',
  'icmp.error': 'After an ICMP error',
  'other.first': 'Other protocols after the first packet',
  'other.single': 'Other protocols, one end sending',
  'other.multiple': 'Other protocols, both ends sending',
  frag: 'How long a fragment waits for the rest',
  interval: 'How often pf purges expired states',
  'adaptive.start': 'States at which timeouts start shrinking',
  'adaptive.end': 'States at which they reach zero',
  'src.track': 'How long a source node lasts after its last state',
};

const num = (n: number) => n.toLocaleString();

// A timeout in the unit it's a whole number of: 24 h, 15 min, 45 s.
function formatSecs(s: number): string {
  if (s >= 3600 && s % 3600 === 0) return `${num(s / 3600)} h`;
  if (s >= 60 && s % 60 === 0) return `${num(s / 60)} min`;
  return `${num(s)} s`;
}

function formatRate(r: number | undefined): string {
  if (r === undefined) return '…';
  if (r === 0) return '0';
  if (r < 0.1) return '<0.1';
  return r < 10 ? r.toFixed(1) : Math.round(r).toLocaleString();
}

// Rates between two answers: undefined until there are two, or when a
// total went down (pf was re-enabled, or counters cleared).
function rate(now: number | undefined, then: number | undefined, dt: number): number | undefined {
  if (now === undefined || then === undefined || dt <= 0 || now < then) return undefined;
  return (now - then) / dt;
}

function CounterTable({ list, totals, prev, dt }: { list: Counter[]; totals: Record<string, number>; prev?: Record<string, number>; dt: number }) {
  // pfctl may count something this list doesn't know yet.
  const rows: Counter[] = [...list, ...Object.keys(totals).filter((k) => !list.some((c) => c.name === k) && ![...counters, ...limitCounters].some((c) => c.name === k)).map((name) => ({ name, help: '' }))];
  return (
    <Table verticalSpacing={6} highlightOnHover>
      <Table.Thead>
        <Table.Tr>
          <Table.Th>Counter</Table.Th>
          <Table.Th ta="right" w={130}>Total</Table.Th>
          <Table.Th ta="right" w={90} style={{ whiteSpace: 'nowrap' }}>Now, /s</Table.Th>
        </Table.Tr>
      </Table.Thead>
      <Table.Tbody>
        {rows.filter((c) => c.name in totals).map((c) => {
          const total = totals[c.name];
          const r = rate(total, prev?.[c.name], dt);
          const rising = !!c.trouble && !!r;
          return (
            <Table.Tr key={c.name}>
              <Table.Td>
                <Group gap={6} wrap="wrap" style={{ rowGap: 0 }}>
                  <span style={{ whiteSpace: 'nowrap' }}><Mono c={total ? undefined : 'dimmed'}>{c.name}</Mono></span>
                  {c.to && <Anchor component={Link} to={c.to} size="xs">{c.toLabel}</Anchor>}
                </Group>
                {c.help && <Text size="xs" c="dimmed">{c.help}</Text>}
              </Table.Td>
              <Table.Td ta="right"><Text size="sm" className="num" c={total ? undefined : 'dimmed'}>{num(total)}</Text></Table.Td>
              <Table.Td ta="right"><Text size="sm" className="num" c={rising ? 'yellow' : r ? undefined : 'dimmed'} fw={rising ? 600 : undefined}>{formatRate(r)}</Text></Table.Td>
            </Table.Tr>
          );
        })}
      </Table.Tbody>
    </Table>
  );
}

const tableNames: { key: 'states' | 'srcNodes' | 'fragments'; label: string; help: string }[] = [
  { key: 'states', label: 'State table', help: 'A connection’s packets are looked up here before any rule.' },
  { key: 'srcNodes', label: 'Source tracking', help: 'Sources that rules with source limits or sticky addresses follow.' },
  { key: 'fragments', label: 'Fragments', help: 'Packets waiting for the rest of their fragments.' },
];

function Count({ c, label }: { c: { packets: number; bytes: number }; label: string }) {
  return (
    <Tooltip label={`${label}: ${num(c.packets)} packets, ${num(c.bytes)} bytes`}>
      <div>
        <Text size="sm" className="num" c={c.packets ? undefined : 'dimmed'}>{formatBytes(c.bytes)}</Text>
        <Text size="xs" c="dimmed" className="num">{num(c.packets)} pkts</Text>
      </div>
    </Tooltip>
  );
}

function Interfaces({ list, prev, dt }: { list: PfInterfaceStats[]; prev?: PfInterfaceStats[]; dt: number }) {
  const { applied } = useStore();
  const [groups, setGroups] = useState(false);
  // What pf filters first; set skip ones last.
  const shown = list.filter((i) => groups || !i.group).sort((a, b) => Number(a.skip) - Number(b.skip));
  return (
    <Card id="interfaces">
      <SectionTitle right={<Switch size="xs" label="Groups too" checked={groups} onChange={(e) => setGroups(e.currentTarget.checked)} />}>Interfaces</SectionTitle>
      <Text size="xs" c="dimmed" mb="sm">
        What pf passed and blocked on each interface since its counters were cleared, usually at boot. A group (egress, all) isn’t counted itself; its interfaces are.
      </Text>
      <Table.ScrollContainer minWidth={760}>
        <Table verticalSpacing={6} highlightOnHover>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Interface</Table.Th>
              <Table.Th ta="right">In, passed</Table.Th>
              <Table.Th ta="right">In, blocked</Table.Th>
              <Table.Th ta="right">Out, passed</Table.Th>
              <Table.Th ta="right">Out, blocked</Table.Th>
              <Table.Th ta="right">Blocked now, /s</Table.Th>
              <Table.Th ta="right">Rules</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {shown.map((i) => {
              const p = prev?.find((x) => x.name === i.name);
              const r = p && rate(i.inBlock.packets + i.outBlock.packets, p.inBlock.packets + p.outBlock.packets, dt);
              const name = deviceName(applied, i.name);
              return (
                <Table.Tr key={i.name}>
                  <Table.Td>
                    <Group gap={6} wrap="nowrap">
                      <Text size="sm" fw={500}>{name}</Text>
                      {name !== i.name && <Mono c="dimmed">{i.name}</Mono>}
                      {i.group && <Badge size="xs" variant="light" color="gray">group</Badge>}
                      {i.skip && <Tooltip label="set skip: pf doesn’t filter it"><Badge size="xs" variant="light" color="gray">skipped</Badge></Tooltip>}
                    </Group>
                    {i.cleared && (
                      <StartedTip at={i.cleared} label="Counting since">
                        <Text size="xs" c="dimmed">for {formatDuration((Date.now() - Date.parse(i.cleared)) / 1000)}</Text>
                      </StartedTip>
                    )}
                  </Table.Td>
                  <Table.Td ta="right"><Count c={i.inPass} label="In, passed" /></Table.Td>
                  <Table.Td ta="right"><Count c={i.inBlock} label="In, blocked" /></Table.Td>
                  <Table.Td ta="right"><Count c={i.outPass} label="Out, passed" /></Table.Td>
                  <Table.Td ta="right"><Count c={i.outBlock} label="Out, blocked" /></Table.Td>
                  <Table.Td ta="right"><Text size="sm" className="num" c={r ? undefined : 'dimmed'}>{formatRate(r)}</Text></Table.Td>
                  <Table.Td ta="right"><Text size="sm" className="num" c={i.rules ? undefined : 'dimmed'}>{num(i.rules)}</Text></Table.Td>
                </Table.Tr>
              );
            })}
          </Table.Tbody>
        </Table>
      </Table.ScrollContainer>
    </Card>
  );
}

/** Firewall › Statistics. */
export function FirewallStats() {
  const [data, setData] = useState<PfStatsResource>();
  const [error, setError] = useState<string>();
  // The answer before this one, for rates.
  const prev = useRef<PfStatsResource>(undefined);
  const [last, setLast] = useState<PfStatsResource>();
  useEffect(() => {
    let live = true;
    const load = () => {
      if (document.hidden) return;
      backend.pfStats().then(
        (d) => {
          if (!live) return;
          setLast(prev.current);
          prev.current = d;
          setData(d);
          setError(undefined);
        },
        (e) => live && setError(e instanceof Error ? e.message : String(e)),
      );
    };
    load();
    const t = setInterval(load, POLL_MS);
    return () => { live = false; clearInterval(t); };
  }, []);
  const dt = data && last ? (Date.parse(data.at) - Date.parse(last.at)) / 1000 : 0;
  const info = data?.info;

  return (
    <>
      <PageHeader
        title="Statistics"
        description="Everything pf counts: totals since it was enabled, and how fast each is rising now, over the last few seconds."
      />
      {error && <Alert color="red" variant="light" mb="md">{error}</Alert>}
      {data?.errors.map((e) => <Alert key={e} color="yellow" variant="light" mb="md">{e}</Alert>)}
      {!data && !error && <Text size="sm" c="dimmed">Reading…</Text>}
      {data && (
        <Stack gap="md">
          <SimpleGrid cols={{ base: 1, sm: 2, lg: 4 }}>
            <Card>
              <Text size="xs" c="dimmed" tt="uppercase" fw={600}>pf</Text>
              <Text fw={600} size="lg" c={info?.enabled ? undefined : 'red'}>{!info ? '—' : info.enabled ? 'Enabled' : 'Disabled'}</Text>
              {info?.enabledFor !== undefined && (
                <StartedTip ageSec={info.enabledFor} label="Enabled since">
                  <Text size="xs" c="dimmed">for {formatDuration(info.enabledFor)}{info.debug ? ` · debug ${info.debug}` : ''}</Text>
                </StartedTip>
              )}
            </Card>
            <Card>
              <Text size="xs" c="dimmed" tt="uppercase" fw={600}>Connections</Text>
              <Text fw={600} size="lg" className="num">{info ? num(info.states) : '—'}</Text>
              <Text size="xs" c="dimmed">{info ? `${num(info.halfOpenTcp)} half-open TCP` : ''}{data.limits.states ? ` · limit ${num(data.limits.states)}` : ''}</Text>
            </Card>
            <Card>
              <Text size="xs" c="dimmed" tt="uppercase" fw={600}>New connections</Text>
              <Text fw={600} size="lg" className="num">{formatRate(rate(info?.tables.states?.inserts, last?.info?.tables.states?.inserts, dt))}<Text span size="sm" c="dimmed"> /s</Text></Text>
              <Text size="xs" c="dimmed">{info?.tables.states ? `${num(info.tables.states.inserts)} since pf was enabled` : ''}</Text>
            </Card>
            <Card>
              <Text size="xs" c="dimmed" tt="uppercase" fw={600}>Rules matched</Text>
              <Text fw={600} size="lg" className="num">{formatRate(rate(info?.counters.match, last?.info?.counters.match, dt))}<Text span size="sm" c="dimmed"> /s</Text></Text>
              <Text size="xs" c="dimmed">{info?.counters.match !== undefined ? `${num(info.counters.match)} since pf was enabled` : ''}</Text>
            </Card>
          </SimpleGrid>

          {info && (
            <Card id="tables">
              <SectionTitle>Tables</SectionTitle>
              <Table.ScrollContainer minWidth={560}>
                <Table verticalSpacing={6} highlightOnHover>
                  <Table.Thead>
                    <Table.Tr>
                      <Table.Th>Table</Table.Th>
                      <Table.Th ta="right">Entries</Table.Th>
                      <Table.Th ta="right">Searches, /s</Table.Th>
                      <Table.Th ta="right">Inserts, /s</Table.Th>
                      <Table.Th ta="right">Removals, /s</Table.Th>
                    </Table.Tr>
                  </Table.Thead>
                  <Table.Tbody>
                    {tableNames.filter((t) => info.tables[t.key]).map((t) => {
                      const now = info.tables[t.key]!;
                      const then = last?.info?.tables[t.key];
                      const cell = (k: 'searches' | 'inserts' | 'removals') => (
                        <Tooltip label={`${num(now[k])} since pf was enabled`}>
                          <Text size="sm" className="num">{formatRate(rate(now[k], then?.[k], dt))}</Text>
                        </Tooltip>
                      );
                      return (
                        <Table.Tr key={t.key}>
                          <Table.Td>
                            <Text size="sm" fw={500}>{t.label}</Text>
                            <Text size="xs" c="dimmed">{t.help}</Text>
                          </Table.Td>
                          <Table.Td ta="right"><Text size="sm" className="num">{num(now.current)}</Text></Table.Td>
                          <Table.Td ta="right">{cell('searches')}</Table.Td>
                          <Table.Td ta="right">{cell('inserts')}</Table.Td>
                          <Table.Td ta="right">{cell('removals')}</Table.Td>
                        </Table.Tr>
                      );
                    })}
                  </Table.Tbody>
                </Table>
              </Table.ScrollContainer>
            </Card>
          )}

          {info && (
            <Grid gutter="md">
              <Grid.Col span={{ base: 12, lg: 6 }}>
                <Card h="100%" id="counters">
                  <SectionTitle>Counters</SectionTitle>
                  <Text size="xs" c="dimmed" mb="sm">Why pf matched or dropped packets. A rate in yellow is one that means trouble, rising now.</Text>
                  <CounterTable list={counters} totals={info.counters} prev={last?.info?.counters} dt={dt} />
                </Card>
              </Grid.Col>
              <Grid.Col span={{ base: 12, lg: 6 }}>
                <Card h="100%" id="limit-counters">
                  <SectionTitle>Limit counters</SectionTitle>
                  <Text size="xs" c="dimmed" mb="sm">Each time a rule’s limit on connections or sources took effect.</Text>
                  <CounterTable list={limitCounters} totals={info.counters} prev={last?.info?.counters} dt={dt} />
                </Card>
              </Grid.Col>
            </Grid>
          )}

          {data.interfaces.length > 0 && <Interfaces list={data.interfaces} prev={last?.interfaces} dt={dt} />}

          <Grid gutter="md">
            {Object.keys(data.limits).length > 0 && (
              <Grid.Col span={{ base: 12, lg: 6 }}>
                <Card h="100%" id="memory">
                  <SectionTitle right={<Anchor component={Link} to="/firewall/settings#limits" size="xs">Limits</Anchor>}>Memory limits</SectionTitle>
                  <Stack gap="sm">
                    {[...pools, ...Object.keys(data.limits).filter((k) => !pools.some((p) => p.name === k)).map((name) => ({ name, label: name, help: '', to: undefined }))].filter((p) => p.name in data.limits).map((p) => {
                      const max = data.limits[p.name];
                      const used = data.used[p.name];
                      const pct = used !== undefined && max ? (used / max) * 100 : undefined;
                      return (
                        <div key={p.name}>
                          <Group justify="space-between" gap="xs" wrap="nowrap">
                            <Text size="sm" fw={500}>{p.label} <Mono c="dimmed">{p.name}</Mono></Text>
                            <Text size="sm" className="num" style={{ whiteSpace: 'nowrap' }}>{used !== undefined ? `${num(used)} of ` : ''}{num(max)}</Text>
                          </Group>
                          {pct !== undefined && <Progress value={Math.max(pct, 0.5)} size="sm" mt={4} color={pct > 90 ? 'red' : pct > 70 ? 'yellow' : 'harbor'} />}
                          {p.help && <Text size="xs" c="dimmed" mt={2}>{p.help}</Text>}
                        </div>
                      );
                    })}
                  </Stack>
                </Card>
              </Grid.Col>
            )}
            {data.timeouts.length > 0 && (
              <Grid.Col span={{ base: 12, lg: 6 }}>
                <Card h="100%" id="timeouts">
                  <SectionTitle right={<Anchor component={Link} to="/firewall/settings#connections" size="xs">Connection tracking</Anchor>}>Timeouts</SectionTitle>
                  <Text size="xs" c="dimmed" mb="sm">How long pf keeps a connection it hasn’t seen a packet for, by where it’s got to.</Text>
                  <Table verticalSpacing={4}>
                    <Table.Tbody>
                      {data.timeouts.map((t) => (
                        <Table.Tr key={t.name}>
                          <Table.Td><Mono>{t.name}</Mono>{timeoutHelp[t.name] && <Text size="xs" c="dimmed">{timeoutHelp[t.name]}</Text>}</Table.Td>
                          <Table.Td ta="right" style={{ whiteSpace: 'nowrap' }}>
                            <Text size="sm" className="num">{t.unit === 's' ? formatSecs(t.value) : `${num(t.value)} states`}</Text>
                          </Table.Td>
                        </Table.Tr>
                      ))}
                    </Table.Tbody>
                  </Table>
                </Card>
              </Grid.Col>
            )}
          </Grid>
        </Stack>
      )}
    </>
  );
}
