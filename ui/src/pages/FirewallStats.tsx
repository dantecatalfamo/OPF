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
import { timeoutHelp } from '../lib/pfTimeouts';

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
  { name: 'match', help: 'Packets that matched a rule. This is the ordinary work of filtering.' },
  { name: 'bad-offset', help: 'Packets dropped for a bad IP header offset.', trouble: true },
  { name: 'fragment', help: 'Fragments dropped because they overlapped, there were too many, or they came too late to put back together.', trouble: true },
  { name: 'short', help: 'Packets dropped as too short to read their headers.', trouble: true },
  { name: 'normalize', help: 'Packets that scrub dropped for bad flags or options.', to: '/firewall/settings#scrub', toLabel: 'Scrub settings' },
  { name: 'memory', help: 'Packets dropped because pf ran out of memory for them.', trouble: true, to: '/firewall/settings#limits', toLabel: 'Limits' },
  { name: 'bad-timestamp', help: 'TCP packets dropped because their timestamp didn’t fit the connection.', trouble: true },
  { name: 'congestion', help: 'Packets dropped because the network stack’s queue was full. The firewall is falling behind.', trouble: true },
  { name: 'ip-option', help: 'Packets dropped for carrying IP options, which pf refuses unless a rule allows them.' },
  { name: 'proto-cksum', help: 'Packets dropped for a bad TCP, UDP or ICMP checksum.', trouble: true },
  { name: 'state-mismatch', help: 'Packets for a known connection that fell outside its TCP window. They may be late, duplicated or forged.' },
  { name: 'state-insert', help: 'New connections that couldn’t be added to the state table. Usually the table already had the same connection.', trouble: true },
  { name: 'state-limit', help: 'New connections refused because the state table was full or a rule reached its max states.', trouble: true, to: '/firewall/settings#limits', toLabel: 'Limits' },
  { name: 'src-limit', help: 'New connections refused because one source reached a rule’s limits, such as max-src-states or max-src-conn.' },
  { name: 'synproxy', help: 'TCP handshakes pf answered itself for a synproxy rule.' },
  { name: 'translate', help: 'Packets dropped because NAT found no free address or port for them.', trouble: true, to: '/firewall/nat', toLabel: 'NAT' },
  { name: 'no-route', help: 'Packets dropped because a route-to rule had no route for them.', trouble: true },
];

// pfctl's Limit Counters: rules' limits, each time one took effect.
const limitCounters: Counter[] = [
  { name: 'max states per rule', help: 'A rule refused a connection at its max states.' },
  { name: 'max-src-states', help: 'A rule refused a source at its max-src-states.' },
  { name: 'max-src-nodes', help: 'A rule refused a new source at its max-src-nodes.' },
  { name: 'max-src-conn', help: 'A source reached a rule’s max-src-conn.' },
  { name: 'max-src-conn-rate', help: 'A source connected faster than a rule’s max-src-conn-rate.' },
  { name: 'overload table insertion', help: 'Addresses added to an overload table, for example by brute-force protection.', to: '/firewall/aliases', toLabel: 'Aliases' },
  { name: 'overload flush states', help: 'Connections ended when their source was put in an overload table with flush.' },
  { name: 'synfloods detected', help: 'Times half-open connections passed the start threshold for adaptive SYN cookies.' },
  { name: 'syncookies sent', help: 'Handshakes answered with a SYN cookie instead of adding a state.' },
  { name: 'syncookies validated', help: 'SYN cookies that came back valid and became connections.' },
];

const pools: { name: string; label: string; help: string; to?: string }[] = [
  { name: 'states', label: 'Connections (states)', help: 'When this is full, new connections are refused until old ones end.', to: '/firewall/settings#limits' },
  { name: 'src-nodes', label: 'Source nodes', help: 'One for each source a rule tracks, for source limits or sticky addresses.', to: '/firewall/settings#limits' },
  { name: 'frags', label: 'Fragments', help: 'Fragments held while pf puts packets back together.' },
  { name: 'tables', label: 'Tables', help: 'Address tables, including aliases, blocklists and OPF’s own.', to: '/firewall/settings#limits' },
  { name: 'table-entries', label: 'Table entries', help: 'Addresses and networks in all the tables together.', to: '/firewall/settings#limits' },
  { name: 'pktdelay-pkts', label: 'Delayed packets', help: 'Packets held by rules that delay them.' },
  { name: 'anchors', label: 'Anchors', help: 'Rule sets inside the main ruleset, such as the one for sign-in access.' },
];


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
  { key: 'srcNodes', label: 'Source tracking', help: 'Sources tracked by rules with source limits or sticky addresses.' },
  { key: 'fragments', label: 'Fragments', help: 'Packets waiting for the rest of their fragments.' },
];

// The bytes rounded, with the exact count on hover; the packets under.
function Count({ c }: { c: { packets: number; bytes: number } }) {
  return (
    <div>
      <Tooltip label={`${num(c.bytes)} bytes`} disabled={c.bytes < 1000}>
        <Text span size="sm" className="num" c={c.packets ? undefined : 'dimmed'}>{formatBytes(c.bytes)}</Text>
      </Tooltip>
      <Text size="xs" c="dimmed" className="num">{num(c.packets)} pkts</Text>
    </div>
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
        What pf passed and blocked on each interface since its counters were cleared, usually at boot. A group such as egress or all has no counts of its own. Its interfaces are counted instead.
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
                      {i.skip && <Tooltip label="pf doesn’t filter this interface."><Badge size="xs" variant="light" color="gray">skipped</Badge></Tooltip>}
                    </Group>
                    {i.cleared && (
                      <StartedTip at={i.cleared} label="Counting since">
                        <Text size="xs" c="dimmed">for {formatDuration((Date.now() - Date.parse(i.cleared)) / 1000)}</Text>
                      </StartedTip>
                    )}
                  </Table.Td>
                  <Table.Td ta="right"><Count c={i.inPass} /></Table.Td>
                  <Table.Td ta="right"><Count c={i.inBlock} /></Table.Td>
                  <Table.Td ta="right"><Count c={i.outPass} /></Table.Td>
                  <Table.Td ta="right"><Count c={i.outBlock} /></Table.Td>
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
        description="Everything pf counts. Totals are since pf was enabled. Rates show how fast each is rising over the last few seconds."
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
                  <Text size="xs" c="dimmed" mb="sm">Why pf matched or dropped packets. A yellow rate means a counter that signals trouble is rising now.</Text>
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
                  <Text size="xs" c="dimmed" mb="sm">How long pf keeps an idle connection, by the stage the connection has reached.</Text>
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
