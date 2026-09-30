// What the DNS resolver is doing: its counters and rates, what the
// blocklists blocked most with a way to let a name through, what the
// lists cost in memory, and, for the review dialog, the pause a full
// reload means.
import { useEffect, useState } from 'react';
import { Alert, Button, Card, Group, SimpleGrid, Stack, Table, Text, Tooltip } from '@mantine/core';
import { IconAlertTriangle, IconClockPause } from '@tabler/icons-react';
import { backend, useStore } from '../model/store';
import { rpzBlocked, type DnsListStatus } from '../lib/api';
import { useLive } from '../lib/live';
import { estimateBytes, memoryLevel, modelNames, reloadSeconds } from '../lib/dnsCost';
import { formatBytes, formatCount, formatDuration, formatLogTime } from '../lib/format';
import type { Model } from '../model/types';
import { Empty, SectionTitle } from '../components/ui';
import { HistoryCard } from '../components/HistoryChart';


function Stat({ label, value, detail, tip }: { label: string; value: string; detail?: string; tip?: string }) {
  const body = (
    <Stack gap={0}>
      <Text size="xs" c="dimmed" tt="uppercase" fw={600} lts={0.6}>{label}</Text>
      <Text fw={600} size="lg" className="num">{value}</Text>
      {detail && <Text size="xs" c="dimmed">{detail}</Text>}
    </Stack>
  );
  return tip ? <Tooltip label={tip} multiline w={280}><div>{body}</div></Tooltip> : body;
}

const pct = (n: number, of: number) => (of ? `${((n / of) * 100).toFixed(n / of < 0.1 ? 1 : 0)}%` : '—');
const perSec = (n?: number) => (n === undefined ? '…' : `${n < 10 ? n.toFixed(1) : Math.round(n)}/s`);

// Answers by response code, as people would put them.
const rcodeWords: Record<string, string> = { NOERROR: 'found', NXDOMAIN: 'no such name', SERVFAIL: 'failed', REFUSED: 'refused', FORMERR: 'malformed' };

/** The resolver's numbers now, at the top of the DNS page. */
export function DnsStatsCard() {
  const { applied } = useStore();
  const { data, error } = useLive('dnsStats');
  const { data: sys } = useLive('system');
  if (!applied.dns.enabled && !data?.enabled) return null;
  const s = data?.stats;
  const answers = s ? Object.entries(s.answers).filter(([k]) => k !== 'nodata') : [];
  const answered = answers.reduce((n, [, c]) => n + c, 0);
  const blocked = s ? rpzBlocked(s) : 0;
  const blocking = (applied.dns.blocklists ?? []).some((l) => l.enabled) || (applied.dns.blocked ?? []).length > 0;
  const physmem = sys?.memory?.total;
  return (
    <Card mb="md">
      <SectionTitle right={s && <Text size="xs" c="dimmed">Counting since unbound started {formatDuration(s.uptime)} ago</Text>}>Right now</SectionTitle>
      <Stack gap="sm">
        {error && !data && <Alert color="red" variant="light" p="sm" icon={<IconAlertTriangle size={16} />}>Couldn’t ask OPF: {error}</Alert>}
        {data?.errors.map((e) => <Alert key={e} color="yellow" variant="light" p="sm" icon={<IconAlertTriangle size={16} />}>{e}</Alert>)}
        {s && (
          <>
            <SimpleGrid cols={{ base: 2, sm: 3, lg: 5 }} spacing="md">
              <Stat label="Queries" value={perSec(data?.queriesPerSec)} detail={`${formatCount(s.queries)} in all`} />
              <Stat label="From the cache" value={pct(s.cacheHits, s.cacheHits + s.cacheMisses)} detail="answered without asking" />
              <Stat
                label="Lookups"
                value={s.cacheMisses ? `${Math.round(s.recursionMedian * 1000)} ms` : '—'}
                detail="typical, when not cached"
                tip={`Half the lookups that weren’t in the cache took less than this; they averaged ${Math.round(s.recursionAvg * 1000)} ms.`}
              />
              <Stat
                label="Blocked"
                value={blocking || blocked ? perSec(data?.blockedPerSec) : 'Off'}
                detail={blocking || blocked ? `${pct(blocked, s.queries)} of queries` : 'no blocklists'}
              />
              <Stat
                label="Memory"
                value={data?.memoryBytes ? formatBytes(data.memoryBytes) : '—'}
                detail={data?.memoryBytes && physmem ? `${pct(data.memoryBytes, physmem)} of the RAM` : 'unbound, lists included'}
              />
            </SimpleGrid>
            <HistoryCard
              title="Over time"
              series={[{ key: 'dns.queries', label: 'Queries', color: 'harbor.6' }, ...(blocking ? [{ key: 'dns.blocked', label: 'Blocked', color: 'red.6' }] : [])]}
              format={(n) => `${n < 10 ? n.toFixed(1) : Math.round(n)}/s`}
              h={150}
              markSubjects={['unbound']}
            />
            {s.extended && answered > 0 && (
              <Group gap="lg">
                <Text size="xs" c="dimmed">
                  Answers: {answers.sort((a, b) => b[1] - a[1]).map(([k, c]) => `${pct(c, answered)} ${rcodeWords[k] ?? k}`).join(' · ')}
                </Text>
                {applied.dns.dnssec && (
                  <Text size="xs" c={s.bogus ? 'yellow' : 'dimmed'}>
                    DNSSEC: {formatCount(s.secure)} verified{s.bogus ? `, ${formatCount(s.bogus)} failed the check and weren’t answered` : ''}
                  </Text>
                )}
              </Group>
            )}
          </>
        )}
        {data && !s && !data.errors.length && <Text size="sm" c="dimmed">Starts once the resolver is applied.</Text>}
      </Stack>
    </Card>
  );
}

const listName = (m: Model, id?: string) => (id === undefined ? 'your own entry' : (m.dns.blocklists ?? []).find((l) => l.id === id)?.name ?? id);

// How many of the names blocked most show before "Show more".
const SHOWN = 10;

/** The names blocked most lately, from unbound's log, with “never block”. */
export function DnsBlockedNames() {
  const { applied, staged, edit } = useStore();
  const { data, error } = useLive('dnsBlocked');
  const [all, setAll] = useState(false);
  const blocking = (applied.dns.blocklists ?? []).some((l) => l.enabled) || (applied.dns.blocked ?? []).length > 0;
  if (!applied.dns.enabled || (!blocking && !data?.blocked)) return null;
  const allowed = new Set((staged.dns.allowed ?? []).map((n) => n.toLowerCase()));
  const own = new Set((staged.dns.blocked ?? []).map((n) => n.toLowerCase()));
  const by = [
    ...Object.entries(data?.byList ?? {}).sort((a, b) => b[1] - a[1]).map(([id, n]) => `${n.toLocaleString()} by ${listName(applied, id)}`),
    ...(data?.own ? [`${data.own.toLocaleString()} by your own names`] : []),
  ];
  return (
    <Card>
      <SectionTitle right={data?.since && <Text size="xs" c="dimmed">Since {formatLogTime(data.since)}</Text>}>Blocked most</SectionTitle>
      <Stack gap="sm">
        {error && !data && <Alert color="red" variant="light" p="sm" icon={<IconAlertTriangle size={16} />}>Couldn’t ask OPF: {error}</Alert>}
        {data?.error && <Alert color="yellow" variant="light" p="sm" icon={<IconAlertTriangle size={16} />}>{data.error}</Alert>}
        {data && data.blocked > 0 && (
          <Text size="sm" c="dimmed">
            {data.blocked.toLocaleString()} {data.blocked === 1 ? 'query' : 'queries'} blocked{by.length > 1 ? `: ${by.join(', ')}` : ''}
            {data.allowed ? `. Your never-block names let ${data.allowed.toLocaleString()} through` : ''}. Which device asked isn’t kept.
          </Text>
        )}
        {data?.names.length ? (
          <>
            <Table verticalSpacing={6}>
              <Table.Tbody>
                {data.names.slice(0, all ? undefined : SHOWN).map((n) => {
                  // Your own exact entry is taken out; anything else is let through.
                  const ownExact = own.has(n.name);
                  const letThrough = allowed.has(n.name);
                  return (
                    <Table.Tr key={n.name}>
                      <Table.Td>
                        {/* Asked for by devices on the network; shown as text, never markup. */}
                        <Text size="sm" className="mono" style={{ wordBreak: 'break-all' }}>{n.name}</Text>
                        <Text size="xs" c="dimmed">
                          by {listName(applied, n.list)}{n.entry !== n.name ? `, as ${n.entry}` : ''} · last {formatLogTime(n.last)}
                        </Text>
                      </Table.Td>
                      <Table.Td ta="right" style={{ verticalAlign: 'top', whiteSpace: 'nowrap' }}>
                        <Text size="sm" className="num">{n.count.toLocaleString()}</Text>
                        {letThrough ? (
                          <Text size="xs" c="teal">Never blocked</Text>
                        ) : ownExact ? (
                          <Button size="compact-xs" variant="subtle" mr={-8} onClick={() => edit('dns', `Stopped blocking ${n.name}`, (m) => ({ ...m, dns: { ...m.dns, blocked: (m.dns.blocked ?? []).filter((b) => b.toLowerCase() !== n.name) } }))}>
                            Stop blocking
                          </Button>
                        ) : (
                          <Button size="compact-xs" variant="subtle" mr={-8} onClick={() => edit('dns', `Never block ${n.name}`, (m) => ({ ...m, dns: { ...m.dns, allowed: [...(m.dns.allowed ?? []), n.name] } }))}>
                            Never block
                          </Button>
                        )}
                      </Table.Td>
                    </Table.Tr>
                  );
                })}
              </Table.Tbody>
            </Table>
            {data.names.length > SHOWN && (
              <Group justify="center" mt="xs">
                <Button size="compact-xs" variant="subtle" color="gray" onClick={() => setAll(!all)}>{all ? 'Show fewer' : `Show ${data.names.length - SHOWN} more`}</Button>
              </Group>
            )}
          </>
        ) : (
          data && !data.error && <Empty>Nothing blocked has been logged yet.</Empty>
        )}
      </Stack>
    </Card>
  );
}

/** What the enabled lists cost in memory, next to the machine's, when it's a lot. */
export function BlocklistMemory({ status }: { status?: DnsListStatus[] }) {
  const { staged } = useStore();
  const { data: sys } = useLive('system');
  const physmem = sys?.memory?.total;
  const { names, unknown } = modelNames(staged, status);
  const bytes = estimateBytes(names);
  const level = memoryLevel(bytes, physmem);
  if (level === 'ok' || !physmem) return null;
  return (
    <Alert color={level === 'warn' ? 'red' : 'yellow'} variant="light" p="sm" icon={<IconAlertTriangle size={16} />}
      title={level === 'warn' ? 'These lists may not fit in memory' : 'These lists take a lot of memory'}>
      <Text size="sm">
        {names.toLocaleString()} names{unknown ? `, plus ${unknown === 1 ? 'a list' : `${unknown} lists`} not downloaded yet,` : ''} take the resolver about {formatBytes(bytes)} of this machine’s {formatBytes(physmem)} of RAM, and a list briefly takes twice its share while it’s downloaded again.
        {level === 'warn' ? ' Without enough memory unbound stops answering, and every device loses DNS.' : ''} Lighter lists block most of the same: Hagezi Light or Normal instead of Pro, or one big list rather than several that overlap.
      </Text>
    </Alert>
  );
}

/** In the review dialog, when a change reloads unbound whole: how long DNS stops while it loads its lists. */
export function ResolverReloadNotice({ model }: { model: Model }) {
  const { data } = useLive('dnsStats');
  const [status, setStatus] = useState<DnsListStatus[]>();
  useEffect(() => { backend.dnsLists().then(setStatus, () => setStatus([])); }, []);
  if (!model.dns.enabled || !status) return null;
  const { names, unknown } = modelNames(model, status);
  const last = data?.lastReload;
  const secs = reloadSeconds(names, last);
  const lastText = last && !last.timedOut ? ` The last one, with ${last.names.toLocaleString()} names, took ${last.seconds.toFixed(1)} s.` : last?.timedOut ? ' The last one hadn’t finished after three minutes.' : '';
  if (secs < 3 && !unknown && !last?.timedOut) {
    return <Text size="sm" c="dimmed">The DNS resolver reloads, which empties its cache.{lastText}</Text>;
  }
  return (
    <Alert color="yellow" variant="light" icon={<IconClockPause size={18} />} title="DNS pauses while the resolver reloads">
      <Text size="sm">
        These changes reload the DNS resolver whole. Devices can’t look names up until it has loaded its lists ({names.toLocaleString()} names{unknown ? `, and ${unknown === 1 ? 'a list' : `${unknown} lists`} not downloaded yet` : ''}): about {Math.max(1, Math.round(secs))} s{unknown ? ' or more' : ''}.{lastText}
      </Text>
    </Alert>
  );
}
