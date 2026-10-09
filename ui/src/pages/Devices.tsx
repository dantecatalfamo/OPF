// Devices: every device OPF knows of, and one device's
// page with everything about it together: who it is (its lease,
// reservation, ARP entries, VPN tunnel), the network it's on, its
// connections now, its events and firewall log, and, where they're
// kept, its traffic and DNS activity.
import { useEffect, useMemo, useState } from 'react';
import { Link, useParams } from 'react-router';
import { Alert, Anchor, Badge, Box, Card, Grid, Group, Progress, SegmentedControl, SimpleGrid, Stack, Table, Text, TextInput, Tooltip } from '@mantine/core';
import { IconAlertTriangle, IconSearch } from '@tabler/icons-react';
import { useElementSize } from '@mantine/hooks';
import { backend, useStore } from '../model/store';
import type { DeviceInfo, DevicesResource, DnsDeviceActivityResource, FirewallLogEntry, OpfEvent, PfState, TrafficDeviceResource } from '../lib/api';
import { useRole } from '../lib/session';
import { formatAgo, formatBits, formatBytes, formatDuration, formatLogTime } from '../lib/format';
import { Empty, Mono, PageHeader, SectionTitle } from '../components/ui';
import { TrafficHoursChart } from './Traffic';
import { HistoryCard } from '../components/HistoryChart';
import { rulesFor } from '../lib/deviceRules';
import { DeviceLink } from '../components/DeviceLink';
import { listName } from './DnsHistory';
import { NamesSwitch, Wrapped } from '../components/HostName';
import { hostOf, useReverseNames, useShowNames } from '../lib/reverseNames';
import { protoGroup, stateWord } from '../lib/connections';
import { StateTip } from '../components/StateTip';
import { DirLabel, ProtoBadge } from '../components/ConnBadges';
import { LogAction, LogRule, LogTime } from './FirewallLog';
import { StartedTip } from '../components/StartedTip';
import { AllowedBy } from './Connections';
import { deviceName } from '../lib/labels';

const errorText = (e: unknown) => (e instanceof Error ? e.message : String(e));
const kindWords: Record<DeviceInfo['kind'], string> = { device: 'Device', vpn: 'VPN device', address: 'Address only', firewall: 'This firewall' };


const label = (d: DeviceInfo) => d.name || d.mac || d.addresses[0] || d.key;

const nameFromWords: Record<NonNullable<DeviceInfo['nameFrom']>, string> = {
  reservation: 'from its DHCP reservation',
  dns: 'its name in DNS, from its lease',
  asked: 'what it calls itself: it isn’t in DNS',
  vpn: 'the VPN device’s name',
};

function Sources({ d }: { d: DeviceInfo }) {
  return (
    <Group gap={4}>
      {d.reservation && <Badge size="xs" variant="light" color="teal">Reserved</Badge>}
      {d.lease && <Badge size="xs" variant="light">Lease</Badge>}
      {d.arp?.length ? <Badge size="xs" variant="light" color="gray">ARP</Badge> : null}
      {d.vpn && <Badge size="xs" variant="light" color="grape">VPN</Badge>}
    </Group>
  );
}

/** Devices: every device OPF knows of. */
export function Devices() {
  const [data, setData] = useState<DevicesResource>();
  const [error, setError] = useState<string>();
  const [q, setQ] = useState('');
  useEffect(() => {
    const load = () => backend.devices().then((d) => { setData(d); setError(undefined); }, (e) => setError(errorText(e)));
    load();
    const t = setInterval(load, 30_000);
    return () => clearInterval(t);
  }, []);
  const shown = useMemo(() => {
    const n = q.trim().toLowerCase();
    return (data?.devices ?? []).filter((d) => !n || [d.name, d.mac, ...d.addresses, ...d.networks.map((x) => x.name)].some((s) => s?.toLowerCase().includes(n)));
  }, [data, q]);
  return (
    <>
      <PageHeader title="Devices" description="Every device OPF knows of: from DHCP leases and reservations, the ARP table and VPN tunnels. Each one’s page has everything about it." />
      <Card>
        <Stack gap="sm">
          <TextInput placeholder="Name, address or MAC" leftSection={<IconSearch size={14} />} value={q} onChange={(e) => setQ(e.currentTarget.value)} w={320} />
          {error && <Alert color="red" variant="light" p="sm" icon={<IconAlertTriangle size={16} />}>Couldn’t ask OPF: {error}</Alert>}
          {data?.errors.map((e) => <Alert key={e} color="yellow" variant="light" p="sm">{e}</Alert>)}
          {!data && !error && <Text size="sm" c="dimmed">Reading…</Text>}
          {data && (shown.length ? (
            <Table.ScrollContainer minWidth={640}>
              <Table verticalSpacing={6} highlightOnHover>
                <Table.Thead>
                  <Table.Tr><Table.Th>Device</Table.Th><Table.Th>Address</Table.Th><Table.Th>Network</Table.Th><Table.Th>Known from</Table.Th></Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {shown.map((d) => (
                    <Table.Tr key={d.key}>
                      <Table.Td>
                        <DeviceLink deviceKey={d.key}>{label(d)}</DeviceLink>
                        <Text size="xs" c="dimmed">
                          {kindWords[d.kind]}{d.nameFrom === 'asked' ? ' · its own name' : ''}{d.mac && d.name ? <> · <Mono>{d.mac}</Mono></> : ''}
                        </Text>
                      </Table.Td>
                      <Table.Td><Text size="sm" className="mono">{d.addresses.join(', ') || '—'}</Text></Table.Td>
                      <Table.Td><Text size="sm">{d.networks.map((n) => n.name).join(', ') || '—'}</Text></Table.Td>
                      <Table.Td><Sources d={d} /></Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            </Table.ScrollContainer>
          ) : <Empty>{q ? 'No device matches.' : 'No devices yet.'}</Empty>)}
        </Stack>
      </Card>
    </>
  );
}

function Row({ k, children }: { k: string; children: React.ReactNode }) {
  return (
    <Group gap="xs" wrap="nowrap" align="flex-start">
      <Text size="sm" c="dimmed" w={130} style={{ flexShrink: 0 }}>{k}</Text>
      <Text size="sm" component="div" style={{ minWidth: 0 }}>{children}</Text>
    </Group>
  );
}

function Identity({ d }: { d: DeviceInfo }) {
  const l = d.lease;
  return (
    <Card h="100%">
      <SectionTitle>Who it is</SectionTitle>
      <Stack gap={6}>
        {d.name && <Row k="Name">{d.name}{d.nameFrom && <Text span size="xs" c={d.nameFrom === 'asked' ? 'yellow' : 'dimmed'}> · {nameFromWords[d.nameFrom]}</Text>}</Row>}
        <Row k="Kind">{kindWords[d.kind]}</Row>
        {d.mac && <Row k="MAC address"><Mono>{d.mac}</Mono></Row>}
        <Row k="Addresses">{d.addresses.length ? d.addresses.map((a, i) => <span key={a}>{i > 0 && ', '}<Mono>{a}</Mono></span>) : 'None now'}</Row>
        <Row k="Network">{d.networks.length ? d.networks.map((n, i) => (
          <span key={n.id}>{i > 0 && ', '}<Anchor component={Link} to={d.kind === 'vpn' ? `/services/wireguard/${n.id}` : `/interfaces/${n.id}`} size="sm">{n.name}</Anchor> <Text span size="xs" c="dimmed">({n.device})</Text></span>
        )) : '—'}</Row>
        {d.firstSeen && <Row k="First seen">{formatLogTime(d.firstSeen)}</Row>}
        {d.reservation && (
          <Row k="Reservation">
            <Mono>{d.reservation.ip}</Mono> as {d.reservation.hostname || 'no name'} · <Anchor component={Link} to={`/services/dhcp?iface=${encodeURIComponent(d.reservation.network)}`} size="sm">DHCP</Anchor>
          </Row>
        )}
        {l && (
          <Row k="DHCP lease">
            <Mono>{l.ip}</Mono>{l.hostname ? <> · asked to be called {l.hostname}</> : ''}
            {l.dnsName ? <> · in DNS as <Mono>{l.dnsName}</Mono></> : l.dnsRefused ? <Text span size="sm" c="yellow"> · no name in DNS: {l.dnsRefused}</Text> : ''}
            <Text size="xs" c="dimmed">{l.starts ? `since ${formatLogTime(l.starts)}` : ''}{l.ends ? ` · ends ${formatLogTime(l.ends)}` : ' · doesn’t end'}</Text>
          </Row>
        )}
        {d.arp?.map((a) => (
          <Row key={a.ip + a.iface} k="ARP"><Mono>{a.ip}</Mono> on {a.iface} · {a.expires === 'permanent' ? 'permanent' : `expires in ${a.expires}`}</Row>
        ))}
      </Stack>
    </Card>
  );
}

function VPN({ v }: { v: NonNullable<DeviceInfo['vpn']> }) {
  return (
    <Card h="100%">
      <SectionTitle>VPN</SectionTitle>
      <Stack gap={6}>
        <Row k="Tunnel"><Anchor component={Link} to={`/services/wireguard/${v.tunnel}`} size="sm">{v.tunnelName}</Anchor></Row>
        <Row k="Address"><Mono>{v.address}</Mono></Row>
        <Row k="Sends">{v.clientRoutes === 'full' ? 'All its traffic through OPF' : v.clientRoutes === 'split' ? 'Only your networks’ traffic' : v.clientRoutes === 'vpn' ? 'Only the tunnel’s network' : 'Its site’s networks'}</Row>
        <Row k="Last handshake">
          {v.handshakeAgo !== undefined ? formatAgo(v.handshakeAgo) : v.lastSeen ? formatLogTime(v.lastSeen) : 'Never'}
          {(v.endpoint || v.lastFrom) && <Text span size="sm" c="dimmed"> from <Mono>{v.endpoint || v.lastFrom}</Mono></Text>}
        </Row>
        {(v.rxBytes > 0 || v.txBytes > 0) && <Row k="Since the tunnel came up">{formatBytes(v.rxBytes)} from it, {formatBytes(v.txBytes)} to it</Row>}
      </Stack>
    </Card>
  );
}

function Rules({ addresses }: { addresses: string[] }) {
  const { applied } = useStore();
  const rules = rulesFor(applied, addresses);
  return (
    <Card h="100%">
      <SectionTitle right={<Anchor component={Link} to="/firewall/rules" size="xs">Rules</Anchor>}>Firewall rules</SectionTitle>
      {rules.length ? (
        <Stack gap={8}>
          {rules.map((r) => (
            <Stack key={r.kind + r.id} gap={0}>
              <Group gap={6}>
                <Anchor component={Link} to={r.to} size="sm" c={r.enabled ? undefined : 'dimmed'}>{r.description}</Anchor>
                {!r.enabled && <Badge size="xs" variant="light" color="gray">Off</Badge>}
                {r.kind === 'forward' && <Badge size="xs" variant="light">Port forward</Badge>}
              </Group>
              <Text size="xs" c="dimmed">{r.how}</Text>
            </Stack>
          ))}
        </Stack>
      ) : <Empty>No rule or port forward names it.</Empty>}
    </Card>
  );
}

function TrafficCard({ deviceKey, days }: { deviceKey: string; days: number }) {
  const [data, setData] = useState<TrafficDeviceResource | null>();
  useEffect(() => {
    let live = true;
    backend.trafficDevice(deviceKey, days).then((d) => live && setData(d), () => live && setData(null));
    return () => { live = false; };
  }, [deviceKey, days]);
  return (
    <Card>
      <SectionTitle right={<Anchor component={Link} to="/devices/traffic" size="xs">Traffic</Anchor>}>Traffic</SectionTitle>
      {data === undefined ? <Text size="sm" c="dimmed">Reading…</Text> : data === null ? <Empty>None counted for it over these days.</Empty> : (
        <Stack gap="sm">
          <SimpleGrid cols={2}>
            <Stat label="Received" value={formatBytes(data.total.received)} />
            <Stat label="Sent" value={formatBytes(data.total.sent)} />
          </SimpleGrid>
          <TrafficHoursChart hours={data.hours} days={days} />
        </Stack>
      )}
    </Card>
  );
}

function Stat({ label, value, detail }: { label: string; value: string; detail?: string }) {
  return (
    <Stack gap={0}>
      <Text size="xs" c="dimmed" tt="uppercase" fw={600} lts={0.6}>{label}</Text>
      <Text fw={600} size="lg" className="num">{value}</Text>
      {detail && <Text size="xs" c="dimmed">{detail}</Text>}
    </Stack>
  );
}

type TopList = 'names' | 'blocked' | 'missing';
const topLists: { value: TopList; label: string; empty: string }[] = [
  { value: 'names', label: 'Looked up', empty: 'Nothing looked up.' },
  { value: 'blocked', label: 'Blocked', empty: 'Nothing blocked.' },
  { value: 'missing', label: 'Not found', empty: 'Every name it asked for was found.' },
];

// One of the device's top names lists at a time, each name with its
// count beside it and a bar for its share of the list's first.
function TopNames({ data }: { data: DnsDeviceActivityResource }) {
  const { applied } = useStore();
  const [list, setList] = useState<TopList>('names');
  const items = data[list];
  const top = Math.max(1, ...items.map((n) => n.count));
  const current = topLists.find((l) => l.value === list)!;
  return (
    <Stack gap="xs">
      <SegmentedControl
        size="xs"
        style={{ alignSelf: 'flex-start' }}
        value={list}
        onChange={(v) => setList(v as TopList)}
        data={topLists.map((l) => ({ value: l.value, label: `${l.label} · ${data[l.value].length}` }))}
      />
      {items.length ? (
        <Table verticalSpacing={4} horizontalSpacing="xs">
          <Table.Tbody>
            {items.slice(0, 10).map((n) => (
              <Table.Tr key={n.name}>
                <Table.Td w="40%">
                  {/* Asked for by a device on the network: text, never markup. */}
                  <Text size="sm" className="mono" style={{ wordBreak: 'break-all' }}>{n.name}</Text>
                  {list === 'blocked' && <Text size="xs" c="dimmed">by {listName(applied, n.list)}{n.entry && n.entry !== n.name ? `, as ${n.entry}` : ''}</Text>}
                </Table.Td>
                <Table.Td>
                  <Progress size="sm" value={(n.count / top) * 100} color={list === 'blocked' ? 'red' : list === 'missing' ? 'yellow' : undefined} aria-hidden />
                </Table.Td>
                <Table.Td ta="right" w={70} style={{ whiteSpace: 'nowrap' }}>
                  <Text size="sm" className="num">{n.err ? '≈' : ''}{n.count.toLocaleString()}</Text>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      ) : <Text size="sm" c="dimmed" py="xs">{current.empty}</Text>}
      {items.length > 10 && <Text size="xs" c="dimmed">The first 10 of {items.length}; the rest are on <Anchor component={Link} to="/services/dns?tab=activity" size="xs">DNS activity</Anchor>.</Text>}
    </Stack>
  );
}

function DnsCard({ deviceKey, days }: { deviceKey: string; days: number }) {
  const [data, setData] = useState<DnsDeviceActivityResource | null>();
  useEffect(() => {
    let live = true;
    backend.dnsDeviceActivity(deviceKey, days).then((d) => live && setData(d), () => live && setData(null));
    return () => { live = false; };
  }, [deviceKey, days]);
  return (
    <Card>
      <SectionTitle right={<Anchor component={Link} to="/services/dns?tab=activity" size="xs">DNS activity</Anchor>}>DNS</SectionTitle>
      {data === undefined ? <Text size="sm" c="dimmed">Reading…</Text> : data === null ? <Empty>None kept for it over these days.</Empty> : (
        <Stack gap="md">
          <SimpleGrid cols={{ base: 2, sm: 4 }}>
            <Stat label="Queries" value={data.total.queries.toLocaleString()} />
            <Stat label="Blocked" value={data.total.blocked.toLocaleString()} />
            <Stat label="No such name" value={(data.total.nxdomain ?? 0).toLocaleString()} />
            <Stat label="Failed" value={(data.total.servfail ?? 0).toLocaleString()} />
          </SimpleGrid>
          <TopNames data={data} />
        </Stack>
      )}
    </Card>
  );
}

// One connection, as this device's page shows it: the other end (its
// address, port and name), which way it was opened, and what's left of
// pf's detail (this device's own address and port, the raw state) on
// hover.
interface DeviceConn {
  key: string;
  proto: string;
  /** out: this device opened it; in: it was opened to the device. */
  dir: 'out' | 'in';
  farHost: string;
  farPort?: string;
  ownEnd: string;
  /** The address it leaves as or arrives at, through NAT. */
  via?: string;
  state: string;
  kind?: string;
  /** The state's direction, as pf has it (which end its pair names first). */
  pfDir: 'in' | 'out';
  bytes: number;
  ageSec: number;
  /** The state whose rule let it through: the one made where it came
   *  in, since a state going out is pf's own pass out rule's. */
  allowedBy: PfState;
}

const splitEnd = (end: string) => {
  const h = hostOf(end) ?? end;
  const rest = end.slice(end.indexOf(h) + h.length).replace(/^[:[\]]+|\]$/g, '');
  return { host: h, port: rest || undefined };
};

// A connection through the firewall has a state on each side, the same
// ends both times; one row each, with the NAT address when one has it.
function deviceConns(states: PfState[], own: string[]): DeviceConn[] {
  const byKey = new Map<string, DeviceConn>();
  for (const s of states) {
    const fromOwn = own.includes(hostOf(s.source) ?? '');
    const far = splitEnd(fromOwn ? s.destination : s.source);
    const key = `${s.proto} ${s.source} ${s.destination}`;
    const prev = byKey.get(key);
    const c: DeviceConn = {
      key, proto: protoGroup(s.proto), dir: fromOwn ? 'out' : 'in', farHost: far.host, farPort: far.port, ownEnd: fromOwn ? s.source : s.destination,
      via: s.translated ? splitEnd(s.translated).host : prev?.via, state: s.state, kind: s.kind, pfDir: s.direction === 'in' ? 'in' : 'out', bytes: Math.max(s.bytes, prev?.bytes ?? 0), ageSec: Math.max(s.ageSec, prev?.ageSec ?? 0),
      allowedBy: prev && prev.allowedBy.direction === 'in' ? prev.allowedBy : s,
    };
    byKey.set(key, c);
  }
  return [...byKey.values()].sort((a, b) => b.bytes - a.bytes);
}

function Connections({ addresses, showNames }: { addresses: string[]; showNames: boolean }) {
  const [states, setStates] = useState<PfState[]>();
  const [error, setError] = useState<string>();
  useEffect(() => {
    let live = true;
    Promise.all(addresses.map((a) => backend.pfStates({ query: a, limit: 25 })))
      .then((rs) => live && setStates(rs.flatMap((r) => r.states)), (e) => live && setError(errorText(e)));
    return () => { live = false; };
  }, [addresses.join()]);
  const conns = useMemo(() => deviceConns(states ?? [], addresses).slice(0, 25), [states, addresses.join()]); // eslint-disable-line react-hooks/exhaustive-deps
  const names = useReverseNames(conns.map((c) => c.farHost), showNames);
  // The rule that let each in, when there's room for it; in a narrow
  // card, each connection in two lines.
  const { ref, width } = useElementSize();
  const wide = width >= 860;
  const table = !width || width >= 560;
  const way = (c: DeviceConn) => (
    <Tooltip label={c.dir === 'out' ? `Outgoing: this device opened it to the other end, from ${c.ownEnd}` : `Incoming: the other end opened it to this device, at ${c.ownEnd}`}>
      <Group gap={8} wrap="nowrap">
        <ProtoBadge proto={c.proto} />
        <DirLabel dir={c.dir === 'out' ? 'out' : 'in'}>{c.dir === 'out' ? 'Outgoing' : 'Incoming'}</DirLabel>
      </Group>
    </Tooltip>
  );
  const far = (c: DeviceConn) => (
    <Text size="sm" className="mono" fw={500}>
      <span style={{ whiteSpace: 'nowrap' }}>{c.farHost}</span>{c.farPort && <Text span size="sm" c="dimmed" className="mono" fw={400} style={{ whiteSpace: 'nowrap' }}> port {c.farPort}</Text>}
    </Text>
  );
  const farMore = (c: DeviceConn) => {
    const name = names.get(c.farHost);
    if (!name && !c.via) return null;
    return (
      <>
        {name && <span className="mono"><Wrapped name={name} /></span>}
        {name && c.via && ' · '}
        {c.via && <>{c.dir === 'out' ? 'leaves as ' : 'arrives at '}<span className="mono">{c.via}</span></>}
      </>
    );
  };
  const state = (c: DeviceConn, size: 'sm' | 'xs') => (
    <StateTip state={c.state} direction={c.pfDir} opener={c.dir === 'out' ? 'This device' : 'The other end'} other={c.dir === 'out' ? 'the other end' : 'this device'}>
      <Text size={size} c="dimmed" style={{ whiteSpace: 'nowrap' }}>{stateWord(c.state, c.kind)}</Text>
    </StateTip>
  );
  return (
    <Card>
      <SectionTitle right={<Anchor component={Link} to="/firewall/connections" size="xs">Connections</Anchor>}>Connections now</SectionTitle>
      <div ref={ref} />
      {error ? <Alert color="red" variant="light" p="sm">{error}</Alert> : !states ? <Text size="sm" c="dimmed">Reading…</Text> : !conns.length ? <Empty>None now.</Empty> : table ? (
        <Table verticalSpacing={6} highlightOnHover>
          <Table.Thead>
            <Table.Tr>
              <Table.Th w={160}>Direction</Table.Th>
              <Table.Th>Other end</Table.Th>
              {wide && <Table.Th>Allowed by</Table.Th>}
              <Table.Th w={100}>State</Table.Th>
              <Table.Th w={90} ta="right">Data</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {conns.map((c) => {
              const more = farMore(c);
              return (
                <Table.Tr key={c.key}>
                  <Table.Td>{way(c)}</Table.Td>
                  <Table.Td>
                    {far(c)}
                    {more && <Text size="xs" c="dimmed">{more}</Text>}
                  </Table.Td>
                  {wide && <Table.Td><AllowedBy c={c.allowedBy} /></Table.Td>}
                  <Table.Td>{state(c, 'sm')}</Table.Td>
                  <Table.Td ta="right" style={{ whiteSpace: 'nowrap' }}>
                    <Text size="sm" className="num">{formatBytes(c.bytes)}</Text>
                    <Text size="xs" c="dimmed"><StartedTip ageSec={c.ageSec}>{formatDuration(c.ageSec)}</StartedTip></Text>
                  </Table.Td>
                </Table.Tr>
              );
            })}
          </Table.Tbody>
        </Table>
      ) : (
        <Stack gap={0}>
          {conns.map((c, i) => {
            const more = farMore(c);
            return (
              <Stack key={c.key} gap={4} py="sm" style={i ? { borderTop: '1px solid var(--mantine-color-default-border)' } : undefined}>
                <Group gap={10} wrap="wrap" style={{ rowGap: 2 }}>
                  {way(c)}
                  {far(c)}
                </Group>
                {more && <Text size="xs" c="dimmed">{more}</Text>}
                <Group gap={6} wrap="wrap" style={{ rowGap: 2 }}>
                  {state(c, 'xs')}
                  <Text size="xs" c="dimmed" className="num" style={{ whiteSpace: 'nowrap' }}>· {formatBytes(c.bytes)} · <StartedTip ageSec={c.ageSec}>{formatDuration(c.ageSec)}</StartedTip></Text>
                </Group>
              </Stack>
            );
          })}
        </Stack>
      )}
    </Card>
  );
}

// The name of the end of a log entry that isn't this device, under it,
// when it has one.
function Events({ terms }: { terms: string[] }) {
  const [events, setEvents] = useState<OpfEvent[]>();
  useEffect(() => {
    let live = true;
    Promise.all(terms.map((q) => backend.events({ query: q, limit: 20 })))
      .then((rs) => live && setEvents(rs.flatMap((r) => r.events).sort((a, b) => b.time.localeCompare(a.time)).filter((e, i, all) => i === 0 || e.time !== all[i - 1].time || e.message !== all[i - 1].message)),
        () => live && setEvents([]));
    return () => { live = false; };
  }, [terms.join()]);
  return (
    <Card h="100%">
      <SectionTitle right={<Anchor component={Link} to="/monitoring/events" size="xs">Events</Anchor>}>Events</SectionTitle>
      {!events ? <Text size="sm" c="dimmed">Reading…</Text> : events.length ? (
        <Stack gap={4}>
          {events.slice(0, 15).map((e) => (
            <Group key={e.time + e.message} gap="xs" wrap="nowrap" align="flex-start">
              <Text size="xs" c="dimmed" w={110} style={{ flexShrink: 0 }}>{formatLogTime(e.time)}</Text>
              <Text size="sm" c={e.warning ? 'yellow' : undefined}>{e.message}</Text>
            </Group>
          ))}
        </Stack>
      ) : <Empty>None about it.</Empty>}
    </Card>
  );
}

// An address in a log entry's source or destination, with or without a
// port: 192.168.1.5:443, [fd00::5]:53.
const hasAddr = (field: string | undefined, a: string) => !!field && (field === a || field.startsWith(a + ':') || field.startsWith(a + '.') || field.startsWith(`[${a}]`));

// A log entry from this device's side: which way it went and the other
// end, like a connection. pf leaves a decoded packet's protocol and ends
// unknown sometimes.
function logView(e: FirewallLogEntry, own: string[]) {
  const fromOwn = own.includes(hostOf(e.source) ?? '');
  const far = splitEnd((fromOwn ? e.destination : e.source) ?? '');
  const ownEnd = splitEnd((fromOwn ? e.source : e.destination) ?? '');
  return { fromOwn, far, ownEnd, ownFull: (fromOwn ? e.source : e.destination) ?? '' };
}

type LogRow = ReturnType<typeof logView> & { e: FirewallLogEntry };


function LogWay({ r }: { r: LogRow }) {
  return (
    <Tooltip label={r.fromOwn ? `Outgoing: this device sent it to the other end, from ${r.ownFull}` : `Incoming: the other end sent it to this device, at ${r.ownFull}`}>
      <Group gap={8} wrap="nowrap">
        {r.e.proto ? <ProtoBadge proto={protoGroup(r.e.proto)} /> : <Box w={52} style={{ flexShrink: 0 }} />}
        <DirLabel dir={r.fromOwn ? 'out' : 'in'}>{r.fromOwn ? 'Outgoing' : 'Incoming'}</DirLabel>
      </Group>
    </Tooltip>
  );
}

// An address never breaks; its port goes under it when it must.
const logFar = (r: LogRow) => (
  <Text size="sm" className="mono" fw={500}>
    <span style={{ whiteSpace: 'nowrap' }}>{r.far.host || '—'}</span>{r.far.port && <Text span size="sm" c="dimmed" className="mono" fw={400} style={{ whiteSpace: 'nowrap' }}> port {r.far.port}</Text>}
  </Text>
);

// The other end's name and, for what reached the device, which port.
function logFarMore(r: LogRow, name?: string) {
  const port = !r.fromOwn && r.ownEnd.port;
  if (!name && !port) return null;
  return (
    <>
      {name && <span className="mono"><Wrapped name={name} /></span>}
      {name && port && ' · '}
      {port && <>to its port <span className="mono">{port}</span></>}
    </>
  );
}

function FirewallLog({ addresses, showNames }: { addresses: string[]; showNames: boolean }) {
  const [entries, setEntries] = useState<FirewallLogEntry[]>();
  useEffect(() => {
    let live = true;
    backend.firewallLog().then((r) => live && setEntries(r.entries.filter((e) => addresses.some((a) => hasAddr(e.source, a) || hasAddr(e.destination, a)))), () => live && setEntries([]));
    return () => { live = false; };
  }, [addresses.join()]);
  const rows: LogRow[] = (entries ?? []).slice(0, 15).map((e) => ({ e, ...logView(e, addresses) }));
  const names = useReverseNames(rows.map((r) => r.far.host), showNames);
  const { applied } = useStore();
  // Its columns when the card has room for them.
  const { ref, width } = useElementSize();
  const wide = !width || width >= 760;
  return (
    <Card>
      <SectionTitle right={<Anchor component={Link} to="/firewall/log" size="xs">Firewall log</Anchor>}>Firewall log</SectionTitle>
      <div ref={ref} />
      {!entries ? <Text size="sm" c="dimmed">Reading…</Text> : !entries.length ? <Empty>Nothing logged for it lately.</Empty> : wide ? (
        <Table verticalSpacing={6} highlightOnHover>
          <Table.Thead>
            <Table.Tr>
              <Table.Th w={130}>When</Table.Th>
              <Table.Th w={160}>Direction</Table.Th>
              <Table.Th>Other end</Table.Th>
              <Table.Th>Rule</Table.Th>
              <Table.Th>Logged on</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {rows.map((r, i) => {
              const more = logFarMore(r, names.get(r.far.host));
              return (
                <Table.Tr key={r.e.time + i}>
                  <Table.Td>
                    <LogAction e={r.e} />
                    <LogTime e={r.e} />
                  </Table.Td>
                  <Table.Td><LogWay r={r} /></Table.Td>
                  <Table.Td>
                    {logFar(r)}
                    {more && <Text size="xs" c="dimmed">{more}</Text>}
                  </Table.Td>
                  <Table.Td><LogRule e={r.e} model={applied} /></Table.Td>
                  <Table.Td><Text size="sm">{deviceName(applied, r.e.iface)}</Text></Table.Td>
                </Table.Tr>
              );
            })}
          </Table.Tbody>
        </Table>
      ) : (
        // Too narrow for the columns: each entry in two lines.
        <Stack gap={0}>
          {rows.map((r, i) => {
            const more = logFarMore(r, names.get(r.far.host));
            return (
              <Stack key={r.e.time + i} gap={4} py="sm" style={i ? { borderTop: '1px solid var(--mantine-color-default-border)' } : undefined}>
                <Group gap={10} wrap="wrap" style={{ rowGap: 2 }}>
                  <LogAction e={r.e} />
                  <LogWay r={r} />
                  {logFar(r)}
                </Group>
                <Group gap={6} wrap="wrap" style={{ rowGap: 2 }}>
                  <LogTime e={r.e} />
                  <Text size="xs" c="dimmed" style={{ whiteSpace: 'nowrap' }}>· on {deviceName(applied, r.e.iface)} ·</Text>
                  <LogRule e={r.e} model={applied} />
                  {more && <Text size="xs" c="dimmed">· {more}</Text>}
                </Group>
              </Stack>
            );
          })}
        </Stack>
      )}
    </Card>
  );
}

/** Devices › one device: everything about it together. */
export function Device() {
  const { key = '' } = useParams();
  const { applied } = useStore();
  const { isAdmin, readOnly } = useRole();
  const [d, setD] = useState<DeviceInfo>();
  const [error, setError] = useState<string>();
  const [days, setDays] = useState('1');
  useEffect(() => {
    let live = true;
    setD(undefined);
    setError(undefined);
    backend.device(key).then((x) => live && setD(x), (e) => live && setError(errorText(e)));
    return () => { live = false; };
  }, [key]);
  const traffic = isAdmin && !!applied.firewall.traffic?.enabled;
  const dns = isAdmin && applied.dns.enabled && !!applied.dns.activity?.enabled && !!applied.dns.activity.devices;
  const kept = Math.max(traffic ? applied.firewall.traffic!.days : 1, dns ? applied.dns.activity!.days : 1);
  const n = Math.min(Number(days), kept);
  const ranges = [{ value: '1', label: 'Today' }, ...[7, 31].filter((x) => x <= kept).map((x) => ({ value: String(x), label: x === 31 ? 'Month' : `${x} days` }))];
  const terms = d ? [...(d.mac ? [d.mac] : []), ...d.addresses] : [];
  const [showNames, setShowNames] = useShowNames();

  return (
    <>
      <Group gap="xs" mb={4}><Anchor component={Link} to="/devices" size="sm">Devices</Anchor></Group>
      <PageHeader
        title={d ? label(d) : 'Device'}
        description={d ? `${kindWords[d.kind]}${d.networks.length ? ` on ${d.networks.map((x) => x.name).join(' and ')}` : ''}${d.addresses.length ? ` · ${d.addresses.join(', ')}` : ''}` : undefined}
        actions={
          <Group gap="md">
            {d && d.addresses.length > 0 && <NamesSwitch checked={showNames} onChange={setShowNames} />}
            {(traffic || dns) && ranges.length > 1 && <SegmentedControl size="xs" data={ranges} value={days} onChange={setDays} />}
          </Group>
        }
      />
      {error && <Alert color="red" variant="light" icon={<IconAlertTriangle size={16} />}>{error}</Alert>}
      {!d && !error && <Text size="sm" c="dimmed">Reading…</Text>}
      {d && (
        <Stack gap="md">
          <Grid gutter="md">
            <Grid.Col span={{ base: 12, md: d.vpn ? 7 : 12 }}><Identity d={d} /></Grid.Col>
            {d.vpn && <Grid.Col span={{ base: 12, md: 5 }}><VPN v={d.vpn} /></Grid.Col>}
          </Grid>
          {d.vpn && (
            <Card>
              <HistoryCard
                title="Through its tunnel"
                series={[{ key: `wg.${d.vpn.peer}.rx`, label: 'From the device', color: 'harbor.6' }, { key: `wg.${d.vpn.peer}.tx`, label: 'To the device', color: 'amber.6' }]}
                format={formatBits} h={150} empty="Nothing recorded for this device yet." markSubjects={[d.vpn.peer]}
              />
            </Card>
          )}
          {traffic && <TrafficCard deviceKey={d.key} days={n} />}
          {dns && <DnsCard deviceKey={d.key} days={n} />}
          {!isAdmin && (applied.firewall.traffic?.enabled || applied.dns.activity?.enabled) && (
            <Text size="xs" c="dimmed">Its traffic and DNS activity are kept, but only admins can see them.</Text>
          )}
          {d.addresses.length > 0 && <Connections addresses={d.addresses} showNames={showNames} />}
          <Grid gutter="md">
            {/* OPF's rules naming it: read-only, OPF has none. */}
            {d.addresses.length > 0 && !readOnly && <Grid.Col span={{ base: 12, md: 6 }}><Rules addresses={[...new Set([...d.addresses, ...(d.reservation ? [d.reservation.ip] : [])])]} /></Grid.Col>}
            <Grid.Col span={{ base: 12, md: readOnly ? 12 : 6 }}><Events terms={terms} /></Grid.Col>
          </Grid>
          {d.addresses.length > 0 && <FirewallLog addresses={d.addresses} showNames={showNames} />}
        </Stack>
      )}
    </>
  );
}
