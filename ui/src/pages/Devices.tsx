// Diagnostics › Devices: every device OPF knows of, and one device's
// page with everything about it together: who it is (its lease,
// reservation, ARP entries, VPN tunnel), the network it's on, its
// connections now, its events and firewall log, and, where they're
// kept, its traffic and DNS activity.
import { useEffect, useMemo, useState } from 'react';
import { Link, useParams } from 'react-router';
import { Alert, Anchor, Badge, Card, Grid, Group, SegmentedControl, SimpleGrid, Stack, Table, Text, TextInput } from '@mantine/core';
import { IconAlertTriangle, IconSearch } from '@tabler/icons-react';
import { backend, useStore } from '../model/store';
import type { DeviceInfo, DevicesResource, DnsDeviceActivityResource, FirewallLogEntry, OpfEvent, PfState, TrafficDeviceResource } from '../lib/api';
import { useRole } from '../lib/session';
import { formatAgo, formatBytes, formatDuration, formatLogTime } from '../lib/format';
import { Empty, Mono, PageHeader, SectionTitle } from '../components/ui';
import { TrafficHoursChart } from './Traffic';
import { DeviceLink } from '../components/DeviceLink';

const errorText = (e: unknown) => (e instanceof Error ? e.message : String(e));
const kindWords: Record<DeviceInfo['kind'], string> = { device: 'Device', vpn: 'VPN device', address: 'Address only', firewall: 'This firewall' };


const label = (d: DeviceInfo) => d.name || d.mac || d.addresses[0] || d.key;

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

/** Diagnostics › Devices: every device OPF knows of. */
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
                        <Text size="xs" c="dimmed">{kindWords[d.kind]}{d.mac && d.name ? <> · <Mono>{d.mac}</Mono></> : ''}</Text>
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

function TrafficCard({ deviceKey, days }: { deviceKey: string; days: number }) {
  const [data, setData] = useState<TrafficDeviceResource | null>();
  useEffect(() => {
    let live = true;
    backend.trafficDevice(deviceKey, days).then((d) => live && setData(d), () => live && setData(null));
    return () => { live = false; };
  }, [deviceKey, days]);
  return (
    <Card>
      <SectionTitle right={<Anchor component={Link} to="/diagnostics/traffic" size="xs">Traffic</Anchor>}>Traffic</SectionTitle>
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

function Names({ title, items }: { title: string; items: { name: string; count: number }[] }) {
  return (
    <Stack gap={2}>
      <Text size="xs" c="dimmed" tt="uppercase" fw={600} lts={0.6}>{title}</Text>
      {items.length ? items.slice(0, 8).map((n) => (
        <Group key={n.name} justify="space-between" wrap="nowrap" gap="xs">
          <Text size="sm" className="mono" style={{ wordBreak: 'break-all' }}>{n.name}</Text>
          <Text size="sm" className="num">{n.count.toLocaleString()}</Text>
        </Group>
      )) : <Text size="sm" c="dimmed">None</Text>}
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
          <SimpleGrid cols={{ base: 1, sm: 3 }} spacing="lg">
            <Names title="Looked up most" items={data.names} />
            <Names title="Blocked most" items={data.blocked} />
            <Names title="Not found most" items={data.missing} />
          </SimpleGrid>
        </Stack>
      )}
    </Card>
  );
}

function Connections({ addresses }: { addresses: string[] }) {
  const [states, setStates] = useState<PfState[]>();
  const [error, setError] = useState<string>();
  useEffect(() => {
    let live = true;
    Promise.all(addresses.map((a) => backend.pfStates({ query: a, limit: 25 })))
      .then((rs) => live && setStates(rs.flatMap((r) => r.states)), (e) => live && setError(errorText(e)));
    return () => { live = false; };
  }, [addresses.join()]);
  return (
    <Card>
      <SectionTitle right={<Anchor component={Link} to="/diagnostics/connections" size="xs">Connections</Anchor>}>Connections now</SectionTitle>
      {error ? <Alert color="red" variant="light" p="sm">{error}</Alert> : !states ? <Text size="sm" c="dimmed">Reading…</Text> : states.length ? (
        <Table.ScrollContainer minWidth={560}>
          <Table verticalSpacing={4}>
            <Table.Tbody>
              {states.slice(0, 25).map((s) => (
                <Table.Tr key={s.id + s.creatorId}>
                  <Table.Td><Text size="xs" c="dimmed">{s.proto}</Text></Table.Td>
                  <Table.Td><Text size="sm" className="mono" style={{ wordBreak: 'break-all' }}>{s.source} → {s.destination}</Text>{s.translated && <Text size="xs" c="dimmed" className="mono">via {s.translated}</Text>}</Table.Td>
                  <Table.Td><Text size="xs" c="dimmed">{s.state}</Text></Table.Td>
                  <Table.Td ta="right"><Text size="sm" className="num">{formatBytes(s.bytes)}</Text><Text size="xs" c="dimmed">{formatDuration(s.ageSec)}</Text></Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      ) : <Empty>None now.</Empty>}
    </Card>
  );
}

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
      <SectionTitle right={<Anchor component={Link} to="/diagnostics/events" size="xs">Events</Anchor>}>Events</SectionTitle>
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

function FirewallLog({ addresses }: { addresses: string[] }) {
  const [entries, setEntries] = useState<FirewallLogEntry[]>();
  useEffect(() => {
    let live = true;
    backend.firewallLog().then((r) => live && setEntries(r.entries.filter((e) => addresses.some((a) => hasAddr(e.source, a) || hasAddr(e.destination, a)))), () => live && setEntries([]));
    return () => { live = false; };
  }, [addresses.join()]);
  return (
    <Card h="100%">
      <SectionTitle right={<Anchor component={Link} to="/diagnostics/log" size="xs">Firewall log</Anchor>}>Firewall log</SectionTitle>
      {!entries ? <Text size="sm" c="dimmed">Reading…</Text> : entries.length ? (
        <Stack gap={4}>
          {entries.slice(0, 15).map((e, i) => (
            <Group key={e.time + i} gap="xs" wrap="nowrap" align="flex-start">
              <Text size="xs" c="dimmed" w={110} style={{ flexShrink: 0 }}>{formatLogTime(e.time)}</Text>
              <Text size="sm" c={e.action === 'block' ? 'red' : undefined}>{e.action}</Text>
              <Text size="sm" className="mono" style={{ wordBreak: 'break-all' }}>{e.proto} {e.source} → {e.destination}</Text>
            </Group>
          ))}
        </Stack>
      ) : <Empty>Nothing logged for it lately.</Empty>}
    </Card>
  );
}

/** Diagnostics › Devices › one device: everything about it together. */
export function Device() {
  const { key = '' } = useParams();
  const { applied } = useStore();
  const { canEdit } = useRole();
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
  const traffic = canEdit && !!applied.firewall.traffic?.enabled;
  const dns = canEdit && applied.dns.enabled && !!applied.dns.activity?.enabled && !!applied.dns.activity.devices;
  const kept = Math.max(traffic ? applied.firewall.traffic!.days : 1, dns ? applied.dns.activity!.days : 1);
  const n = Math.min(Number(days), kept);
  const ranges = [{ value: '1', label: 'Today' }, ...[7, 31].filter((x) => x <= kept).map((x) => ({ value: String(x), label: x === 31 ? 'Month' : `${x} days` }))];
  const terms = d ? [...(d.mac ? [d.mac] : []), ...d.addresses] : [];

  return (
    <>
      <Group gap="xs" mb={4}><Anchor component={Link} to="/diagnostics/devices" size="sm">Devices</Anchor></Group>
      <PageHeader
        title={d ? label(d) : 'Device'}
        description={d ? `${kindWords[d.kind]}${d.networks.length ? ` on ${d.networks.map((x) => x.name).join(' and ')}` : ''}${d.addresses.length ? ` · ${d.addresses.join(', ')}` : ''}` : undefined}
        actions={(traffic || dns) && ranges.length > 1 ? <SegmentedControl size="xs" data={ranges} value={days} onChange={setDays} /> : undefined}
      />
      {error && <Alert color="red" variant="light" icon={<IconAlertTriangle size={16} />}>{error}</Alert>}
      {!d && !error && <Text size="sm" c="dimmed">Reading…</Text>}
      {d && (
        <Stack gap="md">
          <Grid gutter="md">
            <Grid.Col span={{ base: 12, md: d.vpn ? 7 : 12 }}><Identity d={d} /></Grid.Col>
            {d.vpn && <Grid.Col span={{ base: 12, md: 5 }}><VPN v={d.vpn} /></Grid.Col>}
          </Grid>
          {traffic && <TrafficCard deviceKey={d.key} days={n} />}
          {dns && <DnsCard deviceKey={d.key} days={n} />}
          {!canEdit && (applied.firewall.traffic?.enabled || applied.dns.activity?.enabled) && (
            <Text size="xs" c="dimmed">Its traffic and DNS activity are kept, but only admins can see them.</Text>
          )}
          {d.addresses.length > 0 && <Connections addresses={d.addresses} />}
          <Grid gutter="md">
            <Grid.Col span={{ base: 12, md: 6 }}><Events terms={terms} /></Grid.Col>
            {d.addresses.length > 0 && <Grid.Col span={{ base: 12, md: 6 }}><FirewallLog addresses={d.addresses} /></Grid.Col>}
          </Grid>
        </Stack>
      )}
    </>
  );
}
