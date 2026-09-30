import { useState } from 'react';
import { Link } from 'react-router';
import { Anchor, Badge, Button, Card, Grid, Group, Progress, SegmentedControl, SimpleGrid, Stack, Table, Text, ThemeIcon } from '@mantine/core';
import { IconShieldCheck, IconShieldHalf, IconWorld, IconWorldSearch, IconServer2, IconArrowDown, IconArrowUp, IconDownload } from '@tabler/icons-react';
import { useStore } from '../model/store';
import { tunnels } from '../model/types';
import { firstIPv4, ifaceState, peerOnline, peerState, useLive } from '../lib/live';
import { labelOwner } from '../lib/pfLabels';
import { rpzBlocked } from '../lib/api';
import { ranges, useHistory } from '../lib/history';
import { HistoryChart } from '../components/HistoryChart';
import { formatBits, formatBytes, formatCount, formatDuration, formatLogTime } from '../lib/format';
import { deviceName } from '../lib/labels';
import { PageHeader, SectionTitle, StatusDot, Mono } from '../components/ui';

function Tile({ icon: Icon, label, value, detail, state }: {
  icon: typeof IconWorld; label: string; value: string; detail: string; state: 'ok' | 'warn' | 'bad';
}) {
  const color = state === 'ok' ? 'teal' : state === 'warn' ? 'yellow' : 'red';
  return (
    <Card padding="md">
      <Group justify="space-between" align="flex-start" wrap="nowrap">
        <Stack gap={2}>
          <Text size="xs" c="dimmed" tt="uppercase" fw={600} lts={0.6}>
            {label}
          </Text>
          <Text fw={600} size="lg" className="num">
            {value}
          </Text>
          <Text size="xs" c="dimmed">
            {detail}
          </Text>
        </Stack>
        <ThemeIcon variant="light" color={color} size={36} radius="md">
          <Icon size={20} />
        </ThemeIcon>
      </Group>
    </Card>
  );
}

// An address without its port: 1.2.3.4:443 → 1.2.3.4, [2001:db8::1]:443 → 2001:db8::1.
function hostOnly(a: string): string {
  if (a.startsWith('[')) return a.slice(1, a.indexOf(']'));
  return a.split(':').length === 2 ? a.split(':')[0] : a;
}

function Meter({ label, used, total, format }: { label: string; used?: number; total?: number; format?: (n: number) => string }) {
  if (used === undefined || !total) {
    return (
      <Group justify="space-between">
        <Text size="sm">{label}</Text>
        <Text size="sm" c="dimmed">—</Text>
      </Group>
    );
  }
  const pct = (used / total) * 100;
  return (
    <Stack gap={6}>
      <Group justify="space-between">
        <Text size="sm">{label}</Text>
        <Text size="sm" c="dimmed" className="num">
          {format ? `${format(used)} of ${format(total)}` : `${Math.round(pct)}%`}
        </Text>
      </Group>
      <Progress value={pct} color={pct > 85 ? 'red' : pct > 65 ? 'yellow' : 'harbor'} size="sm" />
    </Stack>
  );
}

export function Dashboard() {
  const { applied } = useStore();
  const { data: sys } = useLive('system');
  const { data: ifs } = useLive('interfaces');
  const { data: upd } = useLive('updates');
  const wan = applied.interfaces.find((i) => i.role === 'wan');
  const [range, setRange] = useState(ranges[1].value);
  const wanSeries = wan ? [{ key: `if.${wan.device}.rx`, label: 'Download', color: 'harbor.6' }, { key: `if.${wan.device}.tx`, label: 'Upload', color: 'amber.6' }] : [];
  const { data: history } = useHistory(wanSeries.map((x) => x.key), Number(range));
  const wanStatus = wan ? ifaceState(ifs, wan) : undefined;
  const wanUp = !!wanStatus?.up && wanStatus.status !== 'no carrier' && wanStatus.ipv4.length > 0;
  const vpns = tunnels(applied);
  const peers = vpns.flatMap((t) => t.wireguard.peers.map((p) => ({ tunnel: t, peer: p })));
  const connectedPeers = peers.filter(({ tunnel, peer }) => peerOnline(peerState(ifs, tunnel, peer))).length;
  const { data: pfs } = useLive('pfStatus');
  const { data: log } = useLive('firewallLog');
  const { data: dns } = useLive('dnsStats');
  const dnsBlocking = (applied.dns.blocklists ?? []).some((l) => l.enabled) || (applied.dns.blocked ?? []).length > 0;
  const rate = (n: number) => (n < 10 ? n.toFixed(1) : String(Math.round(n)));
  const blocked = (log?.entries ?? []).filter((e) => e.action === 'block').slice(0, 5);
  const blockedPerMin = pfs?.blockedPerSec !== undefined ? Math.round(pfs.blockedPerSec * 60) : undefined;
  const statsIface = pfs?.info?.iface ? applied.interfaces.find((i) => i.device === pfs.info!.iface!.name)?.name ?? pfs.info.iface.name : undefined;
  const hardware = sys && [[sys.vendor, sys.product].filter(Boolean).join(' '), sys.cpuModel, `${sys.cpus} ${sys.cpus === 1 ? 'core' : 'cores'}`].filter(Boolean).join(' · ');
  const patches = upd?.patches.length ?? 0;
  const disks = sys?.disks ?? [];
  const diskTotal = disks.reduce((n, d) => n + d.total, 0);
  const diskUsed = disks.reduce((n, d) => n + d.used, 0);
  const temp = sys?.sensors.find((x) => x.type === 'temp' && x.number !== undefined);

  return (
    <>
      <PageHeader
        title="Dashboard"
        description={sys ? `OpenBSD ${sys.release} on ${hardware}.${sys.bootedAt ? ` Up for ${formatDuration((Date.now() - Date.parse(sys.bootedAt)) / 1000)}.` : ''}` : 'Reading the system…'}
      />

      <SimpleGrid cols={{ base: 1, xs: 2, md: 3, xl: 5 }} spacing="md" mb="md">
        <Tile
          icon={IconWorld}
          label="Internet"
          value={!ifs ? '…' : wanUp ? 'Connected' : 'Offline'}
          detail={firstIPv4(wanStatus) ? `${firstIPv4(wanStatus)}${wan?.ipv4.mode === 'dhcp' ? ' via DHCP' : ''}` : 'No address'}
          state={!ifs || wanUp ? 'ok' : 'bad'}
        />
        <Tile
          icon={IconShieldHalf}
          label="Firewall"
          value={!pfs ? '…' : !pfs.info ? 'Unknown' : !pfs.info.enabled ? 'Disabled' : `${formatCount(pfs.info.states)} states`}
          detail={pfs?.info && !pfs.info.enabled ? 'pf isn’t filtering anything' : blockedPerMin !== undefined && statsIface ? `${formatCount(blockedPerMin)} packets a minute blocked on ${statsIface}` : 'Connections through and to the firewall'}
          state={!pfs || (pfs.info?.enabled ?? false) ? 'ok' : 'bad'}
        />
        <Tile
          icon={IconWorldSearch}
          label="DNS"
          value={!applied.dns.enabled ? 'Off' : !dns ? '…' : dns.stats ? (dns.queriesPerSec !== undefined ? `${rate(dns.queriesPerSec)} queries/s` : 'Answering') : 'Not answering'}
          detail={
            !applied.dns.enabled ? 'The resolver isn’t running'
              : !dns?.stats ? (dns?.errors[0] ? 'Couldn’t read its counters' : 'Name lookups for your networks')
              : dnsBlocking && dns.blockedPerSec !== undefined ? `${rate(dns.blockedPerSec)} blocked a second, ${formatCount(rpzBlocked(dns.stats))} in all`
              : `${Math.round((dns.stats.cacheHits / Math.max(1, dns.stats.cacheHits + dns.stats.cacheMisses)) * 100)}% answered from the cache`
          }
          state={!applied.dns.enabled || !dns || dns.stats ? 'ok' : 'bad'}
        />
        <Tile
          icon={IconServer2}
          label="VPN"
          value={`${connectedPeers} of ${peers.length} connected`}
          detail={vpns.length ? `WireGuard on port${vpns.length === 1 ? '' : 's'} ${vpns.map((t) => t.wireguard.listenPort).join(', ')}` : 'No tunnels'}
          state={connectedPeers > 0 ? 'ok' : 'warn'}
        />
        <Tile
          icon={IconShieldCheck}
          label="Updates"
          value={!upd || (upd.checking && !upd.checkedAt) ? 'Checking…' : upd.error ? 'Couldn’t check' : patches ? `${patches} ${patches === 1 ? 'patch' : 'patches'} available` : 'Up to date'}
          detail={sys ? `Security fixes for OpenBSD ${sys.release}` : 'Security fixes'}
          state={upd?.error ? 'warn' : patches ? 'warn' : 'ok'}
        />
      </SimpleGrid>

      <Grid gutter="md">
        <Grid.Col span={{ base: 12, lg: 8 }}>
          <Card h="100%">
            <SectionTitle
              right={
                <Group gap="lg">
                  <Group gap={4}>
                    <IconArrowDown size={14} color="var(--mantine-color-harbor-6)" />
                    <Text size="sm" className="num">{wanStatus?.rxBps !== undefined ? formatBits(wanStatus.rxBps) : '—'}</Text>
                  </Group>
                  <Group gap={4}>
                    <IconArrowUp size={14} color="var(--mantine-color-amber-6)" />
                    <Text size="sm" className="num">{wanStatus?.txBps !== undefined ? formatBits(wanStatus.txBps) : '—'}</Text>
                  </Group>
                  <SegmentedControl size="xs" value={range} onChange={setRange} data={ranges} />
                </Group>
              }
            >
              Internet traffic
            </SectionTitle>
            {wan ? (
              <HistoryChart data={history} series={wanSeries} range={Number(range)} format={formatBits} area h={250} />
            ) : (
              <Text size="sm" c="dimmed" h={250} pt="xl" ta="center">No internet interface is set up.</Text>
            )}
            <Anchor component={Link} to="/diagnostics/graphs" size="xs" c="dimmed">More graphs</Anchor>
          </Card>
        </Grid.Col>

        <Grid.Col span={{ base: 12, lg: 4 }}>
          <Card h="100%">
            <SectionTitle right={<Anchor component={Link} to="/interfaces" size="sm">Manage</Anchor>}>Interfaces</SectionTitle>
            <Stack gap="md">
              {applied.interfaces.map((i) => {
                const s = ifaceState(ifs, i);
                const addr = i.ipv4.mode === 'static' ? `${i.ipv4.address}/${i.ipv4.prefix}` : s?.ipv4[0] ?? '—';
                return (
                  <Group key={i.id} justify="space-between" wrap="nowrap" align="flex-start">
                    <Stack gap={2}>
                      <StatusDot ok={!!s?.up && s.status !== 'no carrier' && i.enabled} label={i.name} />
                      <Mono c="dimmed">{addr}</Mono>
                    </Stack>
                    <Stack gap={2} align="flex-end">
                      <Text size="xs" c="dimmed" className="num">↓ {s?.rxBps !== undefined ? formatBits(s.rxBps) : '—'}</Text>
                      <Text size="xs" c="dimmed" className="num">↑ {s?.txBps !== undefined ? formatBits(s.txBps) : '—'}</Text>
                    </Stack>
                  </Group>
                );
              })}
            </Stack>
          </Card>
        </Grid.Col>

        <Grid.Col span={{ base: 12, md: 6, lg: 4 }}>
          <Card h="100%">
            <SectionTitle>System</SectionTitle>
            <Stack gap="md">
              <Meter label="CPU" used={sys?.cpu ? 100 - sys.cpu.idle : undefined} total={100} />
              <Meter label="Memory" used={sys?.memory ? sys.memory.total - sys.memory.free : undefined} total={sys?.memory?.total} format={formatBytes} />
              <Meter label="Storage" used={disks.length ? diskUsed : undefined} total={diskTotal} format={formatBytes} />
              {sys && (
                <Text size="xs" c="dimmed" className="num">
                  {sys.load && `Load ${sys.load.map((l) => l.toFixed(2)).join(', ')}`}
                  {temp && ` · ${temp.number!.toFixed(0)} °C`}
                </Text>
              )}
              {patches > 0 && (
                <Group justify="space-between" mt={4}>
                  <Text size="sm" c="dimmed">
                    {patches} security {patches === 1 ? 'patch' : 'patches'} ready
                  </Text>
                  <Button size="xs" variant="light" leftSection={<IconDownload size={14} />} component={Link} to="/system/general">
                    Review
                  </Button>
                </Group>
              )}
            </Stack>
          </Card>
        </Grid.Col>

        <Grid.Col span={{ base: 12, md: 6, lg: 4 }}>
          <Card h="100%">
            <SectionTitle>Services</SectionTitle>
            <Stack gap="sm">
              {[
                { name: 'DHCP server', ok: applied.dhcp.some((d) => d.enabled), note: `${applied.dhcp.filter((d) => d.enabled).length} networks` },
                { name: 'DNS resolver', ok: applied.dns.enabled, note: applied.dns.mode === 'recursive' ? 'Recursive, DNSSEC' : 'Forwarding' },
                { name: 'WireGuard VPN', ok: vpns.some((t) => t.enabled), note: `${vpns.filter((t) => t.enabled).length} of ${vpns.length} tunnels, ${peers.length} devices` },
                {
                  name: 'Time sync',
                  ok: !!sys?.time?.synced,
                  note: !sys ? '…' : !sys.time ? 'Not running' : sys.time.synced ? `Synced${sys.time.offsetMs !== undefined ? `, offset ${Math.abs(sys.time.offsetMs) < 10 ? (Math.round(sys.time.offsetMs * 10) / 10 || 0).toFixed(1) : Math.round(sys.time.offsetMs)} ms` : ''}` : 'Not synced yet',
                },
              ].map((s) => (
                <Group key={s.name} justify="space-between">
                  <StatusDot ok={s.ok} label={s.name} />
                  <Text size="xs" c="dimmed">{s.note}</Text>
                </Group>
              ))}
            </Stack>
          </Card>
        </Grid.Col>

        <Grid.Col span={{ base: 12, lg: 4 }}>
          <Card h="100%">
            <SectionTitle right={<Anchor component={Link} to="/diagnostics/log" size="sm">View log</Anchor>}>
              Recently blocked
            </SectionTitle>
            <Table verticalSpacing={6} horizontalSpacing={0} fz="sm">
              <Table.Tbody>
                {blocked.map((b, i) => (
                  <Table.Tr key={`${b.time}-${i}`}>
                    <Table.Td>
                      <Mono>{hostOnly(b.source ?? '—')}</Mono>
                      <Text size="xs" c="dimmed">
                        {labelOwner(applied, b.label)?.text ?? (b.rule < 0 ? 'pf’s default rule' : `pf rule ${b.rule}`)}
                      </Text>
                    </Table.Td>
                    <Table.Td ta="right" style={{ verticalAlign: 'top' }}>
                      <Badge color="gray" size="sm">{deviceName(applied, b.iface)}</Badge>
                      <Text size="xs" c="dimmed" className="num">{formatLogTime(b.time)}</Text>
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
            {log && blocked.length === 0 && <Text size="sm" c="dimmed">Nothing blocked has been logged yet.</Text>}
          </Card>
        </Grid.Col>
      </Grid>
    </>
  );
}
