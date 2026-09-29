import { useEffect, useState } from 'react';
import { Link } from 'react-router';
import { Anchor, Badge, Button, Card, Grid, Group, Progress, SimpleGrid, Stack, Table, Text, ThemeIcon } from '@mantine/core';
import { AreaChart } from '@mantine/charts';
import { IconShieldCheck, IconShieldHalf, IconWorld, IconServer2, IconArrowDown, IconArrowUp, IconDownload } from '@tabler/icons-react';
import { useStore } from '../model/store';
import { tunnels } from '../model/types';
import { ifaceStatus, logEntries, peerStatus, pfStats, stepTraffic, systemInfo, trafficSeries, type TrafficPoint } from '../model/live';
import { formatBits, formatBytes, formatCount, formatDuration } from '../lib/format';
import { ifaceName } from '../lib/labels';
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

function useTraffic() {
  const [series, setSeries] = useState<TrafficPoint[]>(() => trafficSeries());
  useEffect(() => {
    const t = setInterval(() => {
      setSeries((s) => {
        const last = s[s.length - 1];
        const { down, up } = stepTraffic(last.download, last.upload);
        const next: TrafficPoint = {
          time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
          download: Math.round(down * 10) / 10,
          upload: Math.round(up * 10) / 10,
        };
        return [...s.slice(1), next];
      });
    }, 3000);
    return () => clearInterval(t);
  }, []);
  return series;
}

function Meter({ label, used, total, format }: { label: string; used: number; total: number; format?: (n: number) => string }) {
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
  const traffic = useTraffic();
  const last = traffic[traffic.length - 1];
  const wan = applied.interfaces.find((i) => i.role === 'wan');
  const wanStatus = wan ? ifaceStatus[wan.id] : undefined;
  const vpns = tunnels(applied);
  const peers = vpns.flatMap((t) => t.wireguard.peers);
  const connectedPeers = peers.filter((p) => (peerStatus[p.id]?.handshakeSecAgo ?? Infinity) < 180).length;
  const blocked = logEntries().slice(0, 5);
  const uptime = formatDuration((Date.now() - systemInfo.bootedAt) / 1000);

  return (
    <>
      <PageHeader
        title="Dashboard"
        description={`${systemInfo.version} on ${systemInfo.hardware}. Up for ${uptime}.`}
      />

      <SimpleGrid cols={{ base: 1, xs: 2, lg: 4 }} spacing="md" mb="md">
        <Tile
          icon={IconWorld}
          label="Internet"
          value={wanStatus?.up ? 'Connected' : 'Offline'}
          detail={wanStatus?.address ? `${wanStatus.address.split('/')[0]} via DHCP` : 'No address'}
          state={wanStatus?.up ? 'ok' : 'bad'}
        />
        <Tile
          icon={IconShieldHalf}
          label="Firewall"
          value={`${formatCount(pfStats.states)} connections`}
          detail={`${formatCount(pfStats.blockedLastHour)} blocked in the last hour`}
          state="ok"
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
          value={`${systemInfo.patches.length} patches available`}
          detail="Security fixes for OpenBSD 7.8"
          state={systemInfo.patches.length ? 'warn' : 'ok'}
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
                    <Text size="sm" className="num">{last.download} Mbit/s</Text>
                  </Group>
                  <Group gap={4}>
                    <IconArrowUp size={14} color="var(--mantine-color-amber-6)" />
                    <Text size="sm" className="num">{last.upload} Mbit/s</Text>
                  </Group>
                </Group>
              }
            >
              Internet traffic
            </SectionTitle>
            <AreaChart
              h={250}
              data={traffic}
              dataKey="time"
              series={[
                { name: 'download', label: 'Download', color: 'harbor.6' },
                { name: 'upload', label: 'Upload', color: 'amber.6' },
              ]}
              curveType="monotone"
              withDots={false}
              gridAxis="x"
              tickLine="none"
              unit=" Mbit/s"
              fillOpacity={0.25}
              strokeWidth={1.75}
              xAxisProps={{ interval: 14 }}
              yAxisProps={{ width: 70 }}
            />
          </Card>
        </Grid.Col>

        <Grid.Col span={{ base: 12, lg: 4 }}>
          <Card h="100%">
            <SectionTitle right={<Anchor component={Link} to="/interfaces" size="sm">Manage</Anchor>}>Interfaces</SectionTitle>
            <Stack gap="md">
              {applied.interfaces.map((i) => {
                const s = ifaceStatus[i.id];
                const addr = i.ipv4.mode === 'static' ? `${i.ipv4.address}/${i.ipv4.prefix}` : s?.address ?? '—';
                return (
                  <Group key={i.id} justify="space-between" wrap="nowrap" align="flex-start">
                    <Stack gap={2}>
                      <StatusDot ok={!!s?.up && i.enabled} label={i.name} />
                      <Mono c="dimmed">{addr}</Mono>
                    </Stack>
                    <Stack gap={2} align="flex-end">
                      <Text size="xs" c="dimmed" className="num">↓ {formatBits(s?.rxBps ?? 0)}</Text>
                      <Text size="xs" c="dimmed" className="num">↑ {formatBits(s?.txBps ?? 0)}</Text>
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
              <Meter label="CPU" used={18} total={100} />
              <Meter label="Memory" used={systemInfo.memoryUsed} total={systemInfo.memoryTotal} format={formatBytes} />
              <Meter label="Storage" used={systemInfo.diskUsed} total={systemInfo.diskTotal} format={formatBytes} />
              <Group justify="space-between" mt={4}>
                <Text size="sm" c="dimmed">
                  {systemInfo.patches.length} security patches ready
                </Text>
                <Button size="xs" variant="light" leftSection={<IconDownload size={14} />} component={Link} to="/system/general">
                  Review
                </Button>
              </Group>
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
                { name: 'WireGuard VPN', ok: vpns.some((t) => t.enabled), note: `${vpns.filter((t) => t.enabled).length} of ${vpns.length} tunnels, ${peers.length} peers` },
                { name: 'Time sync', ok: true, note: 'Synced, offset 0.4 ms' },
                { name: 'SSH', ok: true, note: 'LAN only' },
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
                {blocked.map((b) => (
                  <Table.Tr key={b.id}>
                    <Table.Td>
                      <Mono>{b.source.split(':')[0]}</Mono>
                      <Text size="xs" c="dimmed">
                        {b.rule}
                      </Text>
                    </Table.Td>
                    <Table.Td ta="right" style={{ verticalAlign: 'top' }}>
                      <Badge color="gray" size="sm">{ifaceName(applied, b.iface)}</Badge>
                      <Text size="xs" c="dimmed" className="num">{b.time}</Text>
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Card>
        </Grid.Col>
      </Grid>
    </>
  );
}
