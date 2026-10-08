// Monitoring › Graphs: what the collector kept, over an hour to a
// month: traffic on each interface, the system, pf, DNS and the
// gateways.
import { Card, Grid, SegmentedControl, SimpleGrid, Text } from '@mantine/core';
import { useSearchParams } from 'react-router';
import { useStore } from '../model/store';
import { HistoryChart, seriesKeys, type ChartSeries } from '../components/HistoryChart';
import { tunnels } from '../model/types';
import { poolSize } from '../lib/ip';
import { ranges, useEventMarks, useHistory, type Mark } from '../lib/history';
import { formatBits, formatBytes } from '../lib/format';
import { PageHeader, SectionTitle } from '../components/ui';

const perSec = (n: number) => `${n < 10 ? n.toFixed(1) : Math.round(n).toLocaleString()}/s`;
const pct = (n: number) => `${n < 10 ? n.toFixed(1) : Math.round(n)}%`;
const bits = (n: number) => formatBits(n);
const ms = (n: number) => `${n < 10 ? n.toFixed(1) : Math.round(n)} ms`;

function Graph({ title, note, ...chart }: { title: string; note?: string } & Parameters<typeof HistoryChart>[0]) {
  return (
    <Card>
      <SectionTitle>{title}</SectionTitle>
      <HistoryChart {...chart} />
      {note && <Text size="xs" c="dimmed" mt={4}>{note}</Text>}
    </Card>
  );
}

export function Graphs() {
  const { applied } = useStore();
  const [params, setParams] = useSearchParams();
  const range = Number(ranges.find((r) => r.value === params.get('range'))?.value ?? 86400);
  const ifaces = [...applied.interfaces.filter((i) => i.enabled)].sort((a, b) => Number(b.role === 'wan') - Number(a.role === 'wan'));
  const gateways = applied.routing.gateways;
  const traffic = (dev: string): ChartSeries[] => [
    { key: `if.${dev}.rx`, label: 'In', color: 'harbor.6' },
    { key: `if.${dev}.tx`, label: 'Out', color: 'amber.6' },
  ];
  const system: ChartSeries[] = [{ key: 'cpu.busy', label: 'CPU', color: 'harbor.6' }];
  const memory: ChartSeries[] = [{ key: 'mem.used', label: 'Memory in use', color: 'grape.6' }];
  const load: ChartSeries[] = [{ key: 'load.1', label: 'Load', color: 'teal.6' }];
  const states: ChartSeries[] = [{ key: 'pf.states', label: 'States', color: 'harbor.6' }];
  const blocked: ChartSeries[] = [{ key: 'pf.blocked', label: 'Blocked', color: 'red.6' }];
  const blocking = (applied.dns.blocklists ?? []).some((l) => l.enabled) || (applied.dns.blocked ?? []).length > 0;
  const dns: ChartSeries[] = [
    { key: 'dns.queries', label: 'Queries', color: 'harbor.6' },
    ...(blocking ? [{ key: 'dns.blocked', label: 'Blocked', color: 'red.6' }] : []),
  ];
  const cache: ChartSeries[] = [{ key: 'dns.cachehit', label: 'From the cache', color: 'teal.6' }];
  const colors = ['harbor.6', 'amber.6', 'grape.6', 'teal.6', 'pink.6', 'lime.6'];
  const rtt: ChartSeries[] = gateways.map((g, i) => ({ key: `gw.${g.id}.rtt`, label: g.name, color: colors[i % colors.length] }));
  const loss: ChartSeries[] = gateways.map((g, i) => ({ key: `gw.${g.id}.loss`, label: g.name, color: colors[i % colors.length] }));
  const vpns = tunnels(applied).filter((t) => t.enabled && t.wireguard.peers.length);
  const peerTraffic = (t: (typeof vpns)[number]): ChartSeries[] =>
    t.wireguard.peers.map((p, i) => ({ key: `wg.${p.id}.rx`, plus: `wg.${p.id}.tx`, label: p.name, color: colors[i % colors.length] }));
  const pools = applied.dhcp.filter((d) => d.enabled);
  const leases: ChartSeries[] = pools.map((d, i) => {
    const iface = applied.interfaces.find((x) => x.id === d.iface);
    const size = poolSize(d.rangeStart, d.rangeEnd);
    return { key: `dhcp.${d.iface}.leases`, label: `${iface?.name ?? d.iface}${size ? ` (of ${size})` : ''}`, color: colors[i % colors.length] };
  });
  const offset: ChartSeries[] = [{ key: 'time.offset', label: 'Offset', color: 'harbor.6' }];
  const all = [...ifaces.flatMap((i) => traffic(i.device)), ...system, ...memory, ...load, ...states, ...blocked, ...dns, ...cache, ...rtt, ...loss, ...vpns.flatMap(peerTraffic), ...leases, ...offset];
  const keys = seriesKeys(all);
  const { data, error } = useHistory(keys, range);
  const common = { data, range };
  const events = useEventMarks(range);
  const marksOf = (...subjects: string[]): Mark[] => subjects.flatMap((s) => events.get(s) ?? []);

  return (
    <>
      <PageHeader
        title="Graphs"
        description="What OPF has recorded, sampled every 10 seconds and kept for a month: the last hour in full, older times averaged."
        actions={<SegmentedControl size="xs" value={String(range)} data={ranges} onChange={(v) => setParams(v === '86400' ? {} : { range: v }, { replace: true })} />}
      />
      {error && !data && <Text c="red" size="sm" mb="md">Couldn’t ask OPF: {error}</Text>}
      <Text fw={600} mb="sm">Traffic</Text>
      <SimpleGrid cols={{ base: 1, lg: 2 }} spacing="md" mb="lg">
        {ifaces.map((i) => (
          <Graph key={i.id} title={`${i.name} (${i.device})`} series={traffic(i.device)} format={bits} area peaks marks={marksOf(i.id)} {...common} />
        ))}
      </SimpleGrid>
      <Text fw={600} mb="sm">System and firewall</Text>
      <Grid gutter="md" mb="lg">
        <Grid.Col span={{ base: 12, md: 6, lg: 4 }}><Graph title="CPU" series={system} format={pct} {...common} /></Grid.Col>
        <Grid.Col span={{ base: 12, md: 6, lg: 4 }}><Graph title="Memory" series={memory} format={formatBytes} {...common} /></Grid.Col>
        <Grid.Col span={{ base: 12, md: 6, lg: 4 }}><Graph title="Load" series={load} format={(n) => n.toFixed(2)} {...common} /></Grid.Col>
        <Grid.Col span={{ base: 12, md: 6 }}><Graph title="Connections (pf states)" series={states} format={(n) => Math.round(n).toLocaleString()} {...common} /></Grid.Col>
        <Grid.Col span={{ base: 12, md: 6 }}>
          <Graph title="Packets blocked" series={blocked} format={perSec} note="On pf’s statistics interface (Firewall › Settings)." empty="Nothing recorded: pf needs a statistics interface for this." {...common} />
        </Grid.Col>
      </Grid>
      {applied.dns.enabled && (
        <>
          <Text fw={600} mb="sm">DNS</Text>
          <Grid gutter="md" mb="lg">
            <Grid.Col span={{ base: 12, md: 7 }}><Graph title="Queries" series={dns} format={perSec} marks={marksOf('unbound')} {...common} /></Grid.Col>
            <Grid.Col span={{ base: 12, md: 5 }}><Graph title="Answered from the cache" series={cache} format={pct} {...common} /></Grid.Col>
          </Grid>
        </>
      )}
      {gateways.length > 0 && (
        <>
          <Text fw={600} mb="sm">Gateways</Text>
          <Grid gutter="md">
            <Grid.Col span={{ base: 12, md: 6 }}><Graph title="Latency" series={rtt} format={ms} peaks note="Pinged every 30 seconds." marks={marksOf(...gateways.map((g) => g.id))} {...common} /></Grid.Col>
            <Grid.Col span={{ base: 12, md: 6 }}><Graph title="Packet loss" series={loss} format={pct} marks={marksOf(...gateways.map((g) => g.id))} {...common} /></Grid.Col>
          </Grid>
        </>
      )}
      {vpns.length > 0 && (
        <>
          <Text fw={600} mb="sm" mt="lg">VPN</Text>
          <SimpleGrid cols={{ base: 1, lg: 2 }} spacing="md">
            {vpns.map((t) => (
              <Graph key={t.id} title={`${t.name}: traffic by device`} series={peerTraffic(t)} format={bits} marks={marksOf(t.id, ...t.wireguard.peers.map((p) => p.id))} {...common} />
            ))}
          </SimpleGrid>
        </>
      )}
      <Text fw={600} mb="sm" mt="lg">DHCP and time</Text>
      <Grid gutter="md">
        {pools.length > 0 && <Grid.Col span={{ base: 12, md: 7 }}><Graph title="DHCP leases in use" series={leases} format={(n) => String(Math.round(n))} {...common} /></Grid.Col>}
        <Grid.Col span={{ base: 12, md: pools.length ? 5 : 12 }}>
          <Graph title="Clock offset" series={offset} format={(n) => `${n.toFixed(Math.abs(n) < 10 ? 1 : 0)} ms`} note="How far the clock is from the time server ntpd follows." {...common} />
        </Grid.Col>
      </Grid>
    </>
  );
}
