// A graph of series from the collector over a range: one line or
// area each, gaps where nothing was recorded (OPF wasn't running, or
// the internet was down and nothing answered). With peaks, each
// series also gets a dashed line of the highest sample in each point,
// once a point is more than one sample: an hour's average hides a
// burst that filled the link.
import { useState } from 'react';
import { AreaChart, LineChart } from '@mantine/charts';
import { Anchor, ColorSwatch, Group, SegmentedControl, Text } from '@mantine/core';
import { Link } from 'react-router';
import type { MetricsResource } from '../lib/api';
import { ranges, timeLabel, useHistory } from '../lib/history';
import { formatBits } from '../lib/format';
import { SectionTitle } from './ui';

export interface ChartSeries {
  key: string;
  /** Another series added to this one (a peer's in and out). */
  plus?: string;
  label: string;
  color: string;
}

export const seriesKeys = (s: ChartSeries[]) => s.flatMap((x) => (x.plus ? [x.key, x.plus] : [x.key]));

export function HistoryChart({ data, series, range, format, area, peaks, h = 200, empty }: {
  data?: MetricsResource;
  series: ChartSeries[];
  range: number;
  /** A value as the axis and the tooltip show it. */
  format: (n: number) => string;
  area?: boolean;
  peaks?: boolean;
  h?: number;
  /** What to say when there's nothing to show yet. */
  empty?: string;
}) {
  if (!data) return <Text size="sm" c="dimmed" h={h} pt="xl" ta="center">Loading…</Text>;
  const present = series.filter((s) => data.series[s.key]);
  const first = present.length ? data.series[present[0].key] : undefined;
  if (!first || !present.some((s) => data.series[s.key].avg.some((v) => v !== null))) {
    return <Text size="sm" c="dimmed" h={h} pt="xl" ta="center">{empty ?? 'Nothing recorded yet. OPF samples every 10 seconds.'}</Text>;
  }
  // A 10 s point is one sample: its peak is itself.
  const withPeaks = peaks && first.step > 10;
  const value = (k: string | undefined, i: number, which: 'avg' | 'max') => (k ? data.series[k]?.[which][i] ?? null : null);
  const rows = first.avg.map((_, i) => {
    const t = first.start + i * first.step;
    const row: Record<string, number | string | null> = { time: timeLabel(t, range) };
    for (const s of present) {
      const a = value(s.key, i, 'avg');
      const b = value(s.plus, i, 'avg');
      row[s.label] = a === null && b === null ? null : (a ?? 0) + (b ?? 0);
      if (withPeaks) {
        const pa = value(s.key, i, 'max');
        const pb = value(s.plus, i, 'max');
        // The sum of two peaks is at most the peak of the sum.
        row[`${s.label} peak`] = pa === null && pb === null ? null : (pa ?? 0) + (pb ?? 0);
      }
    }
    return row;
  });
  const chartSeries = present.flatMap((s) => [
    { name: s.label, color: s.color },
    ...(withPeaks ? [{ name: `${s.label} peak`, color: s.color, strokeDasharray: '3 3' }] : []),
  ]);
  const props = {
    h,
    data: rows,
    dataKey: 'time',
    series: chartSeries,
    curveType: 'monotone' as const,
    withDots: false,
    connectNulls: false,
    gridAxis: 'y' as const,
    tickLine: 'none' as const,
    valueFormatter: format,
    strokeWidth: 1.5,
    xAxisProps: { minTickGap: 48 },
    yAxisProps: { width: 88 },
    withLegend: false,
  };
  return (
    <>
      {area ? <AreaChart {...props} fillOpacity={withPeaks ? 0.12 : 0.25} /> : <LineChart {...props} />}
      {(present.length > 1 || withPeaks) && (
        // One entry a series; the peaks share a note rather than doubling it.
        <Group gap="md" justify="flex-end" mt={4}>
          {present.length > 1 && present.map((x) => (
            <Group key={x.key} gap={6}>
              <ColorSwatch color={`var(--mantine-color-${x.color.replace('.', '-')})`} size={10} withShadow={false} />
              <Text size="xs" c="dimmed">{x.label}</Text>
            </Group>
          ))}
          {withPeaks && <Text size="xs" c="dimmed">Dashed: the peak in each point</Text>}
        </Group>
      )}
    </>
  );
}

/** A small graph with its own range, for pages that show a number now. */
export function HistoryCard({ title, series, format, area, peaks, empty, h = 170 }: {
  title: string;
  series: ChartSeries[];
  format: (n: number) => string;
  area?: boolean;
  peaks?: boolean;
  empty?: string;
  h?: number;
}) {
  const [range, setRange] = useState(ranges[1].value);
  const { data } = useHistory(seriesKeys(series), Number(range));
  return (
    <>
      <SectionTitle right={<Group gap="sm"><SegmentedControl size="xs" value={range} onChange={setRange} data={ranges} /></Group>}>{title}</SectionTitle>
      <HistoryChart data={data} series={series} range={Number(range)} format={format} area={area} peaks={peaks} h={h} empty={empty} />
      <Anchor component={Link} to={`/diagnostics/graphs${range === '86400' ? '' : `?range=${range}`}`} size="xs" c="dimmed" mt={6} display="inline-block">More graphs</Anchor>
    </>
  );
}

/** A small, bare graph of an interface's traffic for a card: no axes, a tooltip, in and out. */
export function TrafficSpark({ data, dev, range, h = 56 }: { data?: MetricsResource; dev: string; range: number; h?: number }) {
  const rx = data?.series[`if.${dev}.rx`];
  const tx = data?.series[`if.${dev}.tx`];
  const first = rx ?? tx;
  if (!first || ![rx, tx].some((x) => x?.avg.some((v) => v !== null))) {
    return <Text size="xs" c="dimmed" h={h} ta="center" pt={h / 2 - 8}>{data ? 'No traffic recorded yet' : ''}</Text>;
  }
  const rows = first.avg.map((_, i) => ({
    time: timeLabel(first.start + i * first.step, range),
    In: rx?.avg[i] ?? null,
    Out: tx?.avg[i] ?? null,
  }));
  return (
    <AreaChart
      h={h}
      data={rows}
      dataKey="time"
      series={[{ name: 'In', color: 'harbor.6' }, { name: 'Out', color: 'amber.6' }]}
      curveType="monotone"
      withDots={false}
      connectNulls={false}
      withXAxis={false}
      withYAxis={false}
      gridAxis="none"
      strokeWidth={1.25}
      fillOpacity={0.2}
      valueFormatter={formatBits}
      tooltipAnimationDuration={0}
    />
  );
}
