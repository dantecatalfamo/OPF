// A graph of series from the collector over a range: one line or
// area each, gaps where nothing was recorded (OPF wasn't running, or
// the internet was down and nothing answered). With peaks, each
// series also gets a dashed line of the highest sample in each point,
// once a point is more than one sample: an hour's average hides a
// burst that filled the link.
import { useState } from 'react';
import { AreaChart, LineChart } from '@mantine/charts';
import { Anchor, ColorSwatch, Group, SegmentedControl, Stack, Text } from '@mantine/core';
import { Link } from 'react-router';
import type { MetricsResource } from '../lib/api';
import { ranges, timeLabel, useEventMarks, useHistory, type Mark } from '../lib/history';
import { formatLogTime } from '../lib/format';
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

export function HistoryChart({ data, series, range, format, area, peaks, h = 200, empty, marks }: {
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
  /** Events to mark: a line where each happened, and what it was below. */
  marks?: Mark[];
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
  // An event's line goes on the point it happened in.
  const end = first.start + first.step * first.avg.length;
  const shown = (marks ?? []).filter((m) => m.time >= first.start && m.time < end).sort((a, b) => b.time - a.time);
  const referenceLines = shown.map((m) => ({
    x: rows[Math.min(rows.length - 1, Math.floor((m.time - first.start) / first.step))].time as string,
    color: m.warning ? 'red.6' : 'gray.5',
    strokeDasharray: '4 3',
  }));
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
    // Labels are unique per range (timeLabel); saying so lets an event's
    // line find its point on the axis.
    xAxisProps: { minTickGap: 48, allowDuplicatedCategory: false },
    yAxisProps: { width: 88 },
    withLegend: false,
    referenceLines,
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
      {shown.length > 0 && (
        // What the lines mark, newest first; the Events page has the rest.
        <Stack gap={0} mt={4}>
          {shown.slice(0, 3).map((m) => (
            <Text key={`${m.time}-${m.label}`} size="xs" c={m.warning ? 'red' : 'dimmed'} lineClamp={1}>
              {formatLogTime(new Date(m.time * 1000).toISOString())} · {m.label}
            </Text>
          ))}
          {shown.length > 3 && (
            <Anchor component={Link} to="/diagnostics/events" size="xs" c="dimmed">and {shown.length - 3} more</Anchor>
          )}
        </Stack>
      )}
    </>
  );
}

/** A small graph with its own range, for pages that show a number now. */
export function HistoryCard({ title, series, format, area, peaks, empty, h = 170, markSubjects }: {
  title: string;
  series: ChartSeries[];
  format: (n: number) => string;
  area?: boolean;
  peaks?: boolean;
  empty?: string;
  h?: number;
  /** Whose events to mark: interface, gateway or VPN device ids, daemons. */
  markSubjects?: string[];
}) {
  const [range, setRange] = useState(ranges[1].value);
  const { data } = useHistory(seriesKeys(series), Number(range));
  const allMarks = useEventMarks(Number(range), !!markSubjects?.length);
  const marks = (markSubjects ?? []).flatMap((s) => allMarks.get(s) ?? []);
  return (
    <>
      <SectionTitle right={<Group gap="sm"><SegmentedControl size="xs" value={range} onChange={setRange} data={ranges} /></Group>}>{title}</SectionTitle>
      <HistoryChart data={data} series={series} range={Number(range)} format={format} area={area} peaks={peaks} h={h} empty={empty} marks={marks} />
      <Anchor component={Link} to={`/diagnostics/graphs${range === '86400' ? '' : `?range=${range}`}`} size="xs" c="dimmed" mt={6} display="inline-block">More graphs</Anchor>
    </>
  );
}

/**
 * A small, bare graph of an interface's traffic for a card: no axes, a
 * tooltip, in and out. The card has to let it overflow (so the tooltip
 * isn't cut off); the drawing itself is clipped to the card's corners
 * by the class spark-bottom.
 */
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
      // Above the graph, over the card's own text, rather than hanging
      // off the bottom over the next card.
      tooltipProps={{ position: { y: -h - 44 }, allowEscapeViewBox: { x: false, y: true }, wrapperStyle: { zIndex: 20 } }}
    />
  );
}

/**
 * A faint graph filling its parent (which must be position: relative),
 * for behind a number in a table cell: a rule's matches over time. No
 * tooltip; the number carries one.
 */
export function CellSpark({ data, k, color }: { data?: MetricsResource; k: string; color: string }) {
  const r = data?.series[k];
  if (!r || !r.avg.some((v) => v !== null && v > 0)) return null;
  const rows = r.avg.map((v, i) => ({ t: i, v }));
  return (
    // The lower part of the cell, faint, so the number above stays readable.
    <div aria-hidden style={{ position: 'absolute', inset: '52% 0 3px 0', opacity: 0.45, pointerEvents: 'none' }}>
      <AreaChart
        h="100%"
        data={rows}
        dataKey="t"
        series={[{ name: 'v', color }]}
        curveType="monotone"
        withDots={false}
        connectNulls={false}
        withXAxis={false}
        withYAxis={false}
        withTooltip={false}
        gridAxis="none"
        strokeWidth={1}
        fillOpacity={0.35}
      />
    </div>
  );
}
