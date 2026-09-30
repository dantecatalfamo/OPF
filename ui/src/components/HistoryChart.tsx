// A graph of series from the collector over a range: one line or
// area each, gaps where nothing was recorded (OPF wasn't running, or
// the internet was down and nothing answered).
import { AreaChart, LineChart } from '@mantine/charts';
import { Text } from '@mantine/core';
import type { MetricsResource } from '../lib/api';
import { timeLabel } from '../lib/history';

export interface ChartSeries {
  key: string;
  label: string;
  color: string;
}

export function HistoryChart({ data, series, range, format, area, h = 200, empty }: {
  data?: MetricsResource;
  series: ChartSeries[];
  range: number;
  /** A value as the axis and the tooltip show it. */
  format: (n: number) => string;
  area?: boolean;
  h?: number;
  /** What to say when there's nothing to show yet. */
  empty?: string;
}) {
  const present = series.filter((s) => data?.series[s.key]);
  if (!data) return <Text size="sm" c="dimmed" h={h} pt="xl" ta="center">Loading…</Text>;
  const first = present.length ? data.series[present[0].key] : undefined;
  if (!first || !present.some((s) => data.series[s.key].avg.some((v) => v !== null))) {
    return <Text size="sm" c="dimmed" h={h} pt="xl" ta="center">{empty ?? 'Nothing recorded yet. OPF samples every 10 seconds.'}</Text>;
  }
  const rows = first.avg.map((_, i) => {
    const t = first.start + i * first.step;
    const row: Record<string, number | string | null> = { time: timeLabel(t, range) };
    for (const s of present) row[s.label] = data.series[s.key].avg[i] ?? null;
    return row;
  });
  const props = {
    h,
    data: rows,
    dataKey: 'time',
    series: present.map((s) => ({ name: s.label, color: s.color })),
    curveType: 'monotone' as const,
    withDots: false,
    connectNulls: false,
    gridAxis: 'y' as const,
    tickLine: 'none' as const,
    valueFormatter: format,
    strokeWidth: 1.5,
    xAxisProps: { minTickGap: 48 },
    yAxisProps: { width: 88 },
    withLegend: present.length > 1,
    legendProps: { verticalAlign: 'bottom' as const, height: 28 },
  };
  return area ? <AreaChart {...props} fillOpacity={0.25} /> : <LineChart {...props} />;
}
