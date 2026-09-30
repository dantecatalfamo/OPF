// History from the collector (GET /api/metrics), for the graphs: a
// range to show and the series in it, asked for again while the page
// is open, more often for the last hour (10 s points) than for a month.
import { useEffect, useState } from 'react';
import { backend } from '../model/store';
import type { MetricsResource } from './api';

export const ranges = [
  { value: '3600', label: 'Hour' },
  { value: '86400', label: 'Day' },
  { value: '604800', label: 'Week' },
  { value: '2678400', label: 'Month' },
];

// About how many points a line gets, whatever the range: a chart is a
// few hundred pixels wide, and drawing a day at the firewall's finest
// (1,440 points a line, twice with peaks, on every chart) froze the
// Graphs page. The firewall merges its buckets exactly, so nothing is
// lost but detail finer than a pixel.
const POINTS = 300;

/** Series over the last range seconds, points at least step apart (enough for about POINTS a line, if not given). */
export function useHistory(series: string[], range: number, step?: number): { data?: MetricsResource; error?: string } {
  step = Math.max(step ?? 0, Math.ceil(range / POINTS));
  const [state, setState] = useState<{ data?: MetricsResource; error?: string }>({});
  const key = series.join(',');
  useEffect(() => {
    if (!series.length) return;
    let live = true;
    const load = () => {
      if (document.hidden) return;
      // The server takes 32 series a request.
      const chunks: string[][] = [];
      for (let i = 0; i < series.length; i += 32) chunks.push(series.slice(i, i + 32));
      Promise.all(chunks.map((c) => backend.metrics(c, range, step))).then(
        (all) => live && setState({ data: { series: Object.assign({}, ...all.map((d) => d.series)), known: all[0]?.known ?? [], groups: all[0]?.groups ?? [] } }),
        (e) => live && setState((s) => ({ data: s.data, error: e instanceof Error ? e.message : String(e) })),
      );
    };
    load();
    const t = setInterval(load, range <= 3600 ? 10_000 : 60_000);
    return () => { live = false; clearInterval(t); };
  }, [key, range, step]); // series is compared by its names
  return state;
}

// One formatter each: toLocale*String makes a new one on every call,
// which for every point of every chart is most of a render.
const hourMinute = new Intl.DateTimeFormat([], { hour: '2-digit', minute: '2-digit' });
const weekdayTime = new Intl.DateTimeFormat([], { weekday: 'short', hour: '2-digit', minute: '2-digit' });
const monthDay = new Intl.DateTimeFormat([], { month: 'short', day: 'numeric' });

/** A point's time on a chart's axis, as fits the range. */
export function timeLabel(t: number, range: number): string {
  const f = range <= 86400 ? hourMinute : range <= 7 * 86400 ? weekdayTime : monthDay;
  return f.format(t * 1000);
}
