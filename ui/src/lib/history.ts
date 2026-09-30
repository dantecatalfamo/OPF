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
// Each is precise enough that no two points of a range share a label,
// the first and the last included (a day's are 24 hours apart, a
// week's seven days), so an event's marker lands on its own point and
// the axis never merges two points.
const hms = new Intl.DateTimeFormat([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
const dayTime = new Intl.DateTimeFormat([], { weekday: 'short', hour: '2-digit', minute: '2-digit' });
const dateTime = new Intl.DateTimeFormat([], { weekday: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
const monthDayTime = new Intl.DateTimeFormat([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });

/** A point's time on a chart's axis, as fits the range. */
export function timeLabel(t: number, range: number): string {
  const f = range <= 3600 ? hms : range <= 86400 ? dayTime : range <= 7 * 86400 ? dateTime : monthDayTime;
  return f.format(t * 1000);
}

/** An event to mark on a graph. */
export interface Mark {
  time: number; // unix seconds
  label: string;
  warning?: boolean;
}

// The events graphs mark: things that explain a change in a line.
const markKinds = ['link', 'address', 'gateway', 'vpn', 'service'] as const;

/**
 * Events over the last range, for marking graphs; by subject (an
 * interface, gateway or VPN device id, a daemon) with those about
 * nothing in particular under ''.
 */
export function useEventMarks(range: number, enabled = true): Map<string, Mark[]> {
  const [marks, setMarks] = useState<Map<string, Mark[]>>(new Map());
  useEffect(() => {
    if (!enabled) return;
    let live = true;
    const load = () => {
      if (document.hidden) return;
      backend.events({ kinds: [...markKinds], limit: 500 }).then((r) => {
        if (!live) return;
        const from = Date.now() / 1000 - range;
        const by = new Map<string, Mark[]>();
        for (const e of r.events) {
          const t = Date.parse(e.time) / 1000;
          if (t < from) continue;
          const k = e.subject ?? '';
          by.set(k, [...(by.get(k) ?? []), { time: t, label: e.message, warning: e.warning }]);
        }
        setMarks(by);
      }, () => {});
    };
    load();
    const t = setInterval(load, 60_000);
    return () => { live = false; clearInterval(t); };
  }, [range, enabled]);
  return marks;
}
