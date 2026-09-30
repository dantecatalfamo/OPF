// What loading DNS blocklists costs the resolver. Measured on OpenBSD
// 7.9 (unbound 1.26.1): Hagezi Pro and OISD small, 574,720 names, took
// unbound to 782 MB of memory, and 13.6 s passed before it answered
// after starting.
// Only estimates: names under one wildcard, and unbound's version,
// change them.
import type { DnsListStatus, ResolverReload } from './api';
import type { Model } from '../model/types';

export const bytesPerName = 1400;
const secondsPerName = 13.6 / 575_000;

export const estimateBytes = (names: number) => names * bytesPerName;

/** How long a full reload with this many names takes: scaled from the last one measured when it had enough names to tell, else the estimate. */
export function reloadSeconds(names: number, last?: ResolverReload): number {
  if (last && !last.timedOut && last.names >= 50_000) return (last.seconds * names) / last.names;
  return names * secondsPerName;
}

/** The names a model's enabled lists and own entries load, and whether some lists aren't downloaded yet (so it's more). */
export function modelNames(m: Model, status: DnsListStatus[] | undefined): { names: number; unknown: number } {
  let names = (m.dns.blocked ?? []).length + (m.dns.allowed ?? []).length;
  let unknown = 0;
  for (const l of m.dns.blocklists ?? []) {
    if (!l.enabled) continue;
    const s = status?.find((x) => x.id === l.id && x.fetched);
    if (s) names += s.blocked + s.allowed;
    else unknown++;
  }
  return { names, unknown };
}

/** How worrying a resolver's memory is next to the machine's: over a quarter is worth a note, over half a warning. */
export function memoryLevel(bytes: number, physmem: number | undefined): 'ok' | 'notice' | 'warn' {
  if (!physmem) return 'ok';
  const share = bytes / physmem;
  return share > 0.5 ? 'warn' : share > 0.25 ? 'notice' : 'ok';
}
