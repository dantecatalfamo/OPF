// Reverse DNS for the addresses a page shows, when its viewer turns
// names on: the firewall's own resolver looks them up (POST
// /api/dns/reverse), and this keeps the answers a few minutes so a page
// that refreshes asks only about addresses it hasn't seen.
import { useEffect, useMemo, useState } from 'react';
import { backend } from '../model/store';
import { usePref } from './prefs';

const KEEP_MS = 5 * 60_000;
const BATCH = 256; // the most the server takes at once

// name: "" for none; failed: the resolver couldn't say.
const cache = new Map<string, { name: string; failed: boolean; at: number }>();

/** The address in "1.2.3.4:443", "[2001:db8::1]:443", "2001:db8::1[443]" or a bare one. */
export function hostOf(s: string | undefined): string | undefined {
  if (!s) return undefined;
  let m = /^\[([0-9a-f:.]+)\](?::\d+)?$/i.exec(s) ?? /^([0-9a-f:.]+)\[\d+\]$/i.exec(s);
  if (m) return m[1];
  m = /^(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?$/.exec(s);
  if (m) return m[1];
  return /^[0-9a-f:]+$/i.test(s) && s.includes(':') ? s : undefined;
}

/** Whether to show names: one choice for every page that can. */
export const useShowNames = () => usePref('opf.reverseNames', false);

/** Names for the addresses (with or without ports) while on; an address
 *  without one is missing from the map. */
export function useReverseNames(addresses: (string | undefined)[], on: boolean): Map<string, string> {
  const hosts = useMemo(() => [...new Set(addresses.map(hostOf).filter((a): a is string => !!a))].sort(), [addresses]);
  const key = hosts.join(' ');
  const [, setVersion] = useState(0);
  useEffect(() => {
    if (!on) return;
    let live = true;
    const now = Date.now();
    const wanted = hosts.filter((h) => {
      const c = cache.get(h);
      return !c || now - c.at > (c.failed ? 30_000 : KEEP_MS);
    });
    (async () => {
      for (let i = 0; i < wanted.length && live; i += BATCH) {
        const part = wanted.slice(i, i + BATCH);
        try {
          const r = await backend.reverseNames(part);
          const at = Date.now();
          for (const [a, n] of Object.entries(r.names)) cache.set(a, { name: n, failed: false, at });
          for (const a of r.failed) cache.set(a, { name: '', failed: true, at });
        } catch {
          return; // shown without names; asked again on the next change
        }
        if (live) setVersion((v) => v + 1);
      }
    })();
    return () => { live = false; };
  }, [key, on]); // eslint-disable-line react-hooks/exhaustive-deps
  const out = new Map<string, string>();
  if (on) {
    for (const h of hosts) {
      const c = cache.get(h);
      if (c?.name) out.set(h, c.name);
    }
  }
  return out;
}
