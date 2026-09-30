// What the generators make of the model being edited, from the server
// (or, in the offline preview, the Go generators in the browser). Pages
// used to compute these with a TypeScript copy of the generators; now
// there's one implementation, internal/pf.
import { useEffect, useRef, useState } from 'react';
import type { Model } from '../model/types';
import { backend } from '../model/store';
import type { Derived, PfLine, RenderTarget, Rendered } from './api';

// Several parts of a page ask for the same thing about the same model;
// share one request. Only the latest few are kept.
const cache = new Map<string, Promise<unknown>>();

function cached<T>(key: string, load: () => Promise<T>): Promise<T> {
  let p = cache.get(key) as Promise<T> | undefined;
  if (!p) {
    p = load();
    cache.set(key, p);
    p.catch(() => cache.delete(key)); // don't keep failures
    while (cache.size > 16) cache.delete(cache.keys().next().value!);
  }
  return p;
}

interface Result<T> {
  data?: T; // the last good answer, kept while a new one loads
  error?: string;
}

// Loads key's value, latest request wins, keeping the last answer while
// the next one arrives so the page doesn't flicker. debounce delays asking
// while someone is typing.
function useGenerated<T>(key: string | null, load: () => Promise<T>, debounce = 0): Result<T> {
  const [res, setRes] = useState<Result<T>>({});
  const seq = useRef(0);
  useEffect(() => {
    if (key === null) return;
    const n = ++seq.current;
    const t = setTimeout(() => {
      cached(key, load).then(
        (data) => n === seq.current && setRes({ data }),
        (e) => n === seq.current && setRes((r) => ({ data: r.data, error: e instanceof Error ? e.message : String(e) })),
      );
    }, debounce);
    return () => clearTimeout(t);
  }, [key]); // load is derived from key
  return res;
}

/** Automatic NAT, local networks, each rule's text: see Derived. */
export function useDerived(model: Model): Result<Derived> {
  const key = 'derived ' + JSON.stringify(model);
  return useGenerated(key, () => backend.pfDerived(model));
}

/** The model's pf.conf, each line with where it came from. */
export function useRuleset(model: Model): Result<PfLine[]> {
  const key = 'ruleset ' + JSON.stringify(model);
  return useGenerated(key, () => backend.pfRuleset(model));
}

/** One object's pf text, for a form's preview; asked for as typing pauses. */
export function useRendered(model: Model, target: RenderTarget | null): Result<Rendered> {
  const key = target ? 'render ' + JSON.stringify([model, target]) : null;
  return useGenerated(key, () => backend.pfRender(model, target!), 150);
}

/** A rendered object as text: the comment, then its rules. */
export const renderedText = (r?: Rendered) => (r ? [r.comment, ...r.lines].filter(Boolean).join('\n') : '');
