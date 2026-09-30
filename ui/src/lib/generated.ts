// What the generators make of the model being edited, from the server
// (or, in the offline preview, the Go generators in the browser). Pages
// used to compute these with a TypeScript copy of the generators; now
// there's one implementation, internal/pf.
import { useEffect, useRef, useState } from 'react';
import type { Model } from '../model/types';
import { backend } from '../model/store';
import { call, GeneratorError } from '@wasmgen';
import { offline, type Derived, type PfLine, type RenderTarget, type Rendered } from './api';

// Where previews come from. Asking the server sends it the whole model,
// which for a small firewall is a few KB, less than the generators'
// WebAssembly (about 1.4 MB compressed, once, then cached). Past
// localAbove the model is the bigger cost on every edit, so the
// browser's copy of the same Go generators answers instead. If it can't
// load (an old browser, a policy), the server still does. What's
// applied is always generated and checked by the firewall itself.
const localAbove = 100_000; // bytes of model JSON, about 300 rules
let localBroken = false;

async function generate<T>(size: number, name: string, request: object, remote: () => Promise<T>): Promise<T> {
  if (offline || size <= localAbove || localBroken) return remote();
  try {
    return await call<T>(name, request);
  } catch (e) {
    // A generator's own error (a half-finished rule) is the answer; the
    // module failing to load isn't, so fall back and stop trying.
    if (e instanceof GeneratorError) throw e;
    localBroken = true;
    console.warn('generating previews on the firewall instead:', e);
    return remote();
  }
}

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
  return useGenerated(key, () => generate(key.length, 'derived', { model }, () => backend.pfDerived(model)));
}

/** The model's pf.conf, each line with where it came from. */
export function useRuleset(model: Model): Result<PfLine[]> {
  const key = 'ruleset ' + JSON.stringify(model);
  return useGenerated(key, () => generate(key.length, 'ruleset', { model }, () => backend.pfRuleset(model)));
}

/** One object's pf text, for a form's preview; asked for as typing pauses. */
export function useRendered(model: Model, target: RenderTarget | null): Result<Rendered> {
  const key = target ? 'render ' + JSON.stringify([model, target]) : null;
  return useGenerated(key, () => generate(key!.length, 'render', { model, ...target! }, () => backend.pfRender(model, target!)), 150);
}

/** A rendered object as text: the comment, then its rules. */
export const renderedText = (r?: Rendered) => (r ? [r.comment, ...r.lines].filter(Boolean).join('\n') : '');
