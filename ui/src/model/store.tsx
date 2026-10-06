// The UI's view of the configuration. The server owns it: edits change a
// local copy of the model; reviewing stages that copy on the server,
// which validates it and says which files it changes; applying commits
// it; the server decides whether the commit needs confirmation and
// reverts it when the deadline passes.
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { Alert, Button, Center, Loader, Stack, Text } from '@mantine/core';
import { notifications } from '@mantine/notifications';
import type { Change, HistoryEntry, Model, Section } from './types';
import { sectionLabel } from '../lib/sections';
import { api, offline, type ChangeNote, type CommitResource, type FileChange } from '../lib/api';
import { localApi } from '../lib/localApi';
import { useRole } from '../lib/session';
import { moving, type Move } from '../lib/moving';

// The server, or the preview build's in-browser stand-in.
export const backend = offline ? localApi : api;

const sectionOf: Record<Section, (m: Model) => unknown> = {
  system: (m) => m.system,
  // A tunnel's peers are on its interface, but they're WireGuard
  // settings, not the interface's.
  interfaces: (m) => m.interfaces.map(({ wireguard: _wg, ...i }) => i),
  routing: (m) => m.routing,
  firewall: (m) => m.firewall,
  dhcp: (m) => m.dhcp,
  dns: (m) => m.dns,
  wireguard: (m) => m.interfaces.filter((i) => i.wireguard).map((i) => [i.id, i.wireguard]),
  notifications: (m) => m.notifications ?? null,
};

export function changedSections(a: Model, b: Model): Section[] {
  return (Object.keys(sectionOf) as Section[]).filter(
    (s) => JSON.stringify(sectionOf[s](a)) !== JSON.stringify(sectionOf[s](b)),
  );
}

// What the server staged, for review before committing.
export interface Review {
  version: string;
  files: FileChange[];
  needsConfirm: boolean;
}

// A commit waiting for confirmation. start and deadline are the
// server's; the dialog counts down between them.
export interface Confirming {
  id: string;
  start: number;
  deadline: number;
  /** The commit moved the address this page is on (known only to the
   *  browser that applied it). */
  move?: Move;
}

interface Store {
  applied: Model;
  staged: Model;
  changes: Change[];
  pendingSections: Section[];
  history: HistoryEntry[];
  confirming: Confirming | null;
  /** The running OpenBSD release, once known. */
  release?: string;
  edit: (section: Section, summary: string, fn: (m: Model) => Model) => void;
  discard: () => Promise<void>;
  review: (overwrite?: string[]) => Promise<Review>;
  apply: (review: Review) => Promise<CommitResource>;
  keep: () => Promise<void>;
  revert: () => Promise<void>;
  restore: (entry: HistoryEntry) => Promise<void>;
}

const StoreContext = createContext<Store | null>(null);

let nextChangeId = 100;

const sections = new Set<string>(Object.keys(sectionOf));

function historyOf(c: CommitResource): HistoryEntry {
  return {
    id: c.id,
    time: Date.parse(c.time),
    status: c.status,
    message: c.message,
    author: c.author,
    changes: c.changes.map((n, i) => ({ id: -1 - i, section: (sections.has(n.area) ? n.area : 'system') as Section, summary: n.summary })),
  };
}

function confirmingOf(c: CommitResource): Confirming {
  return { id: c.id, start: Date.parse(c.time), deadline: Date.parse(c.deadline ?? c.time) };
}

// The server limits commit descriptions; stay inside them.
function clip(s: string, maxBytes: number): string {
  const enc = new TextEncoder();
  let out = s.replace(/\p{Cc}/gu, ' ');
  while (enc.encode(out).length > maxBytes) out = out.slice(0, -1);
  return out;
}

function describe(changes: Change[]): { message: string; notes: ChangeNote[] } {
  const notes = changes.slice(0, 500).map((c) => ({ area: c.section, summary: clip(c.summary, 300) }));
  const areas = [...new Set(changes.map((c) => sectionLabel[c.section].toLowerCase()))];
  const message = changes.length === 1 ? changes[0].summary : `${changes.length} changes to ${areas.join(', ')}`;
  return { message: clip(message, 500), notes };
}

function errorMessage(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

export function StoreProvider({ children }: { children: ReactNode }) {
  const [loaded, setLoaded] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [applied, setApplied] = useState<Model | null>(null);
  const [liveVersion, setLiveVersion] = useState('');
  const [staged, setStaged] = useState<Model | null>(null);
  const [log, setLog] = useState<Change[]>([]);
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [confirming, setConfirming] = useState<Confirming | null>(null);
  const [release, setRelease] = useState<string>();
  const confirmingRef = useRef(confirming);
  confirmingRef.current = confirming;
  const { canEdit } = useRole();
  const canEditRef = useRef(canEdit);
  canEditRef.current = canEdit;
  // The latest models, for edits made before the next render.
  const stagedRef = useRef(staged);
  stagedRef.current = staged;
  const appliedRef = useRef(applied);
  appliedRef.current = applied;

  const refreshHistory = useCallback(async () => {
    setHistory((await backend.commits()).map(historyOf));
  }, []);

  // Reload the live model; without keepEdits it's also the new starting
  // point for edits.
  const refreshLive = useCallback(async (keepEdits: boolean) => {
    const live = await backend.live();
    setApplied(live.model);
    setLiveVersion(live.version);
    if (!keepEdits) {
      setStaged(live.model);
      setLog([]);
    }
  }, []);

  const load = useCallback(async () => {
    setLoadError(null);
    try {
      const [live, st, status] = await Promise.all([backend.live(), backend.staged(), backend.status()]);
      setApplied(live.model);
      setLiveVersion(live.version);
      // Something staged by an earlier session: we have its model but
      // not the edits, so changes are listed by section.
      setStaged(st ? st.model : live.model);
      setLog([]);
      setConfirming(status.pending ? confirmingOf(status.pending) : null);
      setRelease(status.release);
      await refreshHistory();
      setLoaded(true);
    } catch (e) {
      setLoadError(errorMessage(e));
    }
  }, [refreshHistory]);

  useEffect(() => {
    load();
  }, [load]);

  const pendingSections = useMemo(() => (applied && staged ? changedSections(applied, staged) : []), [applied, staged]);

  const changes = useMemo(() => {
    const out = log.filter((c) => pendingSections.includes(c.section));
    for (const s of pendingSections) {
      if (!out.some((c) => c.section === s)) {
        out.push({ id: -1, section: s, summary: `Changed ${sectionLabel[s].toLowerCase()} settings` });
      }
    }
    return out;
  }, [log, pendingSections]);

  const edit = useCallback((section: Section, summary: string, fn: (m: Model) => Model) => {
    if (!canEditRef.current) {
      notifications.show({
        color: 'gray',
        title: 'Read-only',
        message: 'Your role can look, but changing the configuration needs an admin (_opfadmin).',
      });
      return;
    }
    if (confirmingRef.current) {
      notifications.show({
        color: 'yellow',
        title: 'Waiting for confirmation',
        message: 'Keep or revert the changes you just applied before making new ones.',
      });
      return;
    }
    const before = stagedRef.current;
    if (!before) return;
    const after = fn(before);
    stagedRef.current = after;
    setStaged(after);
    // Edits that end where the section was before cancel out, so
    // turning something on and off again isn't listed as two changes:
    // back to what's applied drops the section's edits, and back to
    // how an earlier edit left it drops the ones since.
    const now = JSON.stringify(sectionOf[section](after));
    const live = appliedRef.current;
    setLog((l) => {
      if (live && now === JSON.stringify(sectionOf[section](live))) return l.filter((c) => c.section !== section);
      let i = l.length - 1;
      while (i >= 0 && !(l[i].section === section && l[i].after === now)) i--;
      if (i >= 0) return l.filter((c, j) => j <= i || c.section !== section);
      return [...l, { id: nextChangeId++, section, summary, after: now }];
    });
  }, []);

  const discard = useCallback(async () => {
    await backend.discard();
    setStaged(applied);
    setLog([]);
  }, [applied]);

  const review = useCallback(async (overwrite?: string[]): Promise<Review> => {
    if (!staged) throw new Error('not loaded');
    const st = await backend.stage(liveVersion, staged, overwrite);
    return { version: st.version, files: st.changes, needsConfirm: st.changes.some((c) => c.needsConfirm) };
  }, [staged, liveVersion]);

  const apply = useCallback(async (r: Review) => {
    const { message, notes } = describe(changes);
    const move = applied && staged ? moving(applied, staged, window.location) ?? undefined : undefined;
    const c = await backend.createCommit(r.version, message, notes);
    await refreshHistory();
    switch (c.status) {
      case 'pending':
        await refreshLive(true);
        setConfirming({ ...confirmingOf(c), move });
        break;
      case 'failed':
        notifications.show({
          color: 'red', autoClose: false, title: 'The changes couldn’t be applied',
          message: 'Everything was put back as it was, and your changes are still pending. The commit’s log in Change history says what failed.',
        });
        break;
      default:
        await refreshLive(false);
        notifications.show({ color: 'teal', title: 'Changes applied', message: `${changes.length} change${changes.length === 1 ? '' : 's'} now active.` });
    }
    return c;
  }, [changes, applied, staged, refreshHistory, refreshLive]);

  // The server reverts on its own when the deadline passes; find out.
  const pollOnce = useCallback(async () => {
    const c = confirmingRef.current;
    if (!c) return;
    try {
      const st = await backend.status();
      if (st.pending?.id === c.id) return;
      setConfirming(null);
      const d = await backend.commit(c.id);
      if (d.status === 'reverted') {
        notifications.show({
          color: 'red', autoClose: false, title: 'Changes reverted automatically',
          message: 'They weren’t confirmed in time, so the previous configuration was restored. Your edits are still pending if you want to fix them and try again.',
        });
        await refreshLive(true);
      } else {
        await refreshLive(false);
      }
      await refreshHistory();
    } catch {
      // Unreachable, perhaps because of the change being confirmed. The
      // server reverts regardless; keep polling.
    }
  }, [refreshHistory, refreshLive]);

  useEffect(() => {
    if (!confirming) return;
    const t = setInterval(pollOnce, 2000);
    return () => clearInterval(t);
  }, [confirming, pollOnce]);

  const keep = useCallback(async () => {
    const c = confirmingRef.current;
    if (!c) return;
    try {
      await backend.confirm(c.id);
      notifications.show({ color: 'teal', title: 'Changes kept', message: 'Your new configuration is saved and will survive a restart.' });
      setConfirming(null);
      await refreshLive(false);
      await refreshHistory();
    } catch (e) {
      // Most likely it was reverted a moment ago; the poll reports it.
      notifications.show({ color: 'red', title: 'Couldn’t keep the changes', message: errorMessage(e) });
      await pollOnce();
    }
  }, [pollOnce, refreshHistory, refreshLive]);

  const revert = useCallback(async () => {
    const c = confirmingRef.current;
    if (!c) return;
    try {
      await backend.revert(c.id);
      notifications.show({ title: 'Changes reverted', message: 'The previous configuration is active again. Your edits are still pending.' });
      setConfirming(null);
      await refreshLive(true);
      await refreshHistory();
    } catch (e) {
      notifications.show({ color: 'red', title: 'Couldn’t revert', message: errorMessage(e) });
      await pollOnce();
    }
  }, [pollOnce, refreshHistory, refreshLive]);

  const restore = useCallback(async (entry: HistoryEntry) => {
    if (confirmingRef.current || !applied) return;
    try {
      // Loaded as edits: reviewing stages it, and deals with anything the
      // server objects to, like any other change. It replaces any edits,
      // so it's described afresh.
      const old = await backend.commitConfig(entry.id, 'before');
      const when = new Date(entry.time).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' });
      setStaged(old.model);
      setLog(changedSections(applied, old.model).map((section) => ({
        id: nextChangeId++, section, summary: `Restored ${sectionLabel[section].toLowerCase()} settings from before ${when}`,
      })));
      notifications.show({ title: 'Restore ready to review', message: 'Review and apply the pending changes to finish restoring.' });
    } catch (e) {
      notifications.show({ color: 'red', title: 'Couldn’t restore', message: errorMessage(e) });
    }
  }, [applied]);

  if (!loaded || !applied || !staged) {
    return (
      <Center h="100vh">
        {loadError ? (
          <Stack align="center" maw={420}>
            <Alert color="red" title="Can’t reach OPF">
              <Text size="sm">{loadError}</Text>
            </Alert>
            <Button onClick={load}>Try again</Button>
          </Stack>
        ) : (
          <Loader />
        )}
      </Center>
    );
  }

  editing = staged;
  const value: Store = {
    applied, staged, changes, pendingSections, history, confirming, release,
    edit, discard, review, apply, keep, revert, restore,
  };
  return <StoreContext.Provider value={value}>{children}</StoreContext.Provider>;
}

export function useStore(): Store {
  const s = useContext(StoreContext);
  if (!s) throw new Error('useStore outside StoreProvider');
  return s;
}

// The model being edited, for newId. Set on every render of the store.
let editing: Model | null = null;
// The last number newId gave out for each prefix, so several ids made
// before the model is updated (a peer and its routes, say) differ.
const issued = new Map<string, number>();

// Every string id anywhere in a model.
function eachId(v: unknown, f: (id: string) => void) {
  if (Array.isArray(v)) {
    for (const x of v) eachId(x, f);
  } else if (v && typeof v === 'object') {
    for (const [k, x] of Object.entries(v)) {
      if (k === 'id' && typeof x === 'string') f(x);
      else eachId(x, f);
    }
  }
}

/**
 * An id for a new object: the prefix and the next number not used by
 * any id in the model being edited. Ids end up in pf labels and must be
 * unique, so a counter alone won't do: it restarts with every page load
 * while the model's ids persist.
 */
export function newId(prefix: string): string {
  const re = new RegExp(`^${prefix.replace(/[^A-Za-z0-9]/g, '\\$&')}(\\d{1,15})$`); // exact as a number
  let n = issued.get(prefix) ?? 0;
  eachId(editing, (id) => {
    const m = re.exec(id);
    if (m) n = Math.max(n, Number(m[1]));
  });
  issued.set(prefix, n + 1);
  return `${prefix}${n + 1}`;
}
