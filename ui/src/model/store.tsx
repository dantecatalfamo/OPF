// Client-side stand-in for the appliance's staging API. Edits change the
// staged model; Apply makes it live; risky changes must be confirmed or
// they are reverted, exactly like the Go backend.
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { notifications } from '@mantine/notifications';
import type { Change, HistoryEntry, Model, Section } from './types';
import { sampleHistory, sampleModel } from './sample';
import { sectionLabel } from '../lib/sections';

export const CONFIRM_SECONDS = 60;

// Changes to these can cut off access to the appliance itself.
const riskySections: Section[] = ['interfaces', 'firewall'];

const sectionOf: Record<Section, (m: Model) => unknown> = {
  system: (m) => m.system,
  interfaces: (m) => m.interfaces,
  firewall: (m) => m.firewall,
  dhcp: (m) => m.dhcp,
  dns: (m) => m.dns,
  wireguard: (m) => m.wireguard,
};

export function changedSections(a: Model, b: Model): Section[] {
  return (Object.keys(sectionOf) as Section[]).filter(
    (s) => JSON.stringify(sectionOf[s](a)) !== JSON.stringify(sectionOf[s](b)),
  );
}

interface PendingCommit {
  deadline: number;
  before: Model;
  after: Model;
  changes: Change[];
}

interface Store {
  applied: Model;
  staged: Model;
  changes: Change[];
  pendingSections: Section[];
  history: HistoryEntry[];
  confirming: PendingCommit | null;
  edit: (section: Section, summary: string, fn: (m: Model) => Model) => void;
  discard: () => void;
  apply: () => void;
  keep: () => void;
  revert: (why: 'user' | 'timeout') => void;
  restore: (entry: HistoryEntry) => void;
  needsConfirm: boolean;
}

const StoreContext = createContext<Store | null>(null);

let nextChangeId = 100;

function historyId(t: number) {
  const d = new Date(t);
  const p = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`;
}

export function StoreProvider({ children }: { children: ReactNode }) {
  const [applied, setApplied] = useState<Model>(sampleModel);
  const [staged, setStaged] = useState<Model>(sampleModel);
  const [log, setLog] = useState<Change[]>([]);
  const [history, setHistory] = useState<HistoryEntry[]>(() => sampleHistory(Date.now()));
  const [confirming, setConfirming] = useState<PendingCommit | null>(null);
  const confirmingRef = useRef(confirming);
  confirmingRef.current = confirming;

  const pendingSections = useMemo(() => changedSections(applied, staged), [applied, staged]);

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
    if (confirmingRef.current) {
      notifications.show({
        color: 'yellow',
        title: 'Waiting for confirmation',
        message: 'Keep or revert the changes you just applied before making new ones.',
      });
      return;
    }
    setStaged((m) => fn(m));
    setLog((l) => [...l, { id: nextChangeId++, section, summary }]);
  }, []);

  const discard = useCallback(() => {
    setStaged(applied);
    setLog([]);
  }, [applied]);

  const record = useCallback((c: PendingCommit, status: HistoryEntry['status']) => {
    const now = Date.now();
    setHistory((h) => [
      { id: historyId(now), time: now, user: 'admin', status, changes: c.changes, before: c.before, after: c.after },
      ...h,
    ]);
  }, []);

  const needsConfirm = pendingSections.some((s) => riskySections.includes(s));

  const apply = useCallback(() => {
    const commit: PendingCommit = {
      deadline: Date.now() + CONFIRM_SECONDS * 1000,
      before: applied,
      after: staged,
      changes,
    };
    if (needsConfirm) {
      setConfirming(commit);
      return;
    }
    setApplied(staged);
    setLog([]);
    record(commit, 'applied');
    notifications.show({ color: 'teal', title: 'Changes applied', message: `${changes.length} change${changes.length === 1 ? '' : 's'} now active.` });
  }, [applied, staged, changes, needsConfirm, record]);

  const keep = useCallback(() => {
    const c = confirmingRef.current;
    if (!c) return;
    setApplied(c.after);
    setLog([]);
    setConfirming(null);
    record(c, 'confirmed');
    notifications.show({ color: 'teal', title: 'Changes kept', message: 'Your new configuration is saved and will survive a restart.' });
  }, [record]);

  const revert = useCallback((why: 'user' | 'timeout') => {
    const c = confirmingRef.current;
    if (!c) return;
    setConfirming(null);
    record(c, 'reverted');
    notifications.show({
      color: why === 'timeout' ? 'red' : 'gray',
      autoClose: why === 'timeout' ? false : 5000,
      title: why === 'timeout' ? 'Changes reverted automatically' : 'Changes reverted',
      message: why === 'timeout'
        ? 'They weren’t confirmed in time, so the previous configuration was restored. Your edits are still pending if you want to fix them and try again.'
        : 'The previous configuration is active again. Your edits are still pending.',
    });
  }, [record]);

  useEffect(() => {
    if (!confirming) return;
    const t = setTimeout(() => revert('timeout'), confirming.deadline - Date.now());
    return () => clearTimeout(t);
  }, [confirming, revert]);

  const restore = useCallback((entry: HistoryEntry) => {
    const target = entry.before;
    const sections = changedSections(staged, target);
    if (sections.length === 0) {
      notifications.show({ title: 'Nothing to restore', message: 'That configuration is the same as the current one.' });
      return;
    }
    setStaged(target);
    const when = new Date(entry.time).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' });
    setLog((l) => [
      ...l,
      ...sections.map((s) => ({ id: nextChangeId++, section: s, summary: `Restored ${sectionLabel[s].toLowerCase()} settings from before ${when}` })),
    ]);
    notifications.show({ title: 'Restore staged', message: 'Review and apply the pending changes to finish restoring.' });
  }, [staged]);

  const value: Store = {
    applied, staged, changes, pendingSections, history, confirming,
    edit, discard, apply, keep, revert, restore, needsConfirm,
  };
  return <StoreContext.Provider value={value}>{children}</StoreContext.Provider>;
}

export function useStore(): Store {
  const s = useContext(StoreContext);
  if (!s) throw new Error('useStore outside StoreProvider');
  return s;
}

let idCounter = 1000;
export const newId = (prefix: string) => `${prefix}${idCounter++}`;
