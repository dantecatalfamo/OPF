// Whether OPF only monitors this machine (read-only mode), from
// GET /api/status, read once after signing in: the server keeps the
// mode until OPF is restarted. useRole reads it, so no page offers a
// change the server would refuse.
import { createContext, useContext, useEffect, useState, type ReactNode } from 'react';
import { api, offline } from './api';
import { localApi } from './localApi';

const backend = offline ? localApi : api;

export interface Mode {
  /** OPF only watches this machine and changes nothing on it. */
  readOnly: boolean;
  /** OPF has a configuration of its own, from before it was made read-only. */
  managed: boolean;
}

const ModeContext = createContext<Mode>({ readOnly: false, managed: true });

export const useMode = () => useContext(ModeContext);

/** Provides the mode, rendering nothing until it's known so a read-only
 *  page never shows a change it can't make. */
export function ModeProvider({ children }: { children: ReactNode }) {
  const [mode, setMode] = useState<Mode>();
  useEffect(() => {
    backend.status().then(
      (s) => setMode({ readOnly: !!s.readOnly, managed: s.managed ?? true }),
      // The store reports what's wrong; until then, assume nothing.
      () => setMode({ readOnly: false, managed: true }),
    );
  }, []);
  if (!mode) return null;
  return <ModeContext.Provider value={mode}>{children}</ModeContext.Provider>;
}
