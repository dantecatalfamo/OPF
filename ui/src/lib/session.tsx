// Who's signed in. The gate asks the server before anything else loads,
// shows the sign-in page until there's a session, and goes back to it
// when a request finds the session gone (timed out, signed out
// elsewhere, the firewall restarted).
import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from 'react';
import { Center, Loader } from '@mantine/core';
import { backend } from '../model/store';
import { SIGNED_OUT_EVENT, type SessionResource } from './api';
import { SignIn } from '../pages/SignIn';

interface SessionContext {
  /** The server has accounts; without them (the mock) anyone can do anything. */
  accounts: boolean;
  session?: SessionResource['session'];
  signOut: () => Promise<void>;
}

const Ctx = createContext<SessionContext>({ accounts: false, signOut: async () => {} });

export const useSession = () => useContext(Ctx);

export function SessionGate({ children }: { children: ReactNode }) {
  const [state, setState] = useState<SessionResource | null>(null);
  const [failed, setFailed] = useState<string>();
  const load = useCallback(() => {
    backend.session().then(setState, (e) => setFailed(e instanceof Error ? e.message : String(e)));
  }, []);
  useEffect(load, [load]);
  useEffect(() => {
    const lost = () => setState((s) => (s?.accounts ? { ...s, session: undefined } : s));
    window.addEventListener(SIGNED_OUT_EVENT, lost);
    return () => window.removeEventListener(SIGNED_OUT_EVENT, lost);
  }, []);
  const signOut = useCallback(async () => {
    try {
      await backend.logout();
    } finally {
      setState((s) => (s ? { ...s, session: undefined } : s));
    }
  }, []);

  if (!state) {
    return failed ? <SignIn unreachable={failed} onRetry={() => { setFailed(undefined); load(); }} /> : <Center h="100vh"><Loader /></Center>;
  }
  if (state.accounts && !state.session) {
    return <SignIn tls={state.tls} onSignedIn={(s) => setState(s)} />;
  }
  return <Ctx.Provider value={{ accounts: state.accounts, session: state.session, signOut }}>{children}</Ctx.Provider>;
}
