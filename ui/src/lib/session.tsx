// Who's signed in. The gate asks the server before anything else loads,
// shows the sign-in page until there's a session, and goes back to it
// when a request finds the session gone (timed out, signed out
// elsewhere, the firewall restarted). It also asks for the password
// again when a change needs it (withReauth).
import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from 'react';
import { Button, Center, Group, Loader, Modal, PasswordInput, Stack, Text } from '@mantine/core';
import { api, ApiError, offline, SIGNED_OUT_EVENT, type Role, type SessionResource } from './api';
import { localApi } from './localApi';
import { SignIn } from '../pages/SignIn';

// Not model/store's backend: the store needs this module.
const backend = offline ? localApi : api;

interface SessionContext {
  /** The server has accounts; without them (the mock) anyone can do anything. */
  accounts: boolean;
  session?: SessionResource['session'];
  signOut: () => Promise<void>;
  /** Runs fn, and if the server wants the password again, asks for it and runs it once more. */
  withReauth: <T>(fn: () => Promise<T>) => Promise<T>;
}

const Ctx = createContext<SessionContext>({ accounts: false, signOut: async () => {}, withReauth: (fn) => fn() });

export const useSession = () => useContext(Ctx);

/** What the signed-in person may do; without accounts, anything. */
export function useRole() {
  const { accounts, session } = useSession();
  const role: Role = !accounts ? 'admin' : session?.role ?? 'view';
  return { role, canEdit: role === 'admin', canOperate: role === 'admin' || role === 'operator' };
}

export function SessionGate({ children }: { children: ReactNode }) {
  const [state, setState] = useState<SessionResource | null>(null);
  const [failed, setFailed] = useState<string>();
  const [asking, setAsking] = useState(false);
  const [password, setPassword] = useState('');
  const [reauthError, setReauthError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const pending = useRef<{ resolve: () => void; reject: (e: unknown) => void } | null>(null);
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
  const withReauth = useCallback(async <T,>(fn: () => Promise<T>): Promise<T> => {
    try {
      return await fn();
    } catch (e) {
      if (!(e instanceof ApiError && e.code === 'reauth_required')) throw e;
      await new Promise<void>((resolve, reject) => {
        pending.current = { resolve, reject };
        setPassword('');
        setReauthError(undefined);
        setAsking(true);
      });
      return fn();
    }
  }, []);
  const cancel = () => {
    setAsking(false);
    pending.current?.reject(new ApiError(403, 'reauth_required', 'Not done: your password is needed for this.'));
    pending.current = null;
  };
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      await backend.reauth(password);
      setAsking(false);
      pending.current?.resolve();
      pending.current = null;
    } catch (err) {
      setReauthError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  if (!state) {
    return failed ? <SignIn unreachable={failed} onRetry={() => { setFailed(undefined); load(); }} /> : <Center h="100vh"><Loader /></Center>;
  }
  if (state.accounts && !state.session) {
    return <SignIn tls={state.tls} onSignedIn={(s) => setState(s)} />;
  }
  return (
    <Ctx.Provider value={{ accounts: state.accounts, session: state.session, signOut, withReauth }}>
      {children}
      <Modal opened={asking} onClose={cancel} title={<Text fw={600}>Your password, again</Text>}>
        <form onSubmit={submit}>
          <Stack>
            <Text size="sm" c="dimmed">Changes to who can sign in ask for your password once more. It lasts five minutes.</Text>
            <PasswordInput label="Password" autoComplete="current-password" data-autofocus value={password} onChange={(e) => setPassword(e.currentTarget.value)} error={reauthError} />
            <Group justify="flex-end">
              <Button variant="default" onClick={cancel}>Cancel</Button>
              <Button type="submit" loading={busy} disabled={!password}>Continue</Button>
            </Group>
          </Stack>
        </form>
      </Modal>
    </Ctx.Provider>
  );
}
