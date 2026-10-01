// The sign-in page: OpenBSD accounts in OPF's groups (_opfadmin,
// _opfoperator, _opfview). The server never says which of the name or
// password was wrong.
import { useState } from 'react';
import { Alert, Button, Card, Center, Code, PasswordInput, Stack, Text, TextInput } from '@mantine/core';
import { Brand } from '../components/Brand';
import { backend } from '../model/store';
import { ApiError, type SessionResource } from '../lib/api';

export function SignIn({ tls, onSignedIn, unreachable, onRetry }: {
  tls?: string;
  onSignedIn?: (s: SessionResource) => void;
  unreachable?: string;
  onRetry?: () => void;
}) {
  const [user, setUser] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(undefined);
    try {
      onSignedIn?.(await backend.login(user, password));
    } catch (err) {
      setPassword('');
      setError(err instanceof ApiError && (err.code === 'unauthorized' || err.code === 'rate_limited') ? `${err.message[0].toUpperCase()}${err.message.slice(1)}.` : `Couldn’t sign in: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Center mih="100vh" p="md" style={{ background: 'var(--opf-bg)' }}>
      <Stack w="100%" maw={380} gap="lg">
        <Center><Brand /></Center>
        <Card p="xl">
          {unreachable ? (
            <Stack>
              <Text fw={600}>OPF isn’t answering</Text>
              <Text size="sm" c="dimmed">{unreachable}</Text>
              <Button onClick={onRetry}>Try again</Button>
            </Stack>
          ) : (
            <form onSubmit={submit}>
              <Stack>
                <Text fw={600} size="lg">Sign in</Text>
                <TextInput label="Name" autoComplete="username" autoCapitalize="none" spellCheck={false} data-autofocus autoFocus value={user} onChange={(e) => setUser(e.currentTarget.value)} />
                <PasswordInput label="Password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.currentTarget.value)} />
                {error && <Alert color="red" variant="light" p="sm">{error}</Alert>}
                <Button type="submit" loading={busy} disabled={!user || !password}>Sign in</Button>
                <Text size="xs" c="dimmed">
                  With your account on this OpenBSD system. It needs to be in _opfadmin, _opfoperator or _opfview.
                </Text>
              </Stack>
            </form>
          )}
        </Card>
        {tls && (
          <Text size="xs" c="dimmed" ta="center">
            This connection’s certificate, to compare with the one OPF logged when it started:
            <Code block mt={4} style={{ fontSize: 10, overflowWrap: 'anywhere', whiteSpace: 'normal' }}>{tls}</Code>
          </Text>
        )}
      </Stack>
    </Center>
  );
}
