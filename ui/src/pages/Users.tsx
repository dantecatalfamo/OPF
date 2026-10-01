// System › Users: who can sign in, for admins. The accounts are the
// system's own; OPF only changes membership of its three groups, makes
// and removes the accounts it created, sets passwords and locks. The
// changes happen at once, not through staging: they aren't the network
// configuration. Each asks for the admin's password again (withReauth).
import { useCallback, useEffect, useState } from 'react';
import { ActionIcon, Alert, Badge, Button, Card, Group, Menu, Modal, PasswordInput, Select, Stack, Switch, Table, Text, TextInput } from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { IconChevronDown, IconDots } from '@tabler/icons-react';
import { backend } from '../model/store';
import { ApiError, type Account, type Role, type SessionInfo, type UsersResource } from '../lib/api';
import { useRole, useSession } from '../lib/session';
import { formatAgo } from '../lib/format';
import { Mono, PageHeader, SectionTitle } from '../components/ui';

const roles: { value: Role; label: string; about: string }[] = [
  { value: 'admin', label: 'Admin', about: 'Changes everything, including who can sign in.' },
  { value: 'operator', label: 'Operator', about: 'Looks at everything, keeps or undoes a change someone applied, and runs tools.' },
  { value: 'view', label: 'Read-only', about: 'Looks at everything.' },
];
const roleName = (r: Role | '') => roles.find((x) => x.value === r)?.label ?? 'None';
const message = (e: unknown) => (e instanceof Error ? e.message : String(e));

export function Users() {
  const { canEdit } = useRole();
  const { session, withReauth } = useSession();
  const [data, setData] = useState<UsersResource>();
  const [sessions, setSessions] = useState<SessionInfo[]>([]);
  const [error, setError] = useState<string>();
  const [adding, setAdding] = useState<'new' | 'existing' | null>(null);
  const [password, setPassword] = useState<Account | null>(null);
  const load = useCallback(() => {
    backend.users().then((d) => { setData(d); setError(undefined); }, (e) => setError(message(e)));
    backend.sessions().then((s) => setSessions(s.sessions), () => {});
  }, []);
  useEffect(load, [load]);

  // Every change: asked for the password if need be, then the list again.
  const change = async (what: string, fn: () => Promise<unknown>) => {
    try {
      const r = await withReauth(fn);
      const note = (r as { note?: string } | undefined)?.note;
      notifications.show({ color: 'teal', message: note ?? what });
    } catch (e) {
      if (!(e instanceof ApiError && e.code === 'reauth_required')) notifications.show({ color: 'red', title: 'Not done', message: message(e) });
    }
    load();
  };

  if (!canEdit) {
    return (
      <>
        <PageHeader title="Users" description="Who can sign in to OPF." />
        <Alert color="gray" variant="light">Only admins can see and change who can sign in.</Alert>
      </>
    );
  }
  const me = session?.user;
  return (
    <>
      <PageHeader title="Users" description="Who can sign in to OPF: this OpenBSD system’s accounts in _opfadmin, _opfoperator or _opfview. Changes happen straight away." />
      {error && <Alert color="red" variant="light" mb="md">{error}</Alert>}
      <Stack gap="md">
        <Card>
          <SectionTitle
            right={
              <Menu position="bottom-end" withinPortal>
                <Menu.Target>
                  <Button size="xs" variant="light" rightSection={<IconChevronDown size={14} />}>Add</Button>
                </Menu.Target>
                <Menu.Dropdown>
                  <Menu.Item onClick={() => setAdding('new')}>New account</Menu.Item>
                  <Menu.Item onClick={() => setAdding('existing')} disabled={!data?.candidates.length}>A role for an existing account</Menu.Item>
                </Menu.Dropdown>
              </Menu>
            }
          >
            Who can sign in
          </SectionTitle>
          <Table.ScrollContainer minWidth={640}>
            <Table verticalSpacing={8}>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Name</Table.Th>
                  <Table.Th w={190}>Role</Table.Th>
                  <Table.Th>Can log in</Table.Th>
                  <Table.Th w={40} />
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {(data?.users ?? []).map((u) => (
                  <Table.Tr key={u.name}>
                    <Table.Td>
                      <Group gap={6}>
                        <Mono>{u.name}</Mono>
                        {u.name === me && <Badge size="xs" variant="light">you</Badge>}
                        {u.locked && <Badge size="xs" color="red" variant="light">locked</Badge>}
                        {u.noPassword && <Badge size="xs" color="gray" variant="light">no password</Badge>}
                        {u.expired && <Badge size="xs" color="yellow" variant="light">expired</Badge>}
                      </Group>
                      {u.fullName && <Text size="xs" c="dimmed">{u.fullName}</Text>}
                    </Table.Td>
                    <Table.Td>
                      <Select size="xs" data={roles.map((r) => ({ value: r.value, label: r.label }))} value={u.role || null} allowDeselect={false}
                        disabled={u.name === me} aria-label={`${u.name}'s role`}
                        onChange={(v) => v && v !== u.role && change(`${u.name} is now ${roleName(v as Role).toLowerCase()}`, () => backend.setUserRole(u.name, v as Role))} />
                    </Table.Td>
                    <Table.Td>
                      <Text size="sm" c="dimmed">{u.shell ? 'Here, over SSH and at the console' : 'Only here'}</Text>
                    </Table.Td>
                    <Table.Td>
                      <Menu position="bottom-end" withinPortal>
                        <Menu.Target>
                          <ActionIcon variant="subtle" color="gray" aria-label={`More for ${u.name}`}><IconDots size={16} /></ActionIcon>
                        </Menu.Target>
                        <Menu.Dropdown>
                          <Menu.Item onClick={() => setPassword(u)}>Set a password</Menu.Item>
                          <Menu.Item disabled={u.name === me} onClick={() => change(u.locked ? `Unlocked ${u.name}` : `Locked ${u.name}`, () => backend.lockUser(u.name, !u.locked))}>
                            {u.locked ? 'Unlock' : 'Lock'}
                          </Menu.Item>
                          <Menu.Divider />
                          <Menu.Item color="red" disabled={u.name === me}
                            onClick={() => change(u.created ? `Removed ${u.name}` : `Took away ${u.name}’s role`, () => (u.created ? backend.removeUser(u.name) : backend.setUserRole(u.name, '')))}>
                            {u.created ? 'Remove the account' : 'Take away the role'}
                          </Menu.Item>
                        </Menu.Dropdown>
                      </Menu>
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
          <Stack gap={4} mt="md">
            {roles.map((r) => (
              <Text key={r.value} size="xs" c="dimmed"><Text span fw={600} size="xs" c="var(--mantine-color-text)">{r.label}</Text>: {r.about}</Text>
            ))}
            <Text size="xs" c="dimmed">
              Removing an account OPF made deletes it; for one it didn’t, only the role goes. Nobody can take away their own admin role, and there’s always one admin left.
            </Text>
          </Stack>
        </Card>
        <Card>
          <SectionTitle>Signed in now</SectionTitle>
          <Table.ScrollContainer minWidth={520}>
            <Table verticalSpacing={6}>
              <Table.Thead>
                <Table.Tr><Table.Th>Who</Table.Th><Table.Th>From</Table.Th><Table.Th>Signed in</Table.Th><Table.Th>Last used</Table.Th><Table.Th w={80} /></Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {sessions.map((s) => (
                  <SessionRow key={s.id} s={s} mine={s.id === session?.id} onEnd={() => change(`Ended ${s.user}’s session`, () => backend.endSession(s.id))} />
                ))}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        </Card>
      </Stack>
      <NewAccountModal opened={adding === 'new'} onClose={() => setAdding(null)} onDone={(name, role) => { notifications.show({ color: 'teal', message: `Made ${name}, ${roleName(role).toLowerCase()}` }); load(); }} />
      <ExistingModal opened={adding === 'existing'} candidates={data?.candidates ?? []} onClose={() => setAdding(null)}
        onPick={(name, role) => change(`${name} is now ${roleName(role).toLowerCase()}`, () => backend.setUserRole(name, role))} />
      <PasswordModal account={password} onClose={() => setPassword(null)}
        onSet={(name, pw) => change(`Set ${name}’s password`, () => backend.setUserPassword(name, pw))} />
    </>
  );
}

export function SessionRow({ s, onEnd, mine }: { s: SessionInfo; onEnd: () => void; mine?: boolean }) {
  const now = Date.now();
  return (
    <Table.Tr>
      <Table.Td><Mono>{s.user}</Mono>{mine && <Text size="xs" c="dimmed">this one</Text>}</Table.Td>
      <Table.Td><Mono>{s.source}</Mono></Table.Td>
      <Table.Td><Text size="sm">{formatAgo((now - Date.parse(s.created)) / 1000)}</Text></Table.Td>
      <Table.Td><Text size="sm">{formatAgo((now - Date.parse(s.lastUsed)) / 1000)}</Text></Table.Td>
      <Table.Td>{!mine && <Button size="compact-xs" variant="subtle" color="red" onClick={onEnd}>End</Button>}</Table.Td>
    </Table.Tr>
  );
}

const passwordProblem = (p: string) => (p.length < 12 ? 'At least 12 characters' : p.length > 1024 ? 'At most 1024 characters' : null);

function NewAccountModal({ opened, onClose, onDone }: { opened: boolean; onClose: () => void; onDone: (name: string, role: Role) => void }) {
  const { withReauth } = useSession();
  const blank = { name: '', fullName: '', role: 'view' as Role, password: '', again: '', shell: false };
  const [v, setV] = useState(blank);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);
  useEffect(() => { if (opened) { setV(blank); setErrors({}); } }, [opened]); // eslint-disable-line react-hooks/exhaustive-deps
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    const errs: Record<string, string> = {};
    if (!/^[a-z][a-z0-9-]{0,30}$/.test(v.name)) errs.name = 'Lowercase letters, digits and hyphens, starting with a letter';
    if (/[:,]/.test(v.fullName)) errs.fullName = 'No : or ,';
    const p = passwordProblem(v.password);
    if (p) errs.password = p;
    if (v.again !== v.password) errs.again = 'The passwords don’t match';
    setErrors(errs);
    if (Object.keys(errs).length) return;
    setBusy(true);
    try {
      await withReauth(() => backend.createUser({ name: v.name, fullName: v.fullName, role: v.role, password: v.password, shell: v.shell }));
      onDone(v.name, v.role);
      onClose();
    } catch (err) {
      if (err instanceof ApiError && err.details.length) {
        setErrors(Object.fromEntries(err.details.map((d) => [d.path, d.message ?? ""])));
      } else if (!(err instanceof ApiError && err.code === 'reauth_required')) {
        setErrors({ name: message(err) });
      }
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal opened={opened} onClose={onClose} title={<Text fw={600}>New account</Text>}>
      <form onSubmit={submit}>
        <Stack>
          <Group grow align="flex-start">
            <TextInput label="Name" placeholder="carol" autoCapitalize="none" spellCheck={false} data-autofocus value={v.name} onChange={(e) => setV({ ...v, name: e.currentTarget.value })} error={errors.name} />
            <TextInput label="Full name" placeholder="Carol Chen" value={v.fullName} onChange={(e) => setV({ ...v, fullName: e.currentTarget.value })} error={errors.fullName} />
          </Group>
          <Select label="Role" data={roles.map((r) => ({ value: r.value, label: r.label }))} value={v.role} allowDeselect={false}
            description={roles.find((r) => r.value === v.role)?.about} inputWrapperOrder={['label', 'input', 'description', 'error']}
            onChange={(r) => r && setV({ ...v, role: r as Role })} />
          <Group grow align="flex-start">
            <PasswordInput label="Password" autoComplete="new-password" value={v.password} onChange={(e) => setV({ ...v, password: e.currentTarget.value })} error={errors.password} />
            <PasswordInput label="Again" autoComplete="new-password" value={v.again} onChange={(e) => setV({ ...v, again: e.currentTarget.value })} error={errors.again} />
          </Group>
          <Switch label="Can also log in over SSH and at the console" description="Off, the account only signs in here." checked={v.shell} onChange={(e) => setV({ ...v, shell: e.currentTarget.checked })} />
          <Group justify="flex-end" mt="sm">
            <Button variant="default" onClick={onClose}>Cancel</Button>
            <Button type="submit" loading={busy}>Make the account</Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}

function ExistingModal({ opened, candidates, onClose, onPick }: { opened: boolean; candidates: Account[]; onClose: () => void; onPick: (name: string, role: Role) => void }) {
  const [name, setName] = useState<string | null>(null);
  const [role, setRole] = useState<Role>('view');
  useEffect(() => { if (opened) { setName(null); setRole('view'); } }, [opened]);
  return (
    <Modal opened={opened} onClose={onClose} title={<Text fw={600}>A role for an existing account</Text>}>
      <Stack>
        <Text size="sm" c="dimmed">The account keeps its password and everything else; it’s only added to OPF’s group for the role.</Text>
        <Select label="Account" data={candidates.map((c) => ({ value: c.name, label: c.fullName ? `${c.name} (${c.fullName})` : c.name }))} value={name} onChange={setName} searchable />
        <Select label="Role" data={roles.map((r) => ({ value: r.value, label: r.label }))} value={role} allowDeselect={false}
          description={roles.find((r) => r.value === role)?.about} inputWrapperOrder={['label', 'input', 'description', 'error']}
          onChange={(r) => r && setRole(r as Role)} />
        <Group justify="flex-end" mt="sm">
          <Button variant="default" onClick={onClose}>Cancel</Button>
          <Button disabled={!name} onClick={() => { onPick(name!, role); onClose(); }}>Give the role</Button>
        </Group>
      </Stack>
    </Modal>
  );
}

function PasswordModal({ account, onClose, onSet }: { account: Account | null; onClose: () => void; onSet: (name: string, password: string) => void }) {
  const [pw, setPw] = useState('');
  const [again, setAgain] = useState('');
  const [error, setError] = useState<string | null>(null);
  useEffect(() => { setPw(''); setAgain(''); setError(null); }, [account]);
  return (
    <Modal opened={!!account} onClose={onClose} title={<Text fw={600}>Set {account?.name}’s password</Text>}>
      <form onSubmit={(e) => {
        e.preventDefault();
        const p = passwordProblem(pw) ?? (pw !== again ? 'The passwords don’t match' : null);
        setError(p);
        if (p || !account) return;
        onSet(account.name, pw);
        onClose();
      }}>
        <Stack>
          <Text size="sm" c="dimmed">It’s the OpenBSD account’s password{account?.shell ? ', for SSH and the console too' : ''}. Their sessions end.</Text>
          <PasswordInput label="New password" autoComplete="new-password" data-autofocus value={pw} onChange={(e) => setPw(e.currentTarget.value)} />
          <PasswordInput label="Again" autoComplete="new-password" value={again} onChange={(e) => setAgain(e.currentTarget.value)} error={error} />
          <Group justify="flex-end" mt="sm">
            <Button variant="default" onClick={onClose}>Cancel</Button>
            <Button type="submit">Set the password</Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}
