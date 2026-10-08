// Firewall › Sign-in access (authpf): network access that opens while
// someone is signed in to the firewall over SSH and closes when they
// sign out. Who may sign in (system accounts OPF makes, keys only), the
// rules their sessions load, and who's signed in now.
import { useEffect, useState } from 'react';
import { Link } from 'react-router';
import {
  ActionIcon, Alert, Anchor, Badge, Button, Card, Code, Grid, Group, Menu, Modal, MultiSelect, Stack, Switch, Table, Text, Textarea, TextInput, Tooltip,
} from '@mantine/core';
import { useForm } from '@mantine/form';
import { notifications } from '@mantine/notifications';
import { IconAlertTriangle, IconDots, IconPencil, IconPlus, IconTrash } from '@tabler/icons-react';
import { backend, newId, useStore } from '../model/store';
import type { Authpf as AuthpfSettings, AuthpfUser, Model, Rule, RuleInput } from '../model/types';
import type { AuthpfSessionsResource } from '../lib/api';
import { useRole } from '../lib/session';
import { endpointLabel, ifaceName } from '../lib/labels';
import { formatAgo } from '../lib/format';
import { useOpenFromLink } from '../lib/openFromLink';
import { Empty, Mono, PageHeader, SectionTitle } from '../components/ui';
import { RuleDrawer } from './RuleDrawer';

const POLL_MS = 10_000;
const loginRE = /^[a-z][a-z0-9-]{0,30}$/;
const reserved = ['root', 'daemon', 'operator', 'bin', 'build', 'sshd', 'nobody', 'www', 'named', 'proxy', 'authpf', 'admin', 'opf'];
const keyRE = /^(ssh-ed25519|sk-ssh-ed25519@openssh\.com|ecdsa-sha2-nistp(256|384|521)|sk-ecdsa-sha2-nistp256@openssh\.com|ssh-rsa) [A-Za-z0-9+/]+={0,3}( .*)?$/;

const blankSettings: AuthpfSettings = { enabled: false, signIn: [], users: [] };
const errorText = (e: unknown) => (e instanceof Error ? e.message : String(e));

function useAuthpf() {
  const { staged, edit } = useStore();
  const a = staged.firewall.authpf ?? blankSettings;
  const set = (summary: string, fn: (a: AuthpfSettings, m: Model) => Partial<Model['firewall']>) =>
    edit('firewall', summary, (m) => ({ ...m, firewall: { ...m.firewall, ...fn(m.firewall.authpf ?? blankSettings, m) } }));
  return { staged, a, set };
}

function Settings() {
  const { staged, a, set } = useAuthpf();
  const form = useForm({ initialValues: { enabled: a.enabled, signIn: a.signIn, message: a.message ?? '' } });
  useEffect(() => { form.setValues({ enabled: a.enabled, signIn: a.signIn, message: a.message ?? '' }); form.resetDirty(); }, [a.enabled, a.signIn.join(), a.message]); // eslint-disable-line react-hooks/exhaustive-deps
  const v = form.values;
  const wan = staged.interfaces.filter((i) => i.role === 'wan').map((i) => i.id);
  return (
    <Card h="100%">
      <form onSubmit={form.onSubmit((vals) => {
        set(vals.enabled ? 'Sign-in access set up' : 'Sign-in access turned off', (cur) => ({ authpf: { ...cur, enabled: vals.enabled, signIn: vals.signIn, message: vals.message.trim() || undefined } }));
      })}>
        <SectionTitle right={<Switch label="On" {...form.getInputProps('enabled', { type: 'checkbox' })} />}>Settings</SectionTitle>
        <Stack gap="sm">
          <MultiSelect
            label="Users sign in from"
            description="SSH to the firewall's address on these networks is let in, for signing in."
            data={staged.interfaces.map((i) => ({ value: i.id, label: i.name }))}
            error={v.enabled && !v.signIn.length ? 'Choose at least one' : undefined}
            {...form.getInputProps('signIn')}
          />
          {v.signIn.some((id) => wan.includes(id)) && (
            <Alert color="yellow" variant="light" p="xs" icon={<IconAlertTriangle size={16} />}>
              Signing in from the WAN opens SSH to the internet; only keys are taken, never passwords.
            </Alert>
          )}
          <Textarea label="Message once signed in" description="Shown to each user; their access lasts while they stay connected." autosize minRows={2} maxRows={6} {...form.getInputProps('message')} />
          <Text size="xs" c="dimmed">
            Each user is a system account OPF makes, with authpf as its shell and no password. sshd’s settings for them (keys only, no tunnels, a dropped session
            ended within a minute) go in a block OPF keeps at the end of <Mono>/etc/ssh/sshd_config</Mono>.
          </Text>
          <Group justify="flex-end">
            <Button type="submit" disabled={!form.isDirty() || (v.enabled && !v.signIn.length)}>Save</Button>
          </Group>
        </Stack>
      </form>
    </Card>
  );
}

type UserValues = { name: string; description: string; keys: string; banned: boolean; bannedMessage: string };

function UserModal({ user, opened, onClose }: { user: AuthpfUser | null; opened: boolean; onClose: () => void }) {
  const { a, set } = useAuthpf();
  const form = useForm<UserValues>({
    initialValues: { name: '', description: '', keys: '', banned: false, bannedMessage: '' },
    validate: {
      name: (n) => {
        if (!loginRE.test(n)) return 'Lowercase letters, digits and -, starting with a letter';
        if (reserved.includes(n)) return 'That login is the system’s';
        return a.users.some((u) => u.name === n && u.id !== user?.id) ? 'That login is taken' : null;
      },
      keys: (k, vals) => {
        const lines = k.split('\n').map((l) => l.trim()).filter(Boolean);
        if (!lines.length && !vals.banned) return 'Add a public key: signing in takes one';
        const bad = lines.find((l) => !keyRE.test(l));
        return bad ? `Not a public key: “${bad.slice(0, 40)}${bad.length > 40 ? '…' : ''}” (no options before the key)` : null;
      },
    },
  });
  useEffect(() => {
    if (!opened) return;
    form.setValues(user ? { name: user.name, description: user.description, keys: user.keys.join('\n'), banned: !!user.banned, bannedMessage: user.banned ?? '' } : { name: '', description: '', keys: '', banned: false, bannedMessage: '' });
    form.resetDirty();
  }, [opened, user]); // eslint-disable-line react-hooks/exhaustive-deps
  return (
    <Modal opened={opened} onClose={onClose} title={<Text fw={600}>{user ? `Edit ${user.name}` : 'Add a user'}</Text>} size="lg">
      <form onSubmit={form.onSubmit((v) => {
        const next: AuthpfUser = {
          id: user?.id ?? newId('u'),
          name: v.name,
          description: v.description.trim(),
          keys: v.keys.split('\n').map((l) => l.trim()).filter(Boolean),
          banned: v.banned ? v.bannedMessage.trim() || 'You may not use this network.' : undefined,
        };
        set(user ? `Edited sign-in user ${next.name}` : `Added sign-in user ${next.name}`, (cur) => ({
          authpf: { ...cur, users: user ? cur.users.map((u) => (u.id === user.id ? next : u)) : [...cur.users, next] },
        }));
        onClose();
      })}>
        <Stack>
          <TextInput label="Login" description="Their account on the firewall; they sign in with ssh login@firewall" disabled={!!user} {...form.getInputProps('name')} />
          <TextInput label="Description" placeholder="Contractor, Acme" {...form.getInputProps('description')} />
          <Textarea
            label="SSH public keys"
            description="One per line, as in authorized_keys: ssh-ed25519 AAAA… comment"
            autosize
            minRows={3}
            maxRows={8}
            styles={{ input: { fontFamily: 'var(--mantine-font-family-monospace)', fontSize: 12 } }}
            {...form.getInputProps('keys')}
          />
          <Switch label="Banned" description="They can’t sign in, and see the message below instead." {...form.getInputProps('banned', { type: 'checkbox' })} />
          {form.values.banned && <Textarea label="What they see" autosize minRows={2} placeholder="You may not use this network." {...form.getInputProps('bannedMessage')} />}
          <Group justify="flex-end" mt="sm">
            <Button variant="default" onClick={onClose}>Cancel</Button>
            <Button type="submit">{user ? 'Save' : 'Add user'}</Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}

function Users({ signedIn }: { signedIn: Set<string> }) {
  const { staged, a, set } = useAuthpf();
  const [modal, setModal] = useState<{ open: boolean; user: AuthpfUser | null }>({ open: false, user: null });
  const [removing, setRemoving] = useState<AuthpfUser>();
  // A rule for only this user would be for everyone without them: it
  // goes too.
  const onlyTheirs = (u: AuthpfUser) => staged.firewall.rules.filter((r) => r.authpf?.users?.length === 1 && r.authpf.users[0] === u.id);
  const remove = (u: AuthpfUser) => {
    const gone = new Set(onlyTheirs(u).map((r) => r.id));
    set(`Removed sign-in user ${u.name}`, (cur, m) => ({
      authpf: { ...cur, users: cur.users.filter((x) => x.id !== u.id) },
      rules: m.firewall.rules
        .filter((r) => !gone.has(r.id))
        .map((r) => (r.authpf?.users?.includes(u.id) ? { ...r, authpf: { users: r.authpf.users.filter((x) => x !== u.id) } } : r)),
    }));
    setRemoving(undefined);
  };
  return (
    <Card h="100%">
      <SectionTitle right={<Button size="xs" variant="light" leftSection={<IconPlus size={14} />} onClick={() => setModal({ open: true, user: null })}>Add user</Button>}>Users</SectionTitle>
      {a.users.length ? (
        <Table verticalSpacing={6}>
          <Table.Tbody>
            {a.users.map((u) => (
              <Table.Tr key={u.id}>
                <Table.Td>
                  <Group gap={6}>
                    <Mono>{u.name}</Mono>
                    {u.banned && <Badge size="xs" color="red">banned</Badge>}
                    {signedIn.has(u.name) && <Badge size="xs" color="teal">signed in</Badge>}
                  </Group>
                  <Text size="xs" c="dimmed">{u.description || '—'} · {u.keys.length} key{u.keys.length === 1 ? '' : 's'}</Text>
                </Table.Td>
                <Table.Td w={44}>
                  <Menu position="bottom-end">
                    <Menu.Target><ActionIcon variant="subtle" color="gray" aria-label={`Actions for ${u.name}`}><IconDots size={16} /></ActionIcon></Menu.Target>
                    <Menu.Dropdown>
                      <Menu.Item leftSection={<IconPencil size={16} />} onClick={() => setModal({ open: true, user: u })}>Edit</Menu.Item>
                      <Menu.Item leftSection={<IconTrash size={16} />} color="red" onClick={() => setRemoving(u)}>Remove</Menu.Item>
                    </Menu.Dropdown>
                  </Menu>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      ) : <Empty>No one can sign in yet.</Empty>}
      <UserModal user={modal.user} opened={modal.open} onClose={() => setModal((m) => ({ ...m, open: false }))} />
      <Modal opened={!!removing} onClose={() => setRemoving(undefined)} title={<Text fw={600}>Remove {removing?.name}?</Text>}>
        {removing && (
          <Stack>
            <Text size="sm">Their account is removed when the change is applied; a session they have open stays until it ends.</Text>
            {onlyTheirs(removing).length > 0 && (
              <Text size="sm">Their own rules go too: {onlyTheirs(removing).map((r) => `“${r.description}”`).join(', ')}.</Text>
            )}
            <Group justify="flex-end">
              <Button variant="default" onClick={() => setRemoving(undefined)}>Cancel</Button>
              <Button color="red" onClick={() => remove(removing)}>Remove</Button>
            </Group>
          </Stack>
        )}
      </Modal>
    </Card>
  );
}

function Rules() {
  const { staged, a, set } = useAuthpf();
  const [drawer, setDrawer] = useState<{ open: boolean; rule: Rule | null }>({ open: false, rule: null });
  useOpenFromLink(staged.firewall.rules.filter((r) => r.authpf), (rule) => setDrawer({ open: true, rule }));
  const rules = staged.firewall.rules.filter((r) => r.authpf);
  const userName = (id: string) => a.users.find((u) => u.id === id)?.name ?? id;
  const save = (r: RuleInput) => {
    const existing = drawer.rule;
    set(existing ? `Edited sign-in rule “${r.description}”` : `Added sign-in rule “${r.description}”`, (_cur, m) => ({
      rules: existing ? m.firewall.rules.map((x) => (x.id === existing.id ? ({ ...r, id: x.id } as Rule) : x)) : [...m.firewall.rules, { ...r, id: newId('r') } as Rule],
    }));
  };
  const toggle = (r: Rule) => set(`${r.enabled ? 'Turned off' : 'Turned on'} sign-in rule “${r.description}”`, (_c, m) => ({ rules: m.firewall.rules.map((x) => (x.id === r.id ? { ...x, enabled: !x.enabled } : x)) }));
  const del = (r: Rule) => set(`Deleted sign-in rule “${r.description}”`, (_c, m) => ({ rules: m.firewall.rules.filter((x) => x.id !== r.id) }));
  return (
    <Card>
      <SectionTitle right={<Button size="xs" variant="light" leftSection={<IconPlus size={14} />} onClick={() => setDrawer({ open: true, rule: null })}>Add rule</Button>}>
        Rules while signed in
      </SectionTitle>
      <Text size="xs" c="dimmed" mb="sm">
        Loaded for each user when they sign in, with their address as the signed-in user, and taken out when they sign out; checked before every
        interface rule. A user’s own rules come after everyone’s.
      </Text>
      {rules.length ? (
        <Table verticalSpacing={6}>
          <Table.Tbody>
            {rules.map((r) => (
              <Table.Tr key={r.id} style={r.enabled ? undefined : { opacity: 0.55 }}>
                <Table.Td w={60}><Switch size="xs" checked={r.enabled} onChange={() => toggle(r)} aria-label={`${r.enabled ? 'Turn off' : 'Turn on'} ${r.description}`} /></Table.Td>
                <Table.Td>
                  <Text size="sm">{r.description}</Text>
                  {r.kind === 'form' && (
                    <Text size="xs" c="dimmed">
                      {r.action} {r.interfaces.length ? `on ${r.interfaces.map((i) => ifaceName(staged, i)).join(', ')} ` : ''}from {endpointLabel(r.source, staged).toLowerCase()} to {endpointLabel(r.destination, staged).toLowerCase()}
                      {r.port ? ` port ${r.port}` : ''}
                    </Text>
                  )}
                </Table.Td>
                <Table.Td><Text size="xs" c="dimmed">{r.authpf?.users?.length ? `For ${r.authpf.users.map(userName).join(', ')}` : 'For everyone'}</Text></Table.Td>
                <Table.Td w={44}>
                  <Menu position="bottom-end">
                    <Menu.Target><ActionIcon variant="subtle" color="gray" aria-label={`Actions for ${r.description}`}><IconDots size={16} /></ActionIcon></Menu.Target>
                    <Menu.Dropdown>
                      <Menu.Item leftSection={<IconPencil size={16} />} onClick={() => setDrawer({ open: true, rule: r })}>Edit</Menu.Item>
                      <Menu.Item leftSection={<IconTrash size={16} />} color="red" onClick={() => del(r)}>Delete</Menu.Item>
                    </Menu.Dropdown>
                  </Menu>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      ) : <Empty>No rules yet: a signed-in user gets nothing until one lets them.</Empty>}
      <RuleDrawer opened={drawer.open} onClose={() => setDrawer((d) => ({ ...d, open: false }))} model={staged} rule={drawer.rule} iface={a.signIn[0] ?? null} onSave={save} authpf />
    </Card>
  );
}

function Sessions({ data, error, onEnded }: { data?: AuthpfSessionsResource; error?: string; onEnded: () => void }) {
  const { canOperate } = useRole();
  const [ending, setEnding] = useState<AuthpfSessionsResource['sessions'][number]>();
  const end = async (pid: number) => {
    try {
      await backend.authpfEnd(pid);
      notifications.show({ color: 'teal', message: 'Session ended' });
      onEnded();
    } catch (e) {
      notifications.show({ color: 'red', title: 'Couldn’t end it', message: errorText(e) });
    }
    setEnding(undefined);
  };
  return (
    <Card>
      <SectionTitle>Signed in now</SectionTitle>
      {error ? <Alert color="red" variant="light">{error}</Alert> : !data ? <Text size="sm" c="dimmed">Reading…</Text> : data.sessions.length ? (
        <Table verticalSpacing={6}>
          <Table.Tbody>
            {data.sessions.map((s) => (
              <Table.Tr key={s.pid}>
                <Table.Td><Mono>{s.user}</Mono></Table.Td>
                <Table.Td><Mono>{s.address}</Mono></Table.Td>
                <Table.Td>
                  <Tooltip label={new Date(s.since).toLocaleString()}><Text size="sm">since {formatAgo((Date.now() - new Date(s.since).getTime()) / 1000)}</Text></Tooltip>
                  {!s.rules && <Text size="xs" c="yellow">Its rules aren’t loaded</Text>}
                </Table.Td>
                <Table.Td w={120} ta="right">
                  {canOperate && <Button size="compact-sm" variant="subtle" color="red" onClick={() => setEnding(s)}>End session</Button>}
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      ) : <Empty>No one is signed in.</Empty>}
      <Modal opened={!!ending} onClose={() => setEnding(undefined)} title={<Text fw={600}>End {ending?.user}’s session?</Text>}>
        {ending && (
          <Stack>
            <Text size="sm">
              Their rules are taken out, and every connection from <Mono>{ending.address}</Mono> ends, not only theirs: anything else at that address, an
              admin’s SSH included, is cut off too.
            </Text>
            <Group justify="flex-end">
              <Button variant="default" onClick={() => setEnding(undefined)}>Cancel</Button>
              <Button color="red" onClick={() => end(ending.pid)}>End session</Button>
            </Group>
          </Stack>
        )}
      </Modal>
    </Card>
  );
}

export function Authpf() {
  const { applied } = useStore();
  const { a } = useAuthpf();
  const [data, setData] = useState<AuthpfSessionsResource>();
  const [error, setError] = useState<string>();
  const [tick, setTick] = useState(0);
  useEffect(() => {
    let live = true;
    const load = () => !document.hidden && backend.authpfSessions().then((d) => { if (live) { setData(d); setError(undefined); } }, (e) => live && setError(errorText(e)));
    load();
    const t = setInterval(load, POLL_MS);
    return () => { live = false; clearInterval(t); };
  }, [tick]);
  const signedIn = new Set((data?.sessions ?? []).map((s) => s.user));
  const appliedOn = !!applied.firewall.authpf?.enabled;
  return (
    <>
      <PageHeader
        title="Sign-in access"
        description="Network access that opens while someone is signed in to the firewall over SSH, and closes when they sign out: for contractors, guests, or anything that should need a person there. Built on OpenBSD’s authpf."
      />
      {a.enabled && !appliedOn && <Alert color="gray" variant="light" mb="md">Apply the change to set it up: the accounts are made, and sshd and pf take their settings.</Alert>}
      <Grid gutter="md" mb="md">
        <Grid.Col span={{ base: 12, md: 5 }}><Settings /></Grid.Col>
        <Grid.Col span={{ base: 12, md: 7 }}><Users signedIn={signedIn} /></Grid.Col>
      </Grid>
      <Stack gap="md">
        <Rules />
        {(appliedOn || (data?.sessions.length ?? 0) > 0) && <Sessions data={data} error={error} onEnded={() => setTick((n) => n + 1)} />}
        <Text size="xs" c="dimmed">
          Users sign in with <Code>ssh login@{applied.interfaces.find((i) => a.signIn.includes(i.id))?.ipv4.address ?? 'the firewall'}</Code> and stay connected for as
          long as they need access. Rules elsewhere can use “Any signed-in user” as a source. <Anchor component={Link} to="/monitoring/events" size="xs">Sign-ins and sign-outs</Anchor> are in the events.
        </Text>
      </Stack>
    </>
  );
}
