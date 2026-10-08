import { useEffect, useState } from 'react';
import { Button, Card, Grid, Group, List, Modal, PasswordInput, Select, Stack, Table, TagsInput, Text, TextInput, ThemeIcon } from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { useForm } from '@mantine/form';
import { IconCheck, IconShieldCheck } from '@tabler/icons-react';
import { backend, useStore } from '../model/store';
import { refreshLive, useLive } from '../lib/live';
import { PageHeader, SectionTitle } from '../components/ui';
import { FirewallDns } from './SystemDns';
import { GraphSettings } from './GraphSettings';
import { useSession } from '../lib/session';
import { ApiError, type Role, type SessionInfo } from '../lib/api';
import { SessionRow } from './Users';
import { FileLink } from './ConfigFiles';

const zones = ['UTC', 'America/New_York', 'America/Chicago', 'America/Denver', 'America/Los_Angeles', 'America/Toronto', 'America/Sao_Paulo', 'Europe/London', 'Europe/Berlin', 'Europe/Paris', 'Africa/Johannesburg', 'Asia/Kolkata', 'Asia/Singapore', 'Asia/Tokyo', 'Australia/Sydney'];

// Security patches for the running release, from syspatch -c. Installing
// them from here isn't built yet (TODO.md › Diagnostics tools › Updates).
function Updates() {
  const { data: upd, error } = useLive('updates');
  const { data: sys } = useLive('system');
  const release = sys ? `OpenBSD ${sys.release}` : 'OpenBSD';
  let body;
  if (!upd || (upd.checking && !upd.checkedAt)) {
    body = <Text size="sm" c="dimmed">{error ? `Couldn’t ask the firewall: ${error}` : 'Checking for security patches…'}</Text>;
  } else if (upd.error) {
    body = <Text size="sm" c="yellow">{upd.error}. OPF tries again in a few minutes.</Text>;
  } else if (!upd.patches.length) {
    body = (
      <Group gap="sm">
        <ThemeIcon color="teal" variant="light" radius="xl"><IconCheck size={16} /></ThemeIcon>
        <Text size="sm">{release} has every security patch.</Text>
      </Group>
    );
  } else {
    body = (
      <Stack>
        <Text size="sm">
          {upd.patches.length} security {upd.patches.length === 1 ? 'patch is' : 'patches are'} available for {release}.
        </Text>
        <List size="sm" spacing={6} icon={<ThemeIcon size={18} radius="xl" color="amber" variant="light"><IconShieldCheck size={12} /></ThemeIcon>}>
          {upd.patches.map((p) => <List.Item key={p}><Text span className="mono" size="sm">{p}</Text></List.Item>)}
        </List>
        <Text size="xs" c="dimmed">
          Installing them from here comes later. For now, run <Text span className="mono" size="xs">syspatch</Text> as root on the firewall; some patches then need a reboot.
        </Text>
      </Stack>
    );
  }
  return (
    <Card>
      <SectionTitle>Updates</SectionTitle>
      {body}
      {upd?.checkedAt && (
        <Group justify="space-between" mt="sm" gap="xs">
          <Text size="xs" c="dimmed">
            {upd.checking ? 'Checking again…' : `Checked ${new Date(upd.checkedAt).toLocaleString()}; again every 2 hours.`}
          </Text>
          <Button size="compact-xs" variant="subtle" disabled={upd.checking} onClick={() => backend.checkUpdates().then(() => refreshLive('updates'), () => refreshLive('updates'))}>
            Check again
          </Button>
        </Group>
      )}
    </Card>
  );
}

// Who's signed in. Passwords are the system's own: until there's a
// page for accounts (TODO.md › User and role management), they're
// changed with passwd(1) on the firewall.
function Account() {
  const { accounts, session, signOut } = useSession();
  const [changing, setChanging] = useState(false);
  const [mine, setMine] = useState<SessionInfo[]>([]);
  const load = () => { if (accounts) backend.sessions().then((r) => setMine(r.sessions.filter((s) => s.user === session?.user)), () => {}); };
  useEffect(load, [accounts, session?.user]); // eslint-disable-line react-hooks/exhaustive-deps
  return (
    <Card>
      <SectionTitle right={accounts && <Button size="xs" variant="default" onClick={signOut}>Sign out</Button>}>Your account</SectionTitle>
      {accounts && session ? (
        <Stack gap="sm">
          <Text size="sm">Signed in as <b>{session.user}</b>, {roleAbout[session.role]}.</Text>
          <Text size="sm" c="dimmed">
            A session ends after 30 minutes without use, or 12 hours in all, and when your password or groups change. Your password is this OpenBSD account’s.
          </Text>
          <Group justify="flex-end"><Button size="xs" variant="default" onClick={() => setChanging(true)}>Change your password</Button></Group>
          {mine.length > 1 && (
            <>
              <Text size="sm" fw={500}>Your sessions</Text>
              <Table verticalSpacing={4}>
                <Table.Tbody>
                  {mine.map((s) => <SessionRow key={s.id} s={s} mine={s.id === session.id} onEnd={() => backend.endSession(s.id).then(load, load)} />)}
                </Table.Tbody>
              </Table>
            </>
          )}
          <OwnPassword opened={changing} onClose={() => setChanging(false)} />
        </Stack>
      ) : (
        <Text size="sm" c="dimmed">This server has no accounts: it’s the development server, and anyone who can reach it can change everything.</Text>
      )}
    </Card>
  );
}

function OwnPassword({ opened, onClose }: { opened: boolean; onClose: () => void }) {
  const [v, setV] = useState({ current: '', next: '', again: '' });
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);
  useEffect(() => { if (opened) { setV({ current: '', next: '', again: '' }); setErrors({}); } }, [opened]);
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    const errs: Record<string, string> = {};
    if (v.next.length < 12) errs.new = 'At least 12 characters';
    if (v.again !== v.next) errs.again = 'The passwords don’t match';
    setErrors(errs);
    if (Object.keys(errs).length) return;
    setBusy(true);
    try {
      await backend.changeOwnPassword(v.current, v.next);
      notifications.show({ color: 'teal', message: 'Password changed. Your other sessions ended.' });
      onClose();
    } catch (err) {
      setErrors(err instanceof ApiError && err.details.length ? Object.fromEntries(err.details.map((d) => [d.path, d.message ?? ""])) : { current: err instanceof Error ? err.message : String(err) });
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal opened={opened} onClose={onClose} title={<Text fw={600}>Change your password</Text>}>
      <form onSubmit={submit}>
        <Stack>
          <PasswordInput label="Current password" autoComplete="current-password" data-autofocus value={v.current} onChange={(e) => setV({ ...v, current: e.currentTarget.value })} error={errors.current} />
          <PasswordInput label="New password" autoComplete="new-password" value={v.next} onChange={(e) => setV({ ...v, next: e.currentTarget.value })} error={errors.new} />
          <PasswordInput label="Again" autoComplete="new-password" value={v.again} onChange={(e) => setV({ ...v, again: e.currentTarget.value })} error={errors.again} />
          <Text size="xs" c="dimmed">It’s also your password for SSH and the console, if your account has those.</Text>
          <Group justify="flex-end" mt="sm">
            <Button variant="default" onClick={onClose}>Cancel</Button>
            <Button type="submit" loading={busy}>Change it</Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}

const roleAbout: Record<Role, string> = {
  admin: 'an admin (_opfadmin): you can change everything',
  operator: 'an operator (_opfoperator): you can look, keep or undo changes, and run tools, but not make changes',
  view: 'read-only (_opfview): you can look at everything',
};

export function SystemGeneral() {
  const { staged, edit } = useStore();
  const sys = staged.system;
  const form = useForm({
    initialValues: sys,
    validate: {
      hostname: (v) => (/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/i.test(v) ? null : 'Letters, digits and hyphens only'),
      domain: (v) => (/^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/i.test(v) ? null : 'Enter a domain like office.arpa'),
      ntpServers: (v) => (v.length ? null : 'Add at least one time server'),
    },
  });
  useEffect(() => {
    form.setValues(sys);
    form.resetDirty();
  }, [sys]); // form is stable

  return (
    <>
      <PageHeader title="General" description="The name, clock and software of this firewall." />
      <Grid gutter="md">
        <Grid.Col span={{ base: 12, lg: 7 }}>
          <Stack gap="md">
          <Card>
            <form
              onSubmit={form.onSubmit((v) => {
                const parts: string[] = [];
                if (v.hostname !== sys.hostname || v.domain !== sys.domain) parts.push(`name set to ${v.hostname}.${v.domain}`);
                if (v.timezone !== sys.timezone) parts.push(`time zone set to ${v.timezone}`);
                if (v.ntpServers.join() !== sys.ntpServers.join()) parts.push(`time servers: ${v.ntpServers.join(', ')}`);
                edit('system', parts.length ? `System ${parts.join(', ')}` : 'Updated system settings', (m) => ({ ...m, system: { ...m.system, hostname: v.hostname, domain: v.domain, timezone: v.timezone, ntpServers: v.ntpServers } }));
              })}
            >
              <SectionTitle>Identity and time</SectionTitle>
              <Stack>
                <Group grow align="flex-start">
                  <TextInput label="Hostname" {...form.getInputProps('hostname')} />
                  <TextInput label="Domain" description="Used for local device names" inputWrapperOrder={['label', 'input', 'description', 'error']} {...form.getInputProps('domain')} />
                </Group>
                <Select label="Time zone" data={zones} searchable allowDeselect={false} {...form.getInputProps('timezone')} />
                <TagsInput label="Time servers" {...form.getInputProps('ntpServers')} />
                <Group justify="space-between">
                  <Group gap="md"><FileLink path="/etc/myname" /><FileLink path="/etc/ntpd.conf" /></Group>
                  <Button type="submit" disabled={!form.isDirty()}>Save</Button>
                </Group>
              </Stack>
            </form>
          </Card>
          <FirewallDns />
          <GraphSettings />
          </Stack>
        </Grid.Col>
        <Grid.Col span={{ base: 12, lg: 5 }}>
          <Stack gap="md">
            <Updates />
            <Account />
          </Stack>
        </Grid.Col>
      </Grid>
    </>
  );
}
