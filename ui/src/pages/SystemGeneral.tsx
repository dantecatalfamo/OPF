import { useEffect, useState } from 'react';
import { Anchor, Button, Card, Grid, Group, List, Modal, PasswordInput, Select, Stack, Table, Text, TextInput, ThemeIcon } from '@mantine/core';
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
import { TimeSettings } from './SystemTime';

const zones = ['UTC', 'America/New_York', 'America/Chicago', 'America/Denver', 'America/Los_Angeles', 'America/Toronto', 'America/Sao_Paulo', 'Europe/London', 'Europe/Berlin', 'Europe/Paris', 'Africa/Johannesburg', 'Asia/Kolkata', 'Asia/Singapore', 'Asia/Tokyo', 'Australia/Sydney'];

// A patch's entry on OpenBSD's errata page for its release ("7.9" →
// errata79.html), anchored as p plus syspatch's name for it
// (#p001_xserver).
function errataUrl(release: string | undefined, patch: string): string | undefined {
  const m = release?.match(/^(\d+)\.(\d+)$/);
  if (!m) return undefined;
  return `https://www.openbsd.org/errata${m[1]}${m[2]}.html#p${encodeURIComponent(patch)}`;
}

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
          {upd.patches.map((p) => {
            const url = errataUrl(sys?.release, p);
            return (
              <List.Item key={p}>
                {url
                  ? <Anchor href={url} target="_blank" rel="noreferrer" className="mono" size="sm">{p}</Anchor>
                  : <Text span className="mono" size="sm">{p}</Text>}
              </List.Item>
            );
          })}
        </List>
        <Text size="xs" c="dimmed">
          You can’t install them from here yet. For now, run <Text span className="mono" size="xs">syspatch</Text> as root on the firewall. Some patches need a reboot afterwards.
        </Text>
      </Stack>
    );
  }
  return (
    <Card id="updates">
      <SectionTitle>Updates</SectionTitle>
      {body}
      {upd?.checkedAt && (
        <Group justify="space-between" mt="sm" gap="xs">
          <Text size="xs" c="dimmed">
            {upd.checking ? 'Checking again…' : `Checked ${new Date(upd.checkedAt).toLocaleString()}. OPF checks again every 2 hours.`}
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
    <Card id="account">
      <SectionTitle right={accounts && <Button size="xs" variant="default" onClick={signOut}>Sign out</Button>}>Your account</SectionTitle>
      {accounts && session ? (
        <Stack gap="sm">
          <Text size="sm">Signed in as <b>{session.user}</b>, {roleAbout[session.role]}.</Text>
          <Text size="sm" c="dimmed">
            A session ends after 30 minutes without use or 12 hours in total, or when your password or groups change. Your password is your OpenBSD account’s password.
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
        <Text size="sm" c="dimmed">This is the development server, which has no accounts. Anyone who can reach it can change everything.</Text>
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
          <Text size="xs" c="dimmed">If your account can log in over SSH or at the console, this password is used there too.</Text>
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
  admin: 'an admin, in the _opfadmin group. You can change everything',
  operator: 'an operator, in the _opfoperator group. You can see everything, confirm or undo changes someone applied, and run tools, but you can’t make changes',
  view: 'a read-only user, in the _opfview group. You can see everything',
};

export function SystemGeneral() {
  const { staged, edit } = useStore();
  const sys = staged.system;
  const form = useForm({
    initialValues: sys,
    validate: {
      hostname: (v) => (/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/i.test(v) ? null : 'Letters, digits and hyphens only'),
      domain: (v) => (/^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/i.test(v) ? null : 'Enter a domain like office.arpa'),
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
          <Card id="identity">
            <form
              onSubmit={form.onSubmit((v) => {
                const parts: string[] = [];
                if (v.hostname !== sys.hostname || v.domain !== sys.domain) parts.push(`name set to ${v.hostname}.${v.domain}`);
                if (v.timezone !== sys.timezone) parts.push(`time zone set to ${v.timezone}`);
                edit('system', parts.length ? `System ${parts.join(', ')}` : 'Updated system settings', (m) => ({ ...m, system: { ...m.system, hostname: v.hostname, domain: v.domain, timezone: v.timezone } }));
              })}
            >
              <SectionTitle>Name and time zone</SectionTitle>
              <Stack>
                <Group grow align="flex-start">
                  <TextInput label="Hostname" {...form.getInputProps('hostname')} />
                  <TextInput label="Domain" description="Used for local device names" inputWrapperOrder={['label', 'input', 'description', 'error']} {...form.getInputProps('domain')} />
                </Group>
                <Select label="Time zone" data={zones} searchable allowDeselect={false} {...form.getInputProps('timezone')} />
                <Group justify="space-between">
                  <FileLink path="/etc/myname" />
                  <Button type="submit" disabled={!form.isDirty()}>Save</Button>
                </Group>
              </Stack>
            </form>
          </Card>
          <TimeSettings />
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
