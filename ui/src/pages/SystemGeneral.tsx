import { useEffect, useState } from 'react';
import { Button, Card, Grid, Group, List, Modal, PasswordInput, Select, Stack, TagsInput, Text, TextInput, ThemeIcon } from '@mantine/core';
import { useForm } from '@mantine/form';
import { notifications } from '@mantine/notifications';
import { IconCheck, IconShieldCheck } from '@tabler/icons-react';
import { backend, useStore } from '../model/store';
import { refreshLive, useLive } from '../lib/live';
import { PageHeader, SectionTitle } from '../components/ui';
import { GraphSettings } from './GraphSettings';

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

function Password() {
  const [opened, setOpened] = useState(false);
  const form = useForm({
    initialValues: { current: '', next: '', confirm: '' },
    validate: {
      current: (v) => (v ? null : 'Enter your current password'),
      next: (v) => (v.length >= 12 ? null : 'Use at least 12 characters'),
      confirm: (v, vals) => (v === vals.next ? null : 'The passwords don’t match'),
    },
  });
  return (
    <Card>
      <SectionTitle>Administrator</SectionTitle>
      <Stack gap="sm">
        <Text size="sm" c="dimmed">You’re signed in as admin. Sessions end after 4 hours without activity.</Text>
        <Group justify="flex-end">
          <Button variant="default" onClick={() => setOpened(true)}>Change password</Button>
        </Group>
      </Stack>
      <Modal opened={opened} onClose={() => setOpened(false)} title={<Text fw={600}>Change password</Text>}>
        <form
          onSubmit={form.onSubmit(() => {
            setOpened(false);
            form.reset();
            notifications.show({ color: 'teal', title: 'Password changed', message: 'Use the new password next time you sign in.' });
          })}
        >
          <Stack>
            <PasswordInput label="Current password" {...form.getInputProps('current')} />
            <PasswordInput label="New password" {...form.getInputProps('next')} />
            <PasswordInput label="Repeat new password" {...form.getInputProps('confirm')} />
            <Group justify="flex-end" mt="sm">
              <Button variant="default" onClick={() => setOpened(false)}>Cancel</Button>
              <Button type="submit">Change password</Button>
            </Group>
          </Stack>
        </form>
      </Modal>
    </Card>
  );
}

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
                  <TextInput label="Domain" description="Used for local device names" {...form.getInputProps('domain')} />
                </Group>
                <Select label="Time zone" data={zones} searchable allowDeselect={false} {...form.getInputProps('timezone')} />
                <TagsInput label="Time servers" {...form.getInputProps('ntpServers')} />
                <Group justify="flex-end">
                  <Button type="submit" disabled={!form.isDirty()}>Save</Button>
                </Group>
              </Stack>
            </form>
          </Card>
          <GraphSettings />
          </Stack>
        </Grid.Col>
        <Grid.Col span={{ base: 12, lg: 5 }}>
          <Stack gap="md">
            <Updates />
            <Password />
          </Stack>
        </Grid.Col>
      </Grid>
    </>
  );
}
