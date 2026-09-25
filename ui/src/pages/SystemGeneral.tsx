import { useEffect, useState } from 'react';
import { Button, Card, Grid, Group, List, Modal, PasswordInput, Progress, Select, Stack, TagsInput, Text, TextInput, ThemeIcon } from '@mantine/core';
import { useForm } from '@mantine/form';
import { notifications } from '@mantine/notifications';
import { IconCheck, IconShieldCheck } from '@tabler/icons-react';
import { useStore } from '../model/store';
import { systemInfo } from '../model/live';
import { PageHeader, SectionTitle } from '../components/ui';

const zones = ['UTC', 'America/New_York', 'America/Chicago', 'America/Denver', 'America/Los_Angeles', 'America/Toronto', 'America/Sao_Paulo', 'Europe/London', 'Europe/Berlin', 'Europe/Paris', 'Africa/Johannesburg', 'Asia/Kolkata', 'Asia/Singapore', 'Asia/Tokyo', 'Australia/Sydney'];

function Updates() {
  const [state, setState] = useState<'idle' | 'installing' | 'done'>('idle');
  const [progress, setProgress] = useState(0);
  useEffect(() => {
    if (state !== 'installing') return;
    if (progress >= 100) {
      setState('done');
      return;
    }
    const t = setTimeout(() => setProgress((p) => p + 5), 120);
    return () => clearTimeout(t);
  }, [state, progress]);

  return (
    <Card>
      <SectionTitle>Updates</SectionTitle>
      {state === 'done' ? (
        <Group gap="sm">
          <ThemeIcon color="teal" variant="light" radius="xl"><IconCheck size={16} /></ThemeIcon>
          <Text size="sm">{systemInfo.version} is up to date.</Text>
        </Group>
      ) : (
        <Stack>
          <Text size="sm">
            {systemInfo.patches.length} security patches are available for {systemInfo.version}.
          </Text>
          <List size="sm" spacing={6} icon={<ThemeIcon size={18} radius="xl" color="amber" variant="light"><IconShieldCheck size={12} /></ThemeIcon>}>
            {systemInfo.patches.map((p) => <List.Item key={p.id}>{p.description}</List.Item>)}
          </List>
          {state === 'installing' && <Progress value={progress} animated />}
          <Group justify="flex-end">
            <Button loading={state === 'installing'} onClick={() => { setProgress(0); setState('installing'); }}>
              Install patches
            </Button>
          </Group>
        </Stack>
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
          <Card>
            <form
              onSubmit={form.onSubmit((v) => {
                const parts: string[] = [];
                if (v.hostname !== sys.hostname || v.domain !== sys.domain) parts.push(`name set to ${v.hostname}.${v.domain}`);
                if (v.timezone !== sys.timezone) parts.push(`time zone set to ${v.timezone}`);
                if (v.ntpServers.join() !== sys.ntpServers.join()) parts.push(`time servers: ${v.ntpServers.join(', ')}`);
                edit('system', parts.length ? `System ${parts.join(', ')}` : 'Updated system settings', (m) => ({ ...m, system: v }));
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
