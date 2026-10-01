// System › Notifications: webhooks, where OPF sends its events as
// signed JSON. Which webhooks there are, and which events each gets,
// are settings like any other (reviewed and applied). A webhook's URL
// and signing key are secrets: they're set here and take effect at
// once, and afterwards only the URL's scheme and host are shown.
import { useEffect, useState } from 'react';
import {
  Accordion, ActionIcon, Alert, Badge, Button, Card, Chip, Code, CopyButton, Group, Menu, Modal, SegmentedControl, Stack, Switch, Text, TextInput, Tooltip,
} from '@mantine/core';
import { useForm } from '@mantine/form';
import { notifications as toast } from '@mantine/notifications';
import { IconAlertTriangle, IconCheck, IconCopy, IconDots, IconPencil, IconPlus, IconSend, IconTrash } from '@tabler/icons-react';
import { backend, useStore } from '../model/store';
import type { Model, Webhook } from '../model/types';
import type { WebhookStatus } from '../lib/api';
import { formatAgo } from '../lib/format';
import { useNow } from '../lib/useNow';
import { Empty, PageHeader, SectionTitle } from '../components/ui';

const kinds: { value: string; label: string }[] = [
  { value: 'link', label: 'Links' },
  { value: 'address', label: 'Addresses' },
  { value: 'gateway', label: 'Gateways' },
  { value: 'device', label: 'New devices' },
  { value: 'vpn', label: 'VPN' },
  { value: 'service', label: 'Services' },
  { value: 'list', label: 'Lists' },
  { value: 'updates', label: 'Updates' },
  { value: 'commit', label: 'Changes' },
  { value: 'opf', label: 'OPF' },
];

type Format = '' | NonNullable<Webhook['format']>;

// What each format sends, and where its URL comes from.
const formats: { value: Format; label: string; about: string; url: string }[] = [
  { value: '', label: 'JSON', about: 'OPF’s own JSON, signed: for Home Assistant, n8n or a script of your own.', url: 'https://example.com/api/webhook/…' },
  { value: 'slack', label: 'Slack', about: 'A message in a Slack channel, from an incoming webhook (Slack › Apps › Incoming Webhooks). Mattermost takes the same.', url: 'https://hooks.slack.com/services/…' },
  { value: 'discord', label: 'Discord', about: 'A message in a Discord channel, from its webhook (the channel’s Settings › Integrations › Webhooks).', url: 'https://discord.com/api/webhooks/…' },
  { value: 'ntfy', label: 'ntfy', about: 'A push notification on your phone through ntfy, ntfy.sh or your own server; problems arrive at high priority. A token for a protected topic goes in the URL as ?auth=….', url: 'https://ntfy.sh/your-topic' },
];
const formatOf = (w?: Webhook | null) => formats.find((f) => f.value === (w?.format ?? '')) ?? formats[0];

function hookId(name: string, m: Model): string {
  const base = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 24) || 'webhook';
  const taken = new Set((m.notifications?.webhooks ?? []).map((w) => w.id));
  let id = base;
  for (let n = 2; taken.has(id); n++) id = `${base}-${n}`;
  return id;
}

// Which events a webhook gets, and a name: settings, reviewed and applied.
function EditModal({ hook, onClose, onSave }: { hook: Webhook | null; onClose: () => void; onSave: (w: Omit<Webhook, 'id'>) => void }) {
  const form = useForm({
    initialValues: { name: '', kinds: [] as string[], problemsOnly: false, format: '' as Format },
    validate: { name: (v) => (!v.trim() ? 'Name it' : v.length > 60 ? 'Up to 60 characters' : null) },
  });
  useEffect(() => {
    if (hook) form.setValues({ name: hook.name, kinds: hook.kinds ?? [], problemsOnly: hook.problemsOnly ?? false, format: hook.format ?? '' });
  }, [hook]); // form is stable
  return (
    <Modal opened={!!hook} onClose={onClose} title={<Text fw={600}>{hook?.id ? `Edit ${hook.name}` : 'Add a webhook'}</Text>}>
      <form onSubmit={form.onSubmit((v) => { onSave({ name: v.name.trim(), enabled: hook?.enabled ?? true, kinds: v.kinds.length ? v.kinds : undefined, problemsOnly: v.problemsOnly || undefined, format: v.format || undefined }); onClose(); })}>
        <Stack>
          <TextInput label="Name" placeholder="Home Assistant" data-autofocus {...form.getInputProps('name')} />
          <Stack gap={6}>
            <Text size="sm" fw={500}>Send as</Text>
            <SegmentedControl size="xs" data={formats.map((f) => ({ value: f.value, label: f.label }))} {...form.getInputProps('format')} />
            <Text size="xs" c="dimmed">{formats.find((f) => f.value === form.values.format)?.about}</Text>
          </Stack>
          <Stack gap={6}>
            <Text size="sm" fw={500}>Events to send</Text>
            <Chip.Group multiple value={form.values.kinds} onChange={(v) => form.setFieldValue('kinds', v)}>
              <Group gap={6}>
                {kinds.map((k) => <Chip key={k.value} value={k.value} size="xs" variant="outline">{k.label}</Chip>)}
              </Group>
            </Chip.Group>
            <Text size="xs" c="dimmed">None chosen sends every kind.</Text>
          </Stack>
          <Switch label="Only problems" description="A link or gateway down, a service stopped, a download failing, a change reverted." {...form.getInputProps('problemsOnly', { type: 'checkbox' })} />
          <Group justify="flex-end" mt="sm">
            <Button variant="default" onClick={onClose}>Cancel</Button>
            <Button type="submit">Save</Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}

// The URL and key: secrets, set now, never shown again.
function SecretModal({ hook, status, onClose, onSet }: { hook: Webhook | null; status?: WebhookStatus; onClose: () => void; onSet: () => void }) {
  const [url, setUrl] = useState('');
  const [signing, setSigning] = useState<'keep' | 'none' | 'generate' | 'set'>('generate');
  const [key, setKey] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string>();
  const [generated, setGenerated] = useState<string>();
  useEffect(() => {
    if (hook) {
      setUrl(''); setKey(''); setError(undefined); setGenerated(undefined);
      // Chat services don't check signatures.
      setSigning(status?.signed ? 'keep' : hook.format ? 'none' : 'generate');
    }
  }, [hook]); // status is read when it opens
  const save = async () => {
    setSaving(true);
    setError(undefined);
    try {
      const r = await backend.setWebhookSecret(hook!.id, { url: url.trim(), signing, key: signing === 'set' ? key : undefined });
      onSet();
      if (r.key) setGenerated(r.key);
      else onClose();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setSaving(false);
    }
  };
  return (
    <Modal opened={!!hook} onClose={onClose} size="lg" title={<Text fw={600}>{generated ? 'Your signing key' : `Where ${hook?.name ?? 'it'} sends`}</Text>}>
      {generated ? (
        <Stack>
          <Alert color="yellow" variant="light" icon={<IconAlertTriangle size={18} />} title="Shown this once">
            Give this key to the receiver so it can check each delivery came from this firewall. OPF won’t show it again; to replace it, set the URL again with a new key.
          </Alert>
          <Group gap="xs" wrap="nowrap">
            <Code block style={{ flex: 1, overflowWrap: 'anywhere', whiteSpace: 'pre-wrap' }}>{generated}</Code>
            <CopyButton value={generated}>
              {({ copied, copy }) => (
                <Tooltip label={copied ? 'Copied' : 'Copy'}>
                  <ActionIcon variant="subtle" color={copied ? 'teal' : 'gray'} onClick={copy} aria-label="Copy key">{copied ? <IconCheck size={16} /> : <IconCopy size={16} />}</ActionIcon>
                </Tooltip>
              )}
            </CopyButton>
          </Group>
          <Group justify="flex-end"><Button onClick={onClose}>Done</Button></Group>
        </Stack>
      ) : (
        <Stack>
          <Text size="sm" c="dimmed">
            The URL and key are secrets: they’re saved now, take effect at once, and only the URL’s scheme and host are shown afterwards.{status?.target ? ` It sends to ${status.target} now; a new URL replaces it.` : ''}
          </Text>
          <TextInput label="URL" placeholder={formatOf(hook).url} value={url} onChange={(e) => setUrl(e.currentTarget.value)} autoComplete="off" spellCheck={false} data-autofocus />
          {url.startsWith('http://') && <Text size="xs" c="yellow">Sent unencrypted: anyone on the way can read it. Use http only for a receiver on your own network.</Text>}
          <Stack gap={6}>
            <Text size="sm" fw={500}>Signing</Text>
            <SegmentedControl
              size="xs"
              value={signing}
              onChange={(v) => setSigning(v as typeof signing)}
              data={[
                ...(status?.signed ? [{ value: 'keep', label: 'Keep the key' }] : []),
                { value: 'generate', label: 'Make a new key' },
                { value: 'set', label: 'Use my key' },
                { value: 'none', label: 'Don’t sign' },
              ]}
            />
            {signing === 'set' && <TextInput placeholder="The key the receiver checks with" value={key} onChange={(e) => setKey(e.currentTarget.value)} autoComplete="off" spellCheck={false} />}
            <Text size="xs" c="dimmed">
              {hook?.format ? `${formatOf(hook).label} doesn’t check signatures; they matter for a receiver of your own.` : 'Signed deliveries carry X-OPF-Signature, so the receiver can tell they came from this firewall.'}
            </Text>
          </Stack>
          {error && <Alert color="red" variant="light" p="sm">{error}</Alert>}
          <Group justify="flex-end" mt="sm">
            <Button variant="default" onClick={onClose}>Cancel</Button>
            <Button onClick={save} loading={saving} disabled={!url.trim()}>Save URL</Button>
          </Group>
        </Stack>
      )}
    </Modal>
  );
}

function StatusLine({ st, applied, now }: { st?: WebhookStatus; applied: boolean; now: number }) {
  if (!st?.target) return <Text size="xs" c="yellow">No URL yet: set one to start sending.</Text>;
  const ago = (iso: string) => formatAgo((now - Date.parse(iso)) / 1000);
  return (
    <Stack gap={2}>
      <Text size="xs" c="dimmed">
        Sends to <Text span className="mono" size="xs">{st.target}</Text>{st.signed ? ', signed' : ', unsigned'}
        {!applied && ' · starts once it’s applied'}
      </Text>
      {st.lastError ? (
        <Text size="xs" c="red">Last try {st.lastAttempt ? ago(st.lastAttempt) : ''} failed: {st.lastError}{st.queued ? ` · ${st.queued} waiting to retry` : ''}</Text>
      ) : st.lastOk ? (
        <Text size="xs" c="dimmed">Delivered {ago(st.lastOk)}{st.queued ? ` · ${st.queued} waiting` : ''}</Text>
      ) : null}
      {st.dropped ? <Text size="xs" c="yellow">{st.dropped} not delivered after retrying</Text> : null}
    </Stack>
  );
}

export function Notifications() {
  const { staged, applied, edit } = useStore();
  const hooks = staged.notifications?.webhooks ?? [];
  const [status, setStatus] = useState<WebhookStatus[]>();
  const [editing, setEditing] = useState<Webhook | null>(null);
  const [secretFor, setSecretFor] = useState<Webhook | null>(null);
  const [testing, setTesting] = useState<string>();
  const now = useNow(10_000);
  const load = () => backend.webhooks().then(setStatus, () => {});
  useEffect(() => {
    load();
    const t = setInterval(load, 10_000);
    return () => clearInterval(t);
  }, [staged, applied]);

  const setHooks = (summary: string, fn: (w: Webhook[]) => Webhook[]) =>
    edit('notifications', summary, (m) => {
      const next = fn(m.notifications?.webhooks ?? []);
      return { ...m, notifications: next.length ? { webhooks: next } : undefined };
    });
  const test = async (w: Webhook) => {
    setTesting(w.id);
    try {
      const st = await backend.testWebhook(w.id);
      toast.show(st.lastError ? { color: 'red', title: `${w.name}: the test didn’t arrive`, message: st.lastError } : { color: 'teal', title: `${w.name}: test delivered`, message: `To ${st.target}.` });
    } catch (e) {
      toast.show({ color: 'red', title: `Couldn’t test ${w.name}`, message: e instanceof Error ? e.message : String(e) });
    } finally {
      setTesting(undefined);
      load();
    }
  };
  const isApplied = (id: string) => (applied.notifications?.webhooks ?? []).some((w) => w.id === id);

  return (
    <>
      <PageHeader
        title="Notifications"
        description="Send OPF’s events to other systems as they happen: Home Assistant, n8n, a chat bot, a script of your own."
        actions={<Button leftSection={<IconPlus size={16} />} onClick={() => setEditing({ id: '', name: '', enabled: true })}>Add webhook</Button>}
      />
      <Stack gap="md" maw={900}>
        <Card>
          <SectionTitle>Webhooks</SectionTitle>
          {hooks.length ? (
            <Stack gap="md">
              {hooks.map((w) => {
                const st = status?.find((s) => s.id === w.id);
                return (
                  <Group key={w.id} justify="space-between" align="flex-start" wrap="nowrap" gap="md">
                    <Group align="flex-start" wrap="nowrap" gap="sm" style={{ minWidth: 0 }}>
                      <Switch mt={2} size="xs" checked={w.enabled} aria-label={w.enabled ? 'Turn off' : 'Turn on'}
                        onChange={() => setHooks(`${w.enabled ? 'Turned off' : 'Turned on'} webhook ${w.name}`, (all) => all.map((x) => (x.id === w.id ? { ...x, enabled: !x.enabled } : x)))} />
                      <Stack gap={4} style={{ minWidth: 0 }}>
                        <Group gap="xs">
                          <Text fw={500} size="sm">{w.name}</Text>
                          <Badge size="xs" variant="light">{formatOf(w).label}</Badge>
                          <Badge size="xs" variant="light" color="gray">{w.kinds?.length ? w.kinds.map((k) => kinds.find((x) => x.value === k)?.label ?? k).join(', ') : 'Every event'}</Badge>
                          {w.problemsOnly && <Badge size="xs" variant="light" color="red">Problems only</Badge>}
                        </Group>
                        <StatusLine st={st} applied={isApplied(w.id)} now={now} />
                      </Stack>
                    </Group>
                    <Group gap={4} wrap="nowrap">
                      <Button size="compact-xs" variant="light" onClick={() => setSecretFor(w)}>{st?.target ? 'Change URL' : 'Set URL'}</Button>
                      <Button size="compact-xs" variant="subtle" leftSection={<IconSend size={13} />} disabled={!st?.target || testing === w.id} loading={testing === w.id} onClick={() => test(w)}>Test</Button>
                      <Menu position="bottom-end">
                        <Menu.Target><ActionIcon variant="subtle" color="gray" aria-label="Actions"><IconDots size={16} /></ActionIcon></Menu.Target>
                        <Menu.Dropdown>
                          <Menu.Item leftSection={<IconPencil size={16} />} onClick={() => setEditing(w)}>Edit</Menu.Item>
                          <Menu.Item leftSection={<IconTrash size={16} />} color="red" onClick={() => setHooks(`Removed webhook ${w.name}`, (all) => all.filter((x) => x.id !== w.id))}>Remove</Menu.Item>
                        </Menu.Dropdown>
                      </Menu>
                    </Group>
                  </Group>
                );
              })}
            </Stack>
          ) : (
            <Empty>No webhooks. Add one to send events somewhere.</Empty>
          )}
        </Card>
        <Accordion variant="contained" radius="md">
          <Accordion.Item value="format">
            <Accordion.Control><Text size="sm">What a delivery looks like</Text></Accordion.Control>
            <Accordion.Panel>
              <Stack gap="sm">
                <Text size="sm">Slack and Discord get a one-line message, and ntfy a notification titled with the firewall and the kind of event. JSON is a POST with this body:</Text>
                <Code block>{`{
  "source": "opf",
  "host": "${applied.system.hostname}.${applied.system.domain}",
  "event": {
    "time": "2026-09-30T14:02:11Z",
    "kind": "gateway",
    "warning": true,
    "subject": "gw_wan",
    "message": "Gateway WAN_DHCP stopped answering (9.9.9.9)"
  }
}`}</Code>
                <Text size="sm">
                  With the headers <Code>X-OPF-Timestamp</Code> (unix seconds) and, when it has a key, <Code>X-OPF-Signature: sha256=…</Code>: the hex HMAC-SHA256 of <Code>{'<timestamp>.<body>'}</Code> with the key. The receiver should compute it and compare, and refuse a timestamp more than a few minutes old. A test has <Code>"test": true</Code>. A delivery that fails is tried again after 10 seconds, a minute, 5 minutes, 30 minutes and 2 hours, then dropped. Redirects aren’t followed.
                </Text>
              </Stack>
            </Accordion.Panel>
          </Accordion.Item>
        </Accordion>
      </Stack>
      <EditModal
        hook={editing}
        onClose={() => setEditing(null)}
        onSave={(v) => {
          if (editing?.id) setHooks(`Edited webhook ${v.name}`, (all) => all.map((x) => (x.id === editing.id ? { ...v, id: x.id } : x)));
          else setHooks(`Added webhook ${v.name}`, (all) => [...all, { ...v, id: hookId(v.name, staged) }]);
        }}
      />
      <SecretModal hook={secretFor} status={status?.find((s) => s.id === secretFor?.id)} onClose={() => setSecretFor(null)} onSet={load} />
    </>
  );
}
