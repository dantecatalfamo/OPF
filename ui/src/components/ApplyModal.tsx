import { useEffect, useState } from 'react';
import { Accordion, Alert, Badge, Button, Code, Group, List, Loader, Modal, Stack, Tabs, Text, ThemeIcon } from '@mantine/core';
import { IconAlertTriangle, IconFileCode } from '@tabler/icons-react';
import { useStore, type Review } from '../model/store';
import type { Section } from '../model/types';
import { ApiError } from '../lib/api';
import { sectionLabel } from '../lib/sections';
import { sectionIcon } from '../lib/sectionIcons';
import { UnifiedDiff } from './UnifiedDiff';
import { ResolverReloadNotice } from '../pages/DnsActivity';

const order: Section[] = ['system', 'interfaces', 'routing', 'firewall', 'dhcp', 'dns', 'wireguard', 'notifications'];

function ChangeList() {
  const { changes } = useStore();
  const bySection = order
    .map((s) => ({ section: s, items: changes.filter((c) => c.section === s) }))
    .filter((g) => g.items.length);
  return (
    <Stack gap="md">
      {bySection.map(({ section, items }) => {
        const Icon = sectionIcon[section];
        return (
          <Group key={section} align="flex-start" wrap="nowrap" gap="md">
            <ThemeIcon variant="light" size={34} radius="md">
              <Icon size={18} />
            </ThemeIcon>
            <Stack gap={4} style={{ flex: 1 }}>
              <Text fw={600} size="sm">{sectionLabel[section]}</Text>
              {items.map((c, i) => (
                <Text key={`${c.id}-${i}`} size="sm">{c.summary}</Text>
              ))}
            </Stack>
          </Group>
        );
      })}
    </Stack>
  );
}

function Files({ review }: { review: Review }) {
  const files = review.files.filter((f) => !f.model);
  if (!files.length) return null;
  return (
    <Accordion variant="contained" radius="md" chevronPosition="left">
      <Accordion.Item value="files">
        <Accordion.Control icon={<IconFileCode size={18} />}>
          <Text size="sm">
            Show the OpenBSD files this writes{' '}
            <Text span c="dimmed" size="sm">({files.length})</Text>
          </Text>
        </Accordion.Control>
        <Accordion.Panel>
          <Tabs defaultValue={files[0].path} variant="pills" radius="sm">
            <Tabs.List mb="sm">
              {files.map((f) => (
                <Tabs.Tab key={f.path} value={f.path} className="mono" fz="xs">
                  {f.path}
                  {f.status === 'added' && <Badge size="xs" ml={6} color="teal">new</Badge>}
                  {f.status === 'removed' && <Badge size="xs" ml={6} color="red">removed</Badge>}
                </Tabs.Tab>
              ))}
            </Tabs.List>
            {files.map((f) => (
              <Tabs.Panel key={f.path} value={f.path}>
                <UnifiedDiff diff={f.diff} />
              </Tabs.Panel>
            ))}
          </Tabs>
        </Accordion.Panel>
      </Accordion.Item>
    </Accordion>
  );
}

// What the server objected to, in a form someone can act on.
function Problem({ error, onOverwrite }: { error: unknown; onOverwrite: (paths: string[]) => void }) {
  if (!(error instanceof ApiError)) {
    return <Alert color="red" title="Something went wrong">{String(error)}</Alert>;
  }
  const titles: Partial<Record<ApiError['code'], string>> = {
    invalid: 'Some settings aren’t valid',
    check_failed: 'OpenBSD rejected the new configuration',
    modified_outside: 'Files were changed outside OPF',
    conflict: 'The configuration changed in the meantime',
    commit_pending: 'Another commit is waiting for confirmation',
    unsupported: 'OPF can’t make this change yet',
  };
  return (
    <Alert color="red" variant="light" icon={<IconAlertTriangle size={18} />} title={titles[error.code] ?? 'The change was refused'}>
      <Stack gap="xs">
        <Text size="sm">{error.message}</Text>
        {error.details.length > 0 && error.code !== 'check_failed' && (
          <List size="sm" spacing={2}>
            {error.details.map((d, i) => (
              <List.Item key={i}>
                <Text span className="mono" size="xs">{d.path}</Text>
                {d.message && error.code !== 'modified_outside' && <Text span size="sm">: {d.message}</Text>}
              </List.Item>
            ))}
          </List>
        )}
        {error.code === 'check_failed' && error.details.map((d, i) => (
          <Code key={i} block style={{ whiteSpace: 'pre-wrap' }}>{d.output || d.path}</Code>
        ))}
        {error.code === 'modified_outside' && (
          <Group>
            <Button size="xs" color="red" variant="light" onClick={() => onOverwrite(error.details.map((d) => d.path))}>
              Replace them with OPF’s versions
            </Button>
          </Group>
        )}
      </Stack>
    </Alert>
  );
}

export function ApplyModal({ opened, onClose }: { opened: boolean; onClose: () => void }) {
  const { changes, review, apply, discard, staged: stagedModel } = useStore();
  const [staging, setStaging] = useState(false);
  const [applying, setApplying] = useState(false);
  const [staged, setStaged] = useState<Review | null>(null);
  const [error, setError] = useState<unknown>(null);

  const stage = async (overwrite?: string[]) => {
    setStaging(true);
    setError(null);
    setStaged(null);
    try {
      setStaged(await review(overwrite));
    } catch (e) {
      setError(e);
    } finally {
      setStaging(false);
    }
  };

  useEffect(() => {
    if (opened && changes.length) stage();
    if (!opened) {
      setStaged(null);
      setError(null);
    }
  }, [opened]); // stage only when the dialog opens

  const start = async () => {
    if (!staged) return;
    setApplying(true);
    setError(null);
    try {
      await apply(staged);
      onClose();
    } catch (e) {
      setError(e);
    } finally {
      setApplying(false);
    }
  };

  const busy = staging || applying;
  return (
    <Modal
      opened={opened}
      onClose={applying ? () => {} : onClose}
      withCloseButton={!applying}
      closeOnClickOutside={!applying}
      size="xl"
      title={
        <Group gap="sm">
          <Text fw={600} size="lg">{applying ? 'Applying changes' : 'Review changes'}</Text>
          {!applying && <Badge color="amber" c="dark.9" variant="filled">{changes.length}</Badge>}
        </Group>
      }
    >
      {changes.length === 0 ? (
        <Text c="dimmed">Everything is applied. Changes you make will show up here for review first.</Text>
      ) : (
        <Stack gap="lg">
          <ChangeList />
          {staging && (
            <Group gap="sm"><Loader size="sm" /><Text size="sm" c="dimmed">Checking the changes…</Text></Group>
          )}
          {error !== null && <Problem error={error} onOverwrite={(paths) => stage(paths)} />}
          {staged?.needsConfirm && (
            <Alert color="yellow" variant="light" icon={<IconAlertTriangle size={18} />} title="You’ll be asked to confirm">
              These changes affect how devices reach OPF. After applying, confirm you can still use this page before
              the time runs out, or the previous settings come back on their own.
            </Alert>
          )}
          {staged?.files.some((f) => f.path === '/var/unbound/etc/unbound.conf') && <ResolverReloadNotice model={stagedModel} />}
          {staged && <Files review={staged} />}
          {applying && (
            <Group gap="sm"><Loader size="sm" /><Text size="sm">Checking, saving a restore point and applying…</Text></Group>
          )}
          <Group justify="space-between">
            <Button
              variant="subtle"
              color="red"
              disabled={busy}
              onClick={async () => {
                try {
                  await discard();
                  onClose();
                } catch (e) {
                  setError(e);
                }
              }}
            >
              Discard changes
            </Button>
            <Group gap="sm">
              <Button variant="default" onClick={onClose} disabled={applying}>Keep editing</Button>
              <Button onClick={start} loading={applying} disabled={!staged || staging}>Apply changes</Button>
            </Group>
          </Group>
        </Stack>
      )}
    </Modal>
  );
}
