import { useEffect, useMemo, useState } from 'react';
import {
  Accordion, Alert, Badge, Button, Group, Loader, Modal, Stack, Tabs, Text, ThemeIcon,
} from '@mantine/core';
import { IconAlertTriangle, IconCheck, IconFileCode } from '@tabler/icons-react';
import { useStore } from '../model/store';
import type { Section } from '../model/types';
import { sectionLabel } from '../lib/sections';
import { sectionIcon } from '../lib/sectionIcons';
import { FileDiff } from './FileDiff';
import { previewModel, type GeneratedFile } from '../lib/api';

const applyStep: Record<Section, string> = {
  system: 'Updating system settings',
  interfaces: 'Reconfiguring network interfaces',
  routing: 'Updating routes',
  firewall: 'Loading firewall rules',
  dhcp: 'Restarting the DHCP server',
  dns: 'Reloading the DNS resolver',
  wireguard: 'Updating the WireGuard tunnel',
};

const order: Section[] = ['system', 'interfaces', 'routing', 'firewall', 'dhcp', 'dns', 'wireguard'];

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
              <Text fw={600} size="sm">
                {sectionLabel[section]}
              </Text>
              {items.map((c, i) => (
                <Text key={`${c.id}-${i}`} size="sm">
                  {c.summary}
                </Text>
              ))}
            </Stack>
          </Group>
        );
      })}
    </Stack>
  );
}

interface FileDiffItem {
  path: string;
  before: string;
  after: string;
}

function GeneratedFiles() {
  const { applied, staged } = useStore();
  const [files, setFiles] = useState<FileDiffItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    async function fetchFiles() {
      setLoading(true);
      setError(null);
      try {
        // Fetch generated files for both applied and staged models from backend
        const [appliedResult, stagedResult] = await Promise.all([
          previewModel(applied),
          previewModel(staged),
        ]);

        if (cancelled) return;

        if (appliedResult.error || stagedResult.error) {
          setError(appliedResult.error || stagedResult.error || 'Unknown error');
          return;
        }

        const before = new Map(appliedResult.files.map((f: GeneratedFile) => [f.path, f.content]));
        const diffs = stagedResult.files
          .map((f: GeneratedFile) => ({ path: f.path, before: before.get(f.path) ?? '', after: f.content }))
          .filter((f: FileDiffItem) => f.before !== f.after);

        setFiles(diffs);
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : 'Failed to fetch generated files');
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }
    fetchFiles();
    return () => { cancelled = true; };
  }, [applied, staged]);

  if (loading) {
    return (
      <Group gap="sm" py="sm">
        <Loader size="sm" />
        <Text size="sm" c="dimmed">Loading generated files...</Text>
      </Group>
    );
  }

  if (error) {
    return (
      <Alert color="red" variant="light">
        <Text size="sm">Failed to preview files: {error}</Text>
      </Alert>
    );
  }

  if (!files.length) return null;

  return (
    <Accordion variant="contained" radius="md" chevronPosition="left">
      <Accordion.Item value="files">
        <Accordion.Control icon={<IconFileCode size={18} />}>
          <Text size="sm">
            Show the OpenBSD files this writes{' '}
            <Text span c="dimmed" size="sm">
              ({files.length})
            </Text>
          </Text>
        </Accordion.Control>
        <Accordion.Panel>
          <Tabs defaultValue={files[0].path} variant="pills" radius="sm">
            <Tabs.List mb="sm">
              {files.map((f) => (
                <Tabs.Tab key={f.path} value={f.path} className="mono" fz="xs">
                  {f.path}
                </Tabs.Tab>
              ))}
            </Tabs.List>
            {files.map((f) => (
              <Tabs.Panel key={f.path} value={f.path}>
                <FileDiff before={f.before} after={f.after} />
              </Tabs.Panel>
            ))}
          </Tabs>
        </Accordion.Panel>
      </Accordion.Item>
    </Accordion>
  );
}

function Progress({ steps, done }: { steps: string[]; done: number }) {
  return (
    <Stack gap="sm" py="md">
      {steps.map((s, i) => (
        <Group key={s} gap="sm">
          {i < done ? (
            <ThemeIcon size={22} radius="xl" color="teal">
              <IconCheck size={14} />
            </ThemeIcon>
          ) : i === done ? (
            <Loader size={22} />
          ) : (
            <ThemeIcon size={22} radius="xl" variant="default">
              <span />
            </ThemeIcon>
          )}
          <Text size="sm" c={i > done ? 'dimmed' : undefined}>
            {s}
          </Text>
        </Group>
      ))}
    </Stack>
  );
}

export function ApplyModal({ opened, onClose }: { opened: boolean; onClose: () => void }) {
  const { changes, pendingSections, needsConfirm, apply, discard } = useStore();
  const [applying, setApplying] = useState(false);
  const [done, setDone] = useState(0);

  const steps = useMemo(
    () => ['Checking the new configuration', 'Saving a restore point', ...order.filter((s) => pendingSections.includes(s)).map((s) => applyStep[s])],
    [pendingSections],
  );

  useEffect(() => {
    if (!applying) return;
    if (done >= steps.length) {
      apply();
      setApplying(false);
      onClose();
      return;
    }
    const t = setTimeout(() => setDone((d) => d + 1), 550);
    return () => clearTimeout(t);
  }, [applying, done, steps.length, apply, onClose]);

  const start = () => {
    setDone(0);
    setApplying(true);
  };

  return (
    <Modal
      opened={opened}
      onClose={applying ? () => {} : onClose}
      withCloseButton={!applying}
      closeOnClickOutside={!applying}
      size="xl"
      title={
        <Group gap="sm">
          <Text fw={600} size="lg">
            {applying ? 'Applying changes' : 'Review changes'}
          </Text>
          {!applying && <Badge color="amber" c="dark.9" variant="filled">{changes.length}</Badge>}
        </Group>
      }
    >
      {applying ? (
        <Progress steps={steps} done={done} />
      ) : changes.length === 0 ? (
        <Text c="dimmed">Everything is applied. Changes you make will show up here for review first.</Text>
      ) : (
        <Stack gap="lg">
          <ChangeList />
          {needsConfirm && (
            <Alert color="yellow" variant="light" icon={<IconAlertTriangle size={18} />} title="You’ll be asked to confirm">
              These changes affect how devices reach OPF. After applying, you have 60 seconds to confirm you can still
              use this page. If you don’t, the previous settings come back on their own.
            </Alert>
          )}
          <GeneratedFiles />
          <Group justify="space-between">
            <Button
              variant="subtle"
              color="red"
              onClick={() => {
                discard();
                onClose();
              }}
            >
              Discard changes
            </Button>
            <Group gap="sm">
              <Button variant="default" onClick={onClose}>
                Keep editing
              </Button>
              <Button onClick={start}>Apply changes</Button>
            </Group>
          </Group>
        </Stack>
      )}
    </Modal>
  );
}
