import { Badge, Button, Card, Group, Stack, Text, ThemeIcon, Timeline } from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { IconArrowBackUp, IconCheck, IconDownload, IconUpload, IconX } from '@tabler/icons-react';
import { useStore } from '../model/store';
import type { HistoryEntry } from '../model/types';
import { sectionLabel } from '../lib/sections';
import { PageHeader, SectionTitle } from '../components/ui';

const statusBadge: Record<HistoryEntry['status'], { color: string; label: string }> = {
  confirmed: { color: 'teal', label: 'Confirmed' },
  applied: { color: 'teal', label: 'Applied' },
  pending: { color: 'amber', label: 'Waiting for confirmation' },
  applying: { color: 'amber', label: 'Applying' },
  reverted: { color: 'red', label: 'Reverted' },
  failed: { color: 'red', label: 'Failed and reverted' },
};

const preview = () =>
  notifications.show({ title: 'Not available in this preview', message: 'On the appliance this saves or loads a single backup file.' });

export function History() {
  const { history, restore, confirming } = useStore();
  return (
    <>
      <PageHeader
        title="Change history"
        description="Every applied change is kept, with a restore point from just before it. Restoring stages the old settings so you can review them first."
      />
      <Group align="flex-start" gap="md" wrap="wrap">
        <Card style={{ flex: '2 1 480px' }}>
          <Timeline bulletSize={26} lineWidth={2}>
            {history.map((h) => {
              const s = statusBadge[h.status];
              return (
                <Timeline.Item
                  key={h.id}
                  bullet={
                    <ThemeIcon size={26} radius="xl" color={s.color} variant="light">
                      {h.status === 'reverted' || h.status === 'failed' ? <IconX size={14} /> : <IconCheck size={14} />}
                    </ThemeIcon>
                  }
                >
                  <Group justify="space-between" align="flex-start" wrap="nowrap" gap="md">
                    <Stack gap={4}>
                      <Group gap="xs">
                        <Text size="sm" fw={600}>
                          {new Date(h.time).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' })}
                        </Text>
                        <Badge color={s.color} size="sm">{s.label}</Badge>
                        {h.author && <Text size="xs" c="dimmed">by {h.author}</Text>}
                      </Group>
                      {h.message && !(h.changes.length === 1 && h.changes[0].summary === h.message) && (
                        <Text size="sm" fw={500}>{h.message}</Text>
                      )}
                      {h.changes.map((c, i) => (
                        <Text key={`${c.id}-${i}`} size="sm">
                          <Text span c="dimmed" size="sm">{sectionLabel[c.section]}: </Text>
                          {c.summary}
                        </Text>
                      ))}
                    </Stack>
                    {(h.status === 'applied' || h.status === 'confirmed') && (
                      <Button size="xs" variant="default" leftSection={<IconArrowBackUp size={14} />} disabled={!!confirming} onClick={() => restore(h)}>
                        Undo
                      </Button>
                    )}
                  </Group>
                </Timeline.Item>
              );
            })}
          </Timeline>
        </Card>
        <Card style={{ flex: '1 1 260px' }}>
          <SectionTitle>Backup</SectionTitle>
          <Stack gap="sm">
            <Text size="sm" c="dimmed">All settings live in one file. Keep a copy somewhere safe, or use it to set up a replacement.</Text>
            <Button variant="light" leftSection={<IconDownload size={16} />} onClick={preview}>Download backup</Button>
            <Button variant="default" leftSection={<IconUpload size={16} />} onClick={preview}>Restore from backup</Button>
          </Stack>
        </Card>
      </Group>
    </>
  );
}
