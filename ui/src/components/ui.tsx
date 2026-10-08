import type { ReactNode } from 'react';
import { Badge, Box, Group, Stack, Text, Title } from '@mantine/core';
import type { RuleAction } from '../model/types';

export function PageHeader({ title, description, actions }: { title: string; description?: ReactNode; actions?: ReactNode }) {
  return (
    <Group justify="space-between" align="flex-end" mb="xl" gap="md">
      <Stack gap={4} style={{ flex: '1 1 320px' }}>
        <Title order={2} fz={26} style={{ textWrap: 'balance' }}>
          {title}
        </Title>
        {description && (
          <Text c="dimmed" size="sm" maw={680}>
            {description}
          </Text>
        )}
      </Stack>
      {actions && <Group gap="sm">{actions}</Group>}
    </Group>
  );
}

export function StatusDot({ ok, label }: { ok: boolean | 'warn'; label: ReactNode }) {
  const color = ok === 'warn' ? 'yellow' : ok ? 'teal' : 'red';
  return (
    <Group gap={8} wrap="nowrap">
      <Box w={8} h={8} style={{ borderRadius: 8, background: `var(--mantine-color-${color}-6)`, flex: 'none' }} />
      <Text size="sm">{label}</Text>
    </Group>
  );
}

const actionColor: Record<RuleAction, string> = { pass: 'teal', block: 'red', reject: 'orange', match: 'harbor' };
const actionLabel: Record<RuleAction, string> = { pass: 'Allow', block: 'Block', reject: 'Reject', match: 'Match' };

export function ActionBadge({ action, muted }: { action: RuleAction; muted?: boolean }) {
  return (
    <Badge color={muted ? 'gray' : actionColor[action]} w={80}>
      {actionLabel[action]}
    </Badge>
  );
}

export function Mono({ children, c }: { children: ReactNode; c?: string }) {
  return (
    <Text span className="mono" c={c} size="sm">
      {children}
    </Text>
  );
}

export function SectionTitle({ children, right }: { children: ReactNode; right?: ReactNode }) {
  return (
    <Group justify="space-between" mb="md" gap="sm">
      <Text fw={600}>{children}</Text>
      {right}
    </Group>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return (
    <Text c="dimmed" size="sm" ta="center" py="xl">
      {children}
    </Text>
  );
}
