import { useEffect, useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router';
import { Anchor, Box, Button, Card, CopyButton, Drawer, Group, Stack, Text, Textarea, TextInput } from '@mantine/core';
import { useForm } from '@mantine/form';
import { IconCheck, IconCopy, IconPencil, IconSearch } from '@tabler/icons-react';
import { useStore } from '../model/store';
import { pfRuleset } from '../model/generate';
import type { CustomPf } from '../model/types';
import { checkPfLine } from '../lib/pfcheck';
import { PageHeader } from '../components/ui';

function checkBlock(text: string): string | null {
  const lines = text.split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#'));
  for (const [i, l] of lines.entries()) {
    const err = checkPfLine(l);
    if (err) return `Line ${i + 1}: ${err}`;
  }
  return null;
}

function CustomDrawer({ opened, onClose }: { opened: boolean; onClose: () => void }) {
  const { staged, edit } = useStore();
  const form = useForm<CustomPf>({
    initialValues: staged.firewall.custom,
    validate: { options: checkBlock, beforeFilter: checkBlock, afterFilter: checkBlock },
  });
  useEffect(() => {
    if (opened) form.setValues(staged.firewall.custom);
  }, [opened, staged.firewall.custom]); // form is stable
  const mono = { input: { fontFamily: 'var(--mantine-font-family-monospace)', fontSize: 12 } };
  return (
    <Drawer opened={opened} onClose={onClose} size="xl" title={<Text fw={600} size="lg">Custom pf</Text>}>
      <form
        onSubmit={form.onSubmit((v) => {
          edit('firewall', 'Edited custom pf rules', (m) => ({ ...m, firewall: { ...m.firewall, custom: v } }));
          onClose();
        })}
      >
        <Stack>
          <Text size="sm" c="dimmed">
            Anything pf.conf(5) supports, placed at fixed points in the generated ruleset. Interface macros ($wan, $lan…) and alias tables are available. OPF checks the whole ruleset with pfctl before applying.
          </Text>
          <Textarea label="Options" description="After the generated set lines. For set, queue or anchor definitions." autosize minRows={3} styles={mono} {...form.getInputProps('options')} />
          <Textarea label="Before the filter rules" description="Checked before floating and interface rules." autosize minRows={4} styles={mono} {...form.getInputProps('beforeFilter')} />
          <Textarea label="After the filter rules" description="At the very end of the ruleset." autosize minRows={3} styles={mono} {...form.getInputProps('afterFilter')} />
          <Group justify="flex-end">
            <Button variant="default" onClick={onClose}>Cancel</Button>
            <Button type="submit">Save</Button>
          </Group>
        </Stack>
      </form>
    </Drawer>
  );
}

export function Ruleset() {
  const { staged, pendingSections } = useStore();
  const lines = useMemo(() => pfRuleset(staged), [staged]);
  const [q, setQ] = useState('');
  // ?edit=custom, from a custom pf line's link, opens the editor.
  const [params, setParams] = useSearchParams();
  const editing = params.get('edit') === 'custom';
  const setEditing = (open: boolean) =>
    setParams((p) => {
      const next = new URLSearchParams(p);
      if (open) next.set('edit', 'custom');
      else next.delete('edit');
      return next;
    });
  const text = lines.map((l) => l.text).join('\n');
  const shown = lines.map((l, i) => ({ ...l, n: i + 1 })).filter((l) => !q || l.text.toLowerCase().includes(q.toLowerCase()) || l.origin?.label.toLowerCase().includes(q.toLowerCase()));

  return (
    <>
      <PageHeader
        title="Ruleset"
        description={
          <>
            The complete <Text span className="mono" size="sm">/etc/pf.conf</Text> OPF generates{pendingSections.includes('firewall') ? ', including changes not yet applied' : ''}. Every line links to the setting that produced it.
          </>
        }
        actions={
          <>
            <CopyButton value={text}>
              {({ copied, copy }) => (
                <Button variant="default" leftSection={copied ? <IconCheck size={16} /> : <IconCopy size={16} />} onClick={copy}>{copied ? 'Copied' : 'Copy'}</Button>
              )}
            </CopyButton>
            <Button leftSection={<IconPencil size={16} />} onClick={() => setEditing(true)}>Custom pf</Button>
          </>
        }
      />
      <TextInput placeholder="Search rules" leftSection={<IconSearch size={16} />} value={q} onChange={(e) => setQ(e.currentTarget.value)} mb="md" maw={420} />
      <Card padding={0}>
        <Box style={{ overflowX: 'auto' }}>
          <Box className="mono" fz={12} lh={1.7} py="sm" style={{ minWidth: 760 }}>
            {shown.map((l) => (
              <Group key={l.n} gap={0} wrap="nowrap" align="flex-start" className="ruleset-line">
                <Text span c="dimmed" fz={12} w={48} ta="right" pr="md" style={{ flex: 'none', userSelect: 'none' }} className="num">{l.n}</Text>
                <Text span fz={12} c={l.text.startsWith('#') ? 'dimmed' : undefined} style={{ flex: 1, whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
                  {l.text || ' '}
                </Text>
                {l.origin && (
                  <Anchor component={Link} to={l.origin.to} fz={11} c="dimmed" px="md" style={{ flex: 'none', maxWidth: 260, fontFamily: 'var(--mantine-font-family)' }} truncate="end" className="ruleset-origin">
                    {l.origin.label}
                  </Anchor>
                )}
              </Group>
            ))}
          </Box>
        </Box>
      </Card>
      <CustomDrawer opened={editing} onClose={() => setEditing(false)} />
    </>
  );
}
