// DNS resolver › Tools: asking unbound itself. Where it would look a
// name up and what it has cached for it; its local names; and making it
// forget cached answers, after saying what that does.
import { useState } from 'react';
import { Alert, Button, Card, Code, Grid, Group, Modal, Stack, Text, TextInput } from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { backend } from '../model/store';
import type { DnsToolName, DnsToolResult } from '../lib/api';
import { SectionTitle } from '../components/ui';

const nameRE = /^([A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.)*[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.?$/;

function Output({ result, empty }: { result?: DnsToolResult; empty: string }) {
  if (!result) return null;
  return result.lines.length ? (
    <>
      <Code block style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', maxHeight: 420, overflow: 'auto' }}>{result.lines.join('\n')}</Code>
      {result.truncated && <Text size="xs" c="dimmed">Only the first 1,000 lines.</Text>}
    </>
  ) : <Text size="sm" c="dimmed">{empty}</Text>;
}

const flushes: { tool: DnsToolName; label: string; needsName: boolean; what: (n: string) => string }[] = [
  { tool: 'flush', label: 'Forget this name', needsName: true, what: (n) => `unbound forgets what it has cached for ${n}, and asks again the next time a device looks it up.` },
  { tool: 'flush_zone', label: 'Forget everything under it', needsName: true, what: (n) => `unbound forgets ${n} and every name under it (www.${n} and the rest), and asks again as each is looked up.` },
  { tool: 'flush_bogus', label: 'Forget failed DNSSEC answers', needsName: false, what: () => 'unbound forgets every answer that failed DNSSEC validation, so it checks those names again: after a domain fixes its signatures, say.' },
  { tool: 'flush_negative', label: 'Forget “no such name” answers', needsName: false, what: () => 'unbound forgets every “no such name” and empty answer, so a name that has just been created is found at once.' },
];

export function DnsTools() {
  const [name, setName] = useState('');
  const [busy, setBusy] = useState<DnsToolName>();
  const [error, setError] = useState<string>();
  const [lookup, setLookup] = useState<{ tool: DnsToolName; result: DnsToolResult }>();
  const [local, setLocal] = useState<DnsToolResult>();
  const [confirm, setConfirm] = useState<(typeof flushes)[number] | null>(null);
  const n = name.trim().replace(/\.$/, '');
  const valid = nameRE.test(n) && n.length <= 253;

  const run = async (tool: DnsToolName) => {
    setBusy(tool);
    setError(undefined);
    try {
      const r = await backend.dnsTool(tool, flushes.find((f) => f.tool === tool)?.needsName === false || tool === 'local' ? undefined : n);
      if (tool === 'local') setLocal(r);
      else if (tool === 'lookup' || tool === 'cache') setLookup({ tool, result: r });
      else notifications.show({ color: 'teal', title: flushes.find((f) => f.tool === tool)?.label, message: r.lines.join(' ') || 'Done.' });
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(undefined);
    }
  };

  return (
    <Grid gutter="md">
      <Grid.Col span={{ base: 12, lg: 7 }}>
        <Stack gap="md">
          <Card>
            <SectionTitle>A name</SectionTitle>
            <Stack gap="sm">
              <TextInput placeholder="example.com" value={name} onChange={(e) => setName(e.currentTarget.value)} error={name && !valid ? 'Enter a name like example.com' : undefined} maw={420} spellCheck={false} autoComplete="off" />
              <Group gap="xs">
                <Button size="xs" variant="light" disabled={!valid} loading={busy === 'cache'} onClick={() => run('cache')}>What it has cached</Button>
                <Button size="xs" variant="light" disabled={!valid} loading={busy === 'lookup'} onClick={() => run('lookup')}>Where it would ask</Button>
                <Button size="xs" variant="subtle" color="red" disabled={!valid} onClick={() => setConfirm(flushes[0])}>Forget this name</Button>
                <Button size="xs" variant="subtle" color="red" disabled={!valid} onClick={() => setConfirm(flushes[1])}>Forget everything under it</Button>
              </Group>
              {error && <Alert color="red" variant="light" p="sm">{error}</Alert>}
              {lookup && (
                <>
                  <Text size="sm" c="dimmed">{lookup.tool === 'cache' ? 'What unbound has cached for the name and those under it, with each record’s seconds left:' : 'The servers unbound would ask, and how quickly each has answered:'}</Text>
                  <Output result={lookup.result} empty="Nothing cached for this name: the next lookup asks the internet." />
                </>
              )}
              <Text size="xs" c="dimmed">To see the answer a device gets, use Monitoring › Tools › DNS lookup.</Text>
            </Stack>
          </Card>
          <Card>
            <SectionTitle right={<Button size="xs" variant="light" loading={busy === 'local'} onClick={() => run('local')}>{local ? 'Show again' : 'Show'}</Button>}>Local names</SectionTitle>
            <Text size="sm" c="dimmed" mb="sm">The zones and records unbound answers itself: host names, reserved and DHCP devices’ names.</Text>
            <Output result={local} empty="None." />
          </Card>
        </Stack>
      </Grid.Col>
      <Grid.Col span={{ base: 12, lg: 5 }}>
        <Card>
          <SectionTitle>Cached answers</SectionTitle>
          <Stack gap="sm">
            <Text size="sm" c="dimmed">unbound keeps answers until they expire. Making it forget some helps after a name changed somewhere else, or a domain fixed its DNSSEC.</Text>
            {flushes.slice(2).map((f) => (
              <Group key={f.tool} justify="space-between" wrap="nowrap">
                <Text size="sm">{f.label}</Text>
                <Button size="xs" variant="subtle" color="red" onClick={() => setConfirm(f)}>Forget</Button>
              </Group>
            ))}
          </Stack>
        </Card>
      </Grid.Col>
      <Modal opened={!!confirm} onClose={() => setConfirm(null)} title={<Text fw={600}>{confirm?.label}</Text>}>
        <Stack>
          <Text size="sm">{confirm?.what(n)}</Text>
          <Text size="xs" c="dimmed">Nothing else changes, and it isn’t recorded as a change: the next lookups just take a little longer.</Text>
          <Group justify="flex-end">
            <Button variant="default" onClick={() => setConfirm(null)}>Cancel</Button>
            <Button color="red" loading={!!confirm && busy === confirm.tool} onClick={async () => { const c = confirm!; await run(c.tool); setConfirm(null); }}>{confirm?.label}</Button>
          </Group>
        </Stack>
      </Modal>
    </Grid>
  );
}
