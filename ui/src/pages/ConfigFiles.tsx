// System › Configuration files: every file the configuration
// manages, as it is on the firewall, with the staged change to it and
// anything changed outside OPF. The other pages link here for their own
// files (?file=); pf.conf is richer under Firewall › Ruleset.
import { useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router';
import { Alert, Anchor, Badge, Card, CopyButton, Grid, Group, NavLink, ScrollArea, Stack, Tabs, Text, Tooltip, ActionIcon } from '@mantine/core';
import { IconCheck, IconCopy } from '@tabler/icons-react';
import { backend, useStore } from '../model/store';
import type { ConfigFile, ConfigFileView } from '../lib/api';
import { Mono, PageHeader, SectionTitle } from '../components/ui';
import { UnifiedDiff } from '../components/UnifiedDiff';

/** A link to a file on this page, for the pages it belongs to. */
export function FileLink({ path, label }: { path: string; label?: string }) {
  return (
    <Anchor component={Link} to={`/system/files?file=${encodeURIComponent(path)}`} size="xs">
      {label ?? `Show ${path.split('/').pop()}`}
    </Anchor>
  );
}

// What a file is for, where the registry doesn't say (the preview).
const fallbackDesc = (f: ConfigFile) => f.desc || (f.path.startsWith('/etc/hostname.') ? 'Network interface' : 'Configuration');

function Badges({ f }: { f: ConfigFile }) {
  return (
    <>
      {f.staged && <Badge size="xs" color="amber" c="dark.9">{f.staged === 'added' ? 'new, staged' : f.staged === 'removed' ? 'removal staged' : 'change staged'}</Badge>}
      {f.outside && <Badge size="xs" color="red" variant="light">changed outside OPF</Badge>}
      {!f.exists && !f.staged && <Badge size="xs" color="gray" variant="light">missing</Badge>}
    </>
  );
}

function FileView({ path, changes }: { path: string; changes: number }) {
  const [view, setView] = useState<ConfigFileView>();
  const [error, setError] = useState<string>();
  const [tab, setTab] = useState<string | null>('now');
  useEffect(() => {
    let live = true;
    setError(undefined);
    backend.file(path).then((v) => {
      if (!live) return;
      setView(v);
      setTab((t) => (t === 'staged' && !v.stagedDiff) || (t === 'outside' && !v.outsideDiff) ? 'now' : t);
    }, (e) => live && setError(e instanceof Error ? e.message : String(e)));
    return () => { live = false; };
  }, [path, changes]);
  if (error) return <Alert color="red" variant="light">{error}</Alert>;
  if (!view || view.path !== path) return <Text size="sm" c="dimmed">Reading {path}…</Text>;
  const lines = view.content.replace(/\n$/, '').split('\n');
  return (
    <Stack gap="sm">
      <Group justify="space-between" align="flex-start" wrap="nowrap">
        <Stack gap={2}>
          <Group gap="xs"><Text span className="mono" size="sm" fw={600}>{view.path}</Text><Badges f={view} /></Group>
          <Text size="xs" c="dimmed">
            {fallbackDesc(view)}
            {view.commit && <> · last written by <Anchor component={Link} to="/system/history" size="xs">{view.commit.message}</Anchor>, {new Date(view.commit.time).toLocaleString()}</>}
          </Text>
        </Stack>
        <CopyButton value={view.content}>
          {({ copied, copy }) => (
            <Tooltip label={copied ? 'Copied' : 'Copy the file'}>
              <ActionIcon variant="subtle" color="gray" onClick={copy} aria-label="Copy the file">{copied ? <IconCheck size={16} /> : <IconCopy size={16} />}</ActionIcon>
            </Tooltip>
          )}
        </CopyButton>
      </Group>
      {view.path === '/etc/pf.conf' && (
        <Text size="xs" c="dimmed">
          <Anchor component={Link} to="/firewall/ruleset" size="xs">Firewall › Ruleset</Anchor> shows these rules with what made each one.
        </Text>
      )}
      {view.outside && (
        <Alert color="red" variant="light" p="xs">
          <Text size="xs">
            Someone changed this file outside OPF. The next change that writes it asks before replacing it; until then the firewall uses it as it is.
          </Text>
        </Alert>
      )}
      <Tabs value={tab} onChange={setTab} variant="outline">
        <Tabs.List>
          <Tabs.Tab value="now">On the firewall</Tabs.Tab>
          {view.stagedDiff && <Tabs.Tab value="staged">Staged change</Tabs.Tab>}
          {view.outsideDiff && <Tabs.Tab value="outside">Changed outside OPF</Tabs.Tab>}
        </Tabs.List>
        <Tabs.Panel value="now" pt="sm">
          {view.exists ? (
            <ScrollArea.Autosize mah={640} type="auto">
              <pre className="mono" style={{ margin: 0, fontSize: 12, lineHeight: 1.5 }}>
                {lines.map((l, i) => (
                  <div key={i} style={{ display: 'flex' }}>
                    <span style={{ width: '3.5em', flexShrink: 0, textAlign: 'right', paddingRight: '1em', color: 'var(--mantine-color-dimmed)', userSelect: 'none' }}>{i + 1}</span>
                    <span style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{l}</span>
                  </div>
                ))}
              </pre>
            </ScrollArea.Autosize>
          ) : (
            <Text size="sm" c="dimmed">It isn’t on the firewall{view.staged === 'added' ? ' yet: the staged changes add it' : ''}.</Text>
          )}
        </Tabs.Panel>
        {view.stagedDiff && <Tabs.Panel value="staged" pt="sm"><UnifiedDiff diff={view.stagedDiff} /></Tabs.Panel>}
        {view.outsideDiff && <Tabs.Panel value="outside" pt="sm"><UnifiedDiff diff={view.outsideDiff} /></Tabs.Panel>}
      </Tabs>
    </Stack>
  );
}

export function ConfigFiles() {
  const { changes, history } = useStore();
  const [params, setParams] = useSearchParams();
  const [files, setFiles] = useState<ConfigFile[]>();
  const [error, setError] = useState<string>();
  // Read again when something is staged or committed.
  const version = changes.length + 1000 * history.length;
  useEffect(() => {
    backend.files().then(setFiles, (e) => setError(e instanceof Error ? e.message : String(e)));
  }, [version]);
  const selected = params.get('file') ?? files?.[0]?.path;
  const groups = new Map<string, ConfigFile[]>();
  for (const f of files ?? []) groups.set(fallbackDesc(f), [...(groups.get(fallbackDesc(f)) ?? []), f]);

  return (
    <>
      <PageHeader title="Configuration files" description="The OpenBSD files OPF writes for this configuration, as they are on the firewall, with any staged change and anything changed by hand." />
      {error && <Alert color="red" variant="light" mb="md">{error}</Alert>}
      <Grid gutter="md">
        <Grid.Col span={{ base: 12, md: 4 }}>
          <Card p="xs">
            <SectionTitle>Files</SectionTitle>
            {!files ? <Text size="sm" c="dimmed" p="xs">Reading…</Text> : [...groups].map(([desc, fs]) => (
              <Stack key={desc} gap={0} mb="xs">
                <Text size="xs" c="dimmed" tt="uppercase" fw={600} px="xs" pt={4}>{desc}</Text>
                {fs.map((f) => (
                  <NavLink
                    key={f.path} active={f.path === selected} variant="light"
                    onClick={() => setParams({ file: f.path })}
                    label={<Mono>{f.path}</Mono>}
                    description={(f.staged || f.outside || !f.exists) ? <Group gap={4} mt={2}><Badges f={f} /></Group> : undefined}
                  />
                ))}
              </Stack>
            ))}
          </Card>
        </Grid.Col>
        <Grid.Col span={{ base: 12, md: 8 }}>
          <Card>{selected ? <FileView path={selected} changes={version} /> : <Text size="sm" c="dimmed">No files yet: nothing has been committed.</Text>}</Card>
        </Grid.Col>
      </Grid>
    </>
  );
}
