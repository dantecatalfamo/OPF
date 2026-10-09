// System › Take over, read-only: what OPF does while it only monitors
// this machine, and how it would take the machine over. A machine
// configured by hand is taken over by importing its configuration
// first, so nothing changes until the admin changes it; that import is
// next on the roadmap, so the way in is here and locked. A machine OPF
// managed before has a configuration of its own, and is handed back by
// hand on the machine.
import { useEffect, useState } from 'react';
import { Link } from 'react-router';
import { Alert, Anchor, Badge, Button, Card, Code, Group, List, Stack, Text, ThemeIcon, Tooltip } from '@mantine/core';
import { IconEye, IconFileImport, IconLock } from '@tabler/icons-react';
import { backend } from '../model/store';
import type { ConfigFile } from '../lib/api';
import { useMode } from '../lib/mode';
import { useRole } from '../lib/session';
import { Mono, PageHeader, SectionTitle } from '../components/ui';

export function TakeOver() {
  const { readOnly, managed } = useMode();
  const { isAdmin } = useRole();
  const [files, setFiles] = useState<ConfigFile[]>();
  useEffect(() => {
    backend.files().then((r) => setFiles(r.filter((f) => f.exists)), () => setFiles([]));
  }, []);

  if (!readOnly) {
    return (
      <>
        <PageHeader title="Take over" />
        <Alert color="gray" variant="light">OPF manages this machine already.</Alert>
      </>
    );
  }
  return (
    <>
      <PageHeader
        title="Take over this machine"
        description="OPF is only monitoring this machine. Taking it over hands OPF its configuration, so you change it here instead of by hand."
      />
      <Stack gap="md" maw={820}>
        <Card>
          <Group gap="sm" mb="sm" wrap="nowrap">
            <ThemeIcon variant="light" color="blue" size="lg"><IconEye size={20} /></ThemeIcon>
            <SectionTitle>While it only monitors</SectionTitle>
          </Group>
          <List size="sm" spacing={6}>
            <List.Item>It shows the machine as it is: devices, connections, the firewall log and its statistics, interfaces, routes, services, logs and graphs.</List.Item>
            <List.Item>It changes nothing. Every change through this interface is refused, and OPF runs nothing that would change the machine: no new rules or settings, no services started or stopped, no connections closed, no accounts made.</List.Item>
            <List.Item>OPF writes only its own state directory (<Mono>/var/opf</Mono>): the graphs’ history and the event log. On OpenBSD the sandbox (unveil) holds it to that.</List.Item>
            <List.Item>The one thing it made is its sign-in groups, on first start, so people can sign in. Give someone a role by hand: <Mono>usermod -G _opfadmin name</Mono>.</List.Item>
          </List>
        </Card>

        {managed ? (
          <Card>
            <SectionTitle>Managing it again</SectionTitle>
            <Text size="sm" mb="sm">
              OPF has a configuration of its own for this machine, from before it was made read-only, so it can take over again without importing anything. That’s done on the machine itself, as root:
            </Text>
            <Code block>{`rcctl get opf flags          # then set them again without -readonly:
rcctl set opf flags <the same flags, without -readonly>
rm /var/opf/readonly
rcctl restart opf`}</Code>
            <Text size="xs" c="dimmed" mt="sm">
              Restarting changes nothing by itself: OPF keeps its configuration up again (lists, tables, sign-in accounts), and writes the machine’s files only when a change is applied.
            </Text>
          </Card>
        ) : (
          <Card>
            <Group justify="space-between" align="flex-start" mb="sm" wrap="nowrap">
              <SectionTitle>Taking it over</SectionTitle>
              <Badge variant="light" color="gray">Coming next</Badge>
            </Group>
            <Text size="sm" mb="sm">
              This machine was configured by hand, and OPF has no configuration of its own for it. Taking it over imports what’s here first: OPF reads the files below into its configuration and shows you what it understood, rule by rule, with anything it can’t model kept as it is. Nothing on the machine changes until you apply a change of your own.
            </Text>
            <Tooltip label="Importing a machine’s configuration is the next part of OPF to be built" disabled={!isAdmin}>
              <Button leftSection={<IconFileImport size={16} />} rightSection={<IconLock size={14} />} disabled>
                Import and take over
              </Button>
            </Tooltip>
            <Text size="xs" c="dimmed" mt="sm">
              Until then, OPF keeps monitoring. Starting it without <Mono>-readonly</Mono> doesn’t hand it control: it stays read-only while <Mono>/var/opf/readonly</Mono> is there.
            </Text>
          </Card>
        )}

        <Card>
          <SectionTitle right={<Anchor component={Link} to="/system/files" size="xs">Configuration files</Anchor>}>What OPF would take over</SectionTitle>
          {!files ? <Text size="sm" c="dimmed">Reading…</Text> : files.length ? (
            <Stack gap={4}>
              {files.map((f) => (
                <Group key={f.path} gap="sm" wrap="nowrap">
                  <Anchor component={Link} to={`/system/files?file=${encodeURIComponent(f.path)}`} size="sm"><Mono>{f.path}</Mono></Anchor>
                  <Text size="xs" c="dimmed">{f.desc}</Text>
                </Group>
              ))}
            </Stack>
          ) : <Text size="sm" c="dimmed">None of the files OPF manages are on this machine.</Text>}
        </Card>
      </Stack>
    </>
  );
}
