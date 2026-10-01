// Diagnostics › System logs: what syslogd writes, a tab each, and the
// kernel's messages. The firewall reads the end of the log and filters
// it; this shows the newest first.
import { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router';
import { Alert, Button, Card, Group, Select, Switch, Table, Tabs, Text, TextInput, Tooltip } from '@mantine/core';
import { IconSearch } from '@tabler/icons-react';
import { backend } from '../model/store';
import type { SystemLogName, SystemLogResource } from '../lib/api';
import { formatLogTime } from '../lib/format';
import { PageHeader } from '../components/ui';

const logs: { value: SystemLogName; label: string; file: string; about: string }[] = [
  { value: 'messages', label: 'Messages', file: '/var/log/messages', about: 'The kernel and most programs: links changing, the clock, DHCP on the WAN.' },
  { value: 'daemon', label: 'Daemons', file: '/var/log/daemon', about: 'The services: dhcpd’s leases, unbound, and the rest.' },
  { value: 'authlog', label: 'Logins', file: '/var/log/authlog', about: 'SSH logins and failed attempts, and doas.' },
  { value: 'maillog', label: 'Mail', file: '/var/log/maillog', about: 'smtpd, which delivers the system’s own mail.' },
  { value: 'dmesg', label: 'Kernel', file: 'dmesg', about: 'The kernel’s message buffer, in the order it wrote it: the hardware found at boot, and what the drivers said since.' },
];

const PAGE = 300;

export function SystemLogs() {
  const [params, setParams] = useSearchParams();
  const log = logs.find((l) => l.value === params.get('log')) ?? logs[0];
  const [q, setQ] = useState('');
  const [query, setQuery] = useState('');
  const [program, setProgram] = useState<string | null>(null);
  const [limit, setLimit] = useState(PAGE);
  const [follow, setFollow] = useState(true);
  const [data, setData] = useState<SystemLogResource>();
  const [error, setError] = useState<string>();

  useEffect(() => {
    const t = setTimeout(() => setQuery(q.trim()), 300);
    return () => clearTimeout(t);
  }, [q]);
  useEffect(() => { setProgram(null); setLimit(PAGE); setData(undefined); }, [log.value]);
  useEffect(() => setLimit(PAGE), [query, program]);
  useEffect(() => {
    let live = true;
    const load = () => {
      if (document.hidden) return;
      backend.systemLog(log.value, { query: query || undefined, program: program ?? undefined, limit }).then(
        (d) => { if (live) { setData(d); setError(undefined); } },
        (e) => live && setError(e instanceof Error ? e.message : String(e)),
      );
    };
    load();
    const t = follow ? setInterval(load, 10_000) : undefined;
    return () => { live = false; clearInterval(t); };
  }, [log.value, query, program, limit, follow]);

  const kernel = log.value === 'dmesg';
  // The kernel's messages read as a story from boot: in its own order.
  const lines = kernel ? [...(data?.lines ?? [])].reverse() : data?.lines ?? [];
  return (
    <>
      <PageHeader title="System logs" description="What OpenBSD’s own programs write down, newest first. The firewall reads the end of each log; older lines are in the rotated copies beside it." />
      <Tabs value={log.value} onChange={(v) => setParams(v && v !== 'messages' ? { log: v } : {}, { replace: true })} mb="md">
        <Tabs.List>
          {logs.map((l) => <Tabs.Tab key={l.value} value={l.value}>{l.label}</Tabs.Tab>)}
        </Tabs.List>
      </Tabs>
      <Text size="sm" c="dimmed" mb="sm">{log.about}</Text>
      <Group mb="md" gap="sm" align="flex-end">
        <TextInput placeholder="Search" leftSection={<IconSearch size={16} />} value={q} onChange={(e) => setQ(e.currentTarget.value)} style={{ flex: '1 1 260px' }} maw={420} />
        {!kernel && (
          <Select placeholder="Every program" data={data?.programs ?? []} value={program} onChange={setProgram} clearable searchable w={200} />
        )}
        <Switch label="Follow" description="Every 10 seconds" checked={follow} onChange={(e) => setFollow(e.currentTarget.checked)} />
      </Group>
      {(error || data?.error) && <Alert color="red" variant="light" mb="md">{data?.error ?? `Couldn’t ask OPF: ${error}`}</Alert>}
      <Card padding={0}>
        {data && data.lines.length === 0 && !data.error ? (
          <Text size="sm" c="dimmed" ta="center" py="xl">{query || program ? 'No lines match.' : 'The log is empty.'}</Text>
        ) : (
          <Table.ScrollContainer minWidth={560}>
            <Table verticalSpacing={4} fz="xs" highlightOnHover>
              <Table.Tbody>
                {lines.map((l, i) => (
                  <Table.Tr key={i}>
                    {!kernel && (
                      <Table.Td w={150} style={{ whiteSpace: 'nowrap', verticalAlign: 'top' }}>
                        <Text size="xs" c="dimmed" className="num">{l.time ? formatLogTime(l.time) : ''}</Text>
                      </Table.Td>
                    )}
                    {!kernel && (
                      <Table.Td w={120} style={{ whiteSpace: 'nowrap', verticalAlign: 'top' }}>
                        {l.program && (
                          <Tooltip label={l.pid ? `${l.program}, process ${l.pid}` : l.program} openDelay={400}>
                            <Text size="xs" fw={500} style={{ cursor: 'pointer' }} onClick={() => setProgram(l.program!)}>{l.program}</Text>
                          </Tooltip>
                        )}
                      </Table.Td>
                    )}
                    {/* Lines hold text others chose (a user name tried at login): text, never markup. */}
                    <Table.Td className="mono" style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{l.message}</Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        )}
      </Card>
      {data && data.matched > 0 && (
        <Group justify="space-between" mt="sm">
          <Text size="xs" c="dimmed">
            Showing {data.lines.length.toLocaleString()} of {data.matched.toLocaleString()}{query || program ? ' that match' : ''}, from the last {data.read.toLocaleString()} lines of {log.file}.
          </Text>
          {data.matched > data.lines.length && limit < 1000 && (
            <Button size="compact-sm" variant="subtle" onClick={() => setLimit((n) => Math.min(1000, n + PAGE))}>Show more</Button>
          )}
        </Group>
      )}
    </>
  );
}
