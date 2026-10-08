// Diagnostics › Storage: everything that fills up as the firewall runs,
// what it holds now and the most it can (GET /api/diagnostics/storage).
import { useEffect, useState } from 'react';
import { Link } from 'react-router';
import { Alert, Anchor, Badge, Card, Group, Progress, Stack, Table, Text, Tooltip } from '@mantine/core';
import { IconAlertTriangle } from '@tabler/icons-react';
import { backend } from '../model/store';
import type { StorageItem, StorageResource } from '../lib/api';
import { formatBytes } from '../lib/format';
import { PageHeader, SectionTitle } from '../components/ui';

const groups: { id: StorageItem['group']; title: string; desc: string }[] = [
  { id: 'pf', title: 'pf, in the kernel', desc: 'Its tables have hard limits; once one is full, what needs a new entry fails.' },
  { id: 'opf', title: 'Kept by OPF', desc: 'Its own records, each with its own limit.' },
  { id: 'logs', title: 'Logs', desc: 'The system’s logs OPF reads, rotated by newsyslog.' },
  { id: 'disk', title: 'OPF and its disk', desc: '' },
];

const amount = (it: StorageItem, n: number) => (it.unit === 'bytes' ? formatBytes(n) : n.toLocaleString());

function Row({ it }: { it: StorageItem }) {
  const share = it.current !== undefined && it.max ? it.current / it.max : undefined;
  const color = share === undefined ? 'gray' : share > 0.9 ? 'red' : share > 0.75 ? 'yellow' : 'harbor';
  return (
    <Table.Tr>
      <Table.Td style={{ verticalAlign: 'top' }}>
        <Group gap={6} wrap="nowrap">
          <Text size="sm" fw={500}>{it.link ? <Anchor component={Link} to={it.link} size="sm" c="inherit">{it.name}</Anchor> : it.name}</Text>
          <Badge size="xs" variant="light" color="gray">{it.where}</Badge>
        </Group>
        <Text size="xs" c="dimmed">{it.desc}</Text>
        {it.note && <Text size="xs" c="dimmed" mt={2}>{it.note}</Text>}
      </Table.Td>
      <Table.Td w={260} style={{ verticalAlign: 'top' }}>
        {it.off ? (
          <Text size="sm" c="dimmed">{it.id === 'lists' ? 'None' : 'Off'}</Text>
        ) : (
          <Stack gap={4}>
            <Group justify="space-between" gap="xs" wrap="nowrap">
              <Text size="sm" className="num" c={it.current === undefined ? 'dimmed' : undefined}>{it.current !== undefined ? amount(it, it.current) : 'unknown'}</Text>
              <Text size="xs" c="dimmed" className="num">
                {it.max !== undefined ? `of ${amount(it, it.max)}${share !== undefined ? ` · ${share < 0.01 && share > 0 ? '<1' : Math.round(share * 100)}%` : ''}` : it.unbounded ? (
                  <Tooltip label={it.unbounded} multiline w={260}><span>no limit</span></Tooltip>
                ) : null}
              </Text>
            </Group>
            {it.max !== undefined ? (
              <Progress value={share !== undefined ? Math.min(100, share * 100) : 0} color={color} size="sm" />
            ) : it.unbounded && <Text size="xs" c="yellow">{it.unbounded}</Text>}
          </Stack>
        )}
      </Table.Td>
    </Table.Tr>
  );
}

export function Storage() {
  const [data, setData] = useState<StorageResource>();
  const [error, setError] = useState<string>();
  useEffect(() => {
    const load = () => backend.storage().then((d) => { setData(d); setError(undefined); }, (e) => setError(e instanceof Error ? e.message : String(e)));
    load();
    const t = setInterval(load, 15_000);
    return () => clearInterval(t);
  }, []);
  return (
    <>
      <PageHeader title="Storage" description="Everything that fills up as the firewall runs: what each holds now, and the most it can." />
      <Stack gap="md">
        {error && <Alert color="red" variant="light" icon={<IconAlertTriangle size={16} />}>Couldn’t ask OPF: {error}</Alert>}
        {data?.errors.map((e) => <Alert key={e} color="yellow" variant="light" p="sm" icon={<IconAlertTriangle size={16} />}>{e}</Alert>)}
        {!data && !error && <Text size="sm" c="dimmed">Reading…</Text>}
        {data && groups.map((g) => {
          const items = data.items.filter((it) => it.group === g.id);
          if (!items.length) return null;
          return (
            <Card key={g.id}>
              <SectionTitle>{g.title}</SectionTitle>
              {g.desc && <Text size="sm" c="dimmed" mb="xs">{g.desc}</Text>}
              <Table verticalSpacing="sm">
                <Table.Tbody>{items.map((it) => <Row key={it.id} it={it} />)}</Table.Tbody>
              </Table>
            </Card>
          );
        })}
      </Stack>
    </>
  );
}
