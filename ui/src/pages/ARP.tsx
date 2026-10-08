import { useEffect, useState } from 'react';
import { Alert, Badge, Card, Stack, Table, Text, TextInput } from '@mantine/core';
import { IconAlertCircle, IconSearch } from '@tabler/icons-react';
import { backend, useStore } from '../model/store';
import { deviceName } from '../lib/labels';
import { DeviceLink, macKey } from '../components/DeviceLink';
import { Mono, PageHeader } from '../components/ui';
import type { ARPTableResource } from '../lib/api';

const POLL_MS = 30_000;

function useArpTable() {
  const [data, setData] = useState<ARPTableResource | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    const load = () =>
      backend.arpTable().then(
        (d) => { if (live) { setData(d); setError(null); } },
        (e) => { if (live) setError(e instanceof Error ? e.message : String(e)); },
      );
    load();
    const t = setInterval(load, POLL_MS);
    return () => { live = false; clearInterval(t); };
  }, []);

  return { data, error };
}

export function ARP() {
  const { applied } = useStore();
  const { data, error } = useArpTable();
  const [q, setQ] = useState('');

  if (error) {
    return (
      <>
        <PageHeader title="ARP Table" description="The system's ARP cache maps IP addresses to MAC addresses." />
        <Alert color="red" icon={<IconAlertCircle size={16} />} title="Error">
          {error}
        </Alert>
      </>
    );
  }

  if (!data) {
    return (
      <>
        <PageHeader title="ARP Table" description="The system's ARP cache maps IP addresses to MAC addresses." />
        <Text c="dimmed">Loading...</Text>
      </>
    );
  }

  if (data.error) {
    return (
      <>
        <PageHeader title="ARP Table" description="The system's ARP cache maps IP addresses to MAC addresses." />
        <Alert color="yellow" icon={<IconAlertCircle size={16} />}>
          {data.error}
        </Alert>
      </>
    );
  }

  const entries = data.entries.filter(
    (e) => !q || `${e.ip} ${e.mac} ${e.hostname ?? ''}`.toLowerCase().includes(q.toLowerCase().trim()),
  );

  return (
    <>
      <PageHeader title="ARP Table" description="The system's ARP cache maps IP addresses to MAC addresses." />
      <Stack gap="md">
        <TextInput
          placeholder="Filter by IP, MAC, or hostname"
          leftSection={<IconSearch size={16} />}
          value={q}
          onChange={(e) => setQ(e.currentTarget.value)}
          maw={400}
        />
        <Card padding={0}>
          <Table.ScrollContainer minWidth={700}>
            <Table highlightOnHover striped>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>IP Address</Table.Th>
                  <Table.Th>MAC Address</Table.Th>
                  <Table.Th>Interface</Table.Th>
                  <Table.Th>Hostname</Table.Th>
                  <Table.Th>Expires</Table.Th>
                  <Table.Th>Flags</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {entries.length === 0 ? (
                  <Table.Tr>
                    <Table.Td colSpan={6}>
                      <Text c="dimmed" ta="center" py="md">
                        {q ? 'No matching entries' : 'No ARP entries'}
                      </Text>
                    </Table.Td>
                  </Table.Tr>
                ) : (
                  entries.map((e, i) => (
                    <Table.Tr key={`${e.ip}-${i}`}>
                      <Table.Td><Mono>{e.ip}</Mono></Table.Td>
                      <Table.Td>{/^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/i.test(e.mac) ? <DeviceLink deviceKey={macKey(e.mac)}><Mono>{e.mac}</Mono></DeviceLink> : <Mono>{e.mac}</Mono>}</Table.Td>
                      <Table.Td>
                        <Text size="sm">{deviceName(applied, e.iface)}</Text>
                      </Table.Td>
                      <Table.Td>
                        {e.hostname ? <Text size="sm">{e.hostname}</Text> : <Text size="sm" c="dimmed">—</Text>}
                      </Table.Td>
                      <Table.Td>
                        <Text size="sm" c={e.expires === 'permanent' ? 'teal' : 'dimmed'}>
                          {e.expires ?? '—'}
                        </Text>
                      </Table.Td>
                      <Table.Td>
                        {e.flags ? <Badge size="xs" color="gray">{e.flags}</Badge> : null}
                      </Table.Td>
                    </Table.Tr>
                  ))
                )}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        </Card>
        <Text size="xs" c="dimmed">
          {entries.length} {entries.length === 1 ? 'entry' : 'entries'}
          {q && entries.length !== data.entries.length ? ` (${data.entries.length} total)` : ''}
        </Text>
      </Stack>
    </>
  );
}
