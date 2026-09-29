import { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router';
import { ActionIcon, Alert, Badge, Button, Card, Grid, Group, Modal, NumberInput, SegmentedControl, Stack, Switch, Table, Tabs, TagsInput, Text, TextInput, Tooltip } from '@mantine/core';
import { useForm } from '@mantine/form';
import { IconAlertTriangle, IconBookmark, IconPlus, IconTrash } from '@tabler/icons-react';
import { backend, newId, useStore } from '../model/store';
import type { DhcpLeasesResource } from '../lib/api';
import { useNow } from '../lib/useNow';
import type { DhcpScope, Iface, Reservation } from '../model/types';
import { inSubnet, isIPv4, isMAC, toInt } from '../lib/ip';
import { Empty, Mono, PageHeader, SectionTitle } from '../components/ui';

function ScopeSettings({ iface, scope }: { iface: Iface; scope: DhcpScope }) {
  const { edit } = useStore();
  const form = useForm({
    initialValues: { enabled: scope.enabled, rangeStart: scope.rangeStart, rangeEnd: scope.rangeEnd, leaseHours: scope.leaseHours as number | string, dns: scope.dns, dnsServers: scope.dnsServers },
    validate: {
      rangeStart: (v) => (inSubnet(v, iface.ipv4.address!, iface.ipv4.prefix!) ? null : `Must be inside ${iface.name}’s network`),
      rangeEnd: (v, vals) => {
        if (!inSubnet(v, iface.ipv4.address!, iface.ipv4.prefix!)) return `Must be inside ${iface.name}’s network`;
        return isIPv4(vals.rangeStart) && toInt(v) < toInt(vals.rangeStart) ? 'Must come after the first address' : null;
      },
      leaseHours: (v) => (Number(v) >= 1 && Number(v) <= 720 ? null : 'Between 1 hour and 30 days'),
      dnsServers: (v, vals) => (vals.dns === 'self' || (v.length && v.every(isIPv4)) ? null : 'Enter one or more IPv4 addresses'),
    },
  });
  useEffect(() => {
    form.setValues({ enabled: scope.enabled, rangeStart: scope.rangeStart, rangeEnd: scope.rangeEnd, leaseHours: scope.leaseHours, dns: scope.dns, dnsServers: scope.dnsServers });
    form.resetDirty();
  }, [scope]); // form is stable

  const size = isIPv4(form.values.rangeStart) && isIPv4(form.values.rangeEnd) ? toInt(form.values.rangeEnd) - toInt(form.values.rangeStart) + 1 : 0;

  return (
    <Card>
      <form
        onSubmit={form.onSubmit((v) => {
          const next: DhcpScope = { ...scope, ...v, leaseHours: Number(v.leaseHours) };
          const summary = v.enabled !== scope.enabled
            ? `${v.enabled ? 'Turned on' : 'Turned off'} DHCP on ${iface.name}`
            : `Updated DHCP settings on ${iface.name} (addresses ${v.rangeStart}–${v.rangeEnd})`;
          edit('dhcp', summary, (m) => ({ ...m, dhcp: m.dhcp.map((d) => (d.iface === scope.iface ? next : d)) }));
        })}
      >
        <SectionTitle right={<Switch label="Enabled" {...form.getInputProps('enabled', { type: 'checkbox' })} />}>Settings</SectionTitle>
        <Stack>
          <Group grow align="flex-start">
            <TextInput label="First address" styles={{ input: { fontFamily: 'var(--mantine-font-family-monospace)' } }} {...form.getInputProps('rangeStart')} />
            <TextInput label="Last address" styles={{ input: { fontFamily: 'var(--mantine-font-family-monospace)' } }} {...form.getInputProps('rangeEnd')} />
          </Group>
          <Text size="xs" c="dimmed" mt={-8}>
            {size > 0 ? `${size} addresses to hand out. Reserved addresses can be inside or outside this range.` : ' '}
          </Text>
          <NumberInput label="Lease time" suffix=" hours" min={1} max={720} {...form.getInputProps('leaseHours')} />
          <Stack gap={6}>
            <Text size="sm" fw={500}>DNS servers given to devices</Text>
            <SegmentedControl
              data={[{ value: 'self', label: `This firewall (${iface.ipv4.address})` }, { value: 'custom', label: 'Other servers' }]}
              {...form.getInputProps('dns')}
            />
            {form.values.dns === 'custom' && <TagsInput placeholder="9.9.9.9" {...form.getInputProps('dnsServers')} />}
          </Stack>
          <Group justify="flex-end">
            <Button type="submit" disabled={!form.isDirty()}>Save</Button>
          </Group>
        </Stack>
      </form>
    </Card>
  );
}

function ReservationModal({ opened, onClose, iface, scope, initial }: {
  opened: boolean; onClose: () => void; iface: Iface; scope: DhcpScope; initial: Partial<Reservation> | null;
}) {
  const { edit } = useStore();
  const form = useForm({
    initialValues: { hostname: '', mac: '', ip: '' },
    validate: {
      hostname: (v) => (/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/i.test(v) ? null : 'Letters, digits and hyphens only'),
      mac: (v) => (isMAC(v) ? (scope.reservations.some((r) => r.mac.toLowerCase() === v.toLowerCase()) ? 'This device already has a reservation' : null) : 'Use the format 00:11:22:33:44:55'),
      ip: (v) => {
        if (!inSubnet(v, iface.ipv4.address!, iface.ipv4.prefix!)) return `Must be inside ${iface.name}’s network`;
        if (v === iface.ipv4.address) return 'That’s the firewall’s own address';
        return scope.reservations.some((r) => r.ip === v) ? 'Already reserved' : null;
      },
    },
  });
  useEffect(() => {
    if (opened) form.setValues({ hostname: initial?.hostname ?? '', mac: initial?.mac ?? '', ip: initial?.ip ?? '' });
  }, [opened, initial]); // form is stable

  return (
    <Modal opened={opened} onClose={onClose} title={<Text fw={600}>Reserve an address</Text>}>
      <form
        onSubmit={form.onSubmit((v) => {
          edit('dhcp', `Reserved ${v.ip} for “${v.hostname}” on ${iface.name}`, (m) => ({
            ...m,
            dhcp: m.dhcp.map((d) => (d.iface === scope.iface ? { ...d, reservations: [...d.reservations, { id: newId('d'), ...v, mac: v.mac.toLowerCase() }] } : d)),
          }));
          onClose();
        })}
      >
        <Stack>
          <Text size="sm" c="dimmed">The device will always get the same address. Handy for printers, servers and anything you forward ports to.</Text>
          <TextInput label="Name" placeholder="printer" {...form.getInputProps('hostname')} />
          <TextInput label="Hardware (MAC) address" placeholder="00:11:22:33:44:55" styles={{ input: { fontFamily: 'var(--mantine-font-family-monospace)' } }} {...form.getInputProps('mac')} />
          <TextInput label="IP address" placeholder={iface.ipv4.address?.replace(/\d+$/, '50')} styles={{ input: { fontFamily: 'var(--mantine-font-family-monospace)' } }} {...form.getInputProps('ip')} />
          <Group justify="flex-end" mt="sm">
            <Button variant="default" onClick={onClose}>Cancel</Button>
            <Button type="submit">Reserve</Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}

// dhcpd's leases, from the server, refreshed while the page is open.
function useDhcpLeases() {
  const [data, setData] = useState<DhcpLeasesResource | null>(null);
  const [failed, setFailed] = useState<string | null>(null);
  useEffect(() => {
    let live = true;
    const load = () =>
      backend.dhcpLeases().then(
        (d) => { if (live) { setData(d); setFailed(null); } },
        (e) => { if (live) setFailed(e instanceof Error ? e.message : String(e)); },
      );
    load();
    const t = setInterval(load, 30_000);
    return () => { live = false; clearInterval(t); };
  }, []);
  return { data, failed };
}

function endsIn(ends: string | undefined, now: number): string {
  if (!ends) return 'never';
  const min = Math.max(0, Math.round((Date.parse(ends) - now) / 60_000));
  return min >= 60 ? `in ${Math.floor(min / 60)} h` : `in ${min} min`;
}

export function Dhcp() {
  const { staged, edit } = useStore();
  const [params] = useSearchParams();
  const navigate = useNavigate();
  const scopes = staged.dhcp;
  const ifaces = staged.interfaces.filter((i) => i.ipv4.mode === 'static' && i.role !== 'wan' && i.role !== 'vpn');
  const currentId = params.get('iface') ?? scopes[0]?.iface ?? ifaces[0]?.id;
  const iface = ifaces.find((i) => i.id === currentId) ?? ifaces[0];
  const scope = scopes.find((s) => s.iface === iface.id);
  const [modal, setModal] = useState<{ open: boolean; initial: Partial<Reservation> | null }>({ open: false, initial: null });

  const enable = () =>
    edit('dhcp', `Turned on DHCP on ${iface.name}`, (m) => {
      const base = iface.ipv4.address!.split('.').slice(0, 3).join('.');
      return { ...m, dhcp: [...m.dhcp, { iface: iface.id, enabled: true, rangeStart: `${base}.100`, rangeEnd: `${base}.199`, leaseHours: 24, dns: 'self', dnsServers: [], reservations: [] }] };
    });

  const { data: leaseData, failed: leasesFailed } = useDhcpLeases();
  const now = useNow(30_000);
  const ifaceLeases = (leaseData?.leases ?? []).filter((l) => l.iface === iface.id);

  return (
    <>
      <PageHeader title="DHCP server" description="Hands out addresses to devices as they join each network." />
      <Tabs value={iface.id} onChange={(v) => v && navigate(`?iface=${v}`)} mb="md">
        <Tabs.List>
          {ifaces.map((i) => (
            <Tabs.Tab key={i.id} value={i.id}>{i.name}</Tabs.Tab>
          ))}
        </Tabs.List>
      </Tabs>

      {!scope ? (
        <Card>
          <Stack align="flex-start">
            <Text>DHCP isn’t set up on {iface.name}, so devices there need fixed addresses.</Text>
            <Button onClick={enable}>Turn on DHCP for {iface.name}</Button>
          </Stack>
        </Card>
      ) : (
        <Grid gutter="md">
          <Grid.Col span={{ base: 12, lg: 5 }}>
            <ScopeSettings iface={iface} scope={scope} />
          </Grid.Col>
          <Grid.Col span={{ base: 12, lg: 7 }}>
            <Stack gap="md">
              <Card>
                <SectionTitle right={<Button size="xs" variant="light" leftSection={<IconPlus size={14} />} onClick={() => setModal({ open: true, initial: null })}>Reserve address</Button>}>
                  Reserved addresses
                </SectionTitle>
                {scope.reservations.length ? (
                  <Table.ScrollContainer minWidth={420}>
                    <Table>
                      <Table.Tbody>
                        {scope.reservations.map((r) => (
                          <Table.Tr key={r.id}>
                            <Table.Td><Text size="sm" fw={500}>{r.hostname}</Text></Table.Td>
                            <Table.Td><Mono>{r.ip}</Mono></Table.Td>
                            <Table.Td><Mono c="dimmed">{r.mac}</Mono></Table.Td>
                            <Table.Td w={40}>
                              <ActionIcon variant="subtle" color="gray" aria-label="Remove reservation" onClick={() => edit('dhcp', `Removed reservation “${r.hostname}” (${r.ip}) on ${iface.name}`, (m) => ({ ...m, dhcp: m.dhcp.map((d) => (d.iface === scope.iface ? { ...d, reservations: d.reservations.filter((x) => x.id !== r.id) } : d)) }))}>
                                <IconTrash size={16} />
                              </ActionIcon>
                            </Table.Td>
                          </Table.Tr>
                        ))}
                      </Table.Tbody>
                    </Table>
                  </Table.ScrollContainer>
                ) : (
                  <Empty>No reservations. Reserve an address from the device list below.</Empty>
                )}
              </Card>
              <Card>
                <SectionTitle right={<Badge color="gray">{ifaceLeases.length} devices</Badge>}>Connected devices</SectionTitle>
                {leasesFailed && <Alert color="red" variant="light" p="sm" mb="sm" icon={<IconAlertTriangle size={16} />}>Couldn’t ask OPF: {leasesFailed}</Alert>}
                {leaseData?.error && <Alert color="yellow" variant="light" p="sm" mb="sm" icon={<IconAlertTriangle size={16} />}>{leaseData.error}.</Alert>}
                <Table.ScrollContainer minWidth={520}>
                  <Table highlightOnHover>
                    <Table.Thead>
                      <Table.Tr>
                        <Table.Th>Device</Table.Th>
                        <Table.Th>Address</Table.Th>
                        <Table.Th>Lease ends</Table.Th>
                        <Table.Th />
                      </Table.Tr>
                    </Table.Thead>
                    <Table.Tbody>
                      {ifaceLeases.map((l) => {
                        const reserved = scope.reservations.some((r) => r.mac === l.mac);
                        return (
                          <Table.Tr key={l.ip}>
                            <Table.Td>
                              {/* The name is the device's own choice; shown as text, never markup. */}
                              {l.hostname ? <Text size="sm" fw={500}>{l.hostname}</Text> : <Text size="sm" c="dimmed">Unnamed device</Text>}
                              {l.mac && <Mono c="dimmed">{l.mac}</Mono>}
                              {l.dnsName && <Text size="xs" c="dimmed">In DNS as <Mono>{l.dnsName}</Mono></Text>}
                              {l.dnsRefused && <Text size="xs" c="dimmed">Not in DNS: {l.dnsRefused}</Text>}
                            </Table.Td>
                            <Table.Td><Mono>{l.ip}</Mono></Table.Td>
                            <Table.Td><Text size="sm" c="dimmed" className="num">{endsIn(l.ends, now)}</Text></Table.Td>
                            <Table.Td w={44}>
                              {reserved ? (
                                <Tooltip label="Reserved"><IconBookmark size={16} color="var(--mantine-color-harbor-6)" /></Tooltip>
                              ) : (
                                <Tooltip label="Always give this device this address">
                                  <ActionIcon variant="subtle" aria-label="Reserve" onClick={() => setModal({ open: true, initial: { hostname: l.hostname ?? '', mac: l.mac ?? '', ip: l.ip } })}>
                                    <IconBookmark size={16} />
                                  </ActionIcon>
                                </Tooltip>
                              )}
                            </Table.Td>
                          </Table.Tr>
                        );
                      })}
                    </Table.Tbody>
                  </Table>
                </Table.ScrollContainer>
                {leaseData && ifaceLeases.length === 0 && <Empty>No devices have an address yet.</Empty>}
                {leaseData?.truncated && <Text size="xs" c="dimmed">Showing the first 5000 leases.</Text>}
              </Card>
            </Stack>
          </Grid.Col>
        </Grid>
      )}
      {scope && <ReservationModal opened={modal.open} onClose={() => setModal((m) => ({ ...m, open: false }))} iface={iface} scope={scope} initial={modal.initial} />}
    </>
  );
}
