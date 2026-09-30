import { useEffect, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router';
import { ActionIcon, Alert, Badge, Button, Card, Group, Menu, Modal, Radio, SegmentedControl, Select, Stack, Switch, Table, Tabs, Text, TextInput, Tooltip } from '@mantine/core';
import { useForm } from '@mantine/form';
import { IconActivity, IconAlertCircle, IconDots, IconPencil, IconPlus, IconSearch, IconTrash } from '@tabler/icons-react';
import { backend, newId, useStore } from '../model/store';
import { defaultGateway, useLive } from '../lib/live';
import type { Gateway, StaticRoute } from '../model/types';
import type { RoutingTableResource } from '../lib/api';
import { deviceName, ifaceName } from '../lib/labels';
import { isCIDR, isIPv4 } from '../lib/ip';
import { Empty, Mono, PageHeader, StatusDot } from '../components/ui';
import { HistoryCard } from '../components/HistoryChart';


const mono = { input: { fontFamily: 'var(--mantine-font-family-monospace)' } };

function GatewayModal({ opened, onClose, gateway }: { opened: boolean; onClose: () => void; gateway: Gateway | null }) {
  const { staged, edit } = useStore();
  const form = useForm({
    initialValues: { name: '', iface: 'wan', address: '', monitor: '', description: '' },
    validate: {
      name: (v) => (/^[A-Z0-9_]{1,32}$/.test(v) ? null : 'Uppercase letters, digits and _'),
      address: (v) => (v === 'dhcp' || isIPv4(v) ? null : 'Enter the gateway’s address'),
      monitor: (v) => (!v || isIPv4(v) ? null : 'Enter an address to ping, or leave empty'),
    },
  });
  useEffect(() => {
    if (opened) form.setValues(gateway ? { ...gateway, monitor: gateway.monitor ?? '' } : { name: '', iface: 'wan', address: '', monitor: '', description: '' });
  }, [opened, gateway]); // form is stable
  return (
    <Modal opened={opened} onClose={onClose} title={<Text fw={600}>{gateway ? `Edit ${gateway.name}` : 'Add gateway'}</Text>}>
      <form
        onSubmit={form.onSubmit((v) => {
          const g: Gateway = { id: gateway?.id ?? newId('gw'), ...v, monitor: v.monitor || undefined };
          edit('routing', gateway ? `Edited gateway ${g.name}` : `Added gateway ${g.name} (${g.address})`, (m) => ({
            ...m,
            routing: { ...m.routing, gateways: gateway ? m.routing.gateways.map((x) => (x.id === g.id ? g : x)) : [...m.routing.gateways, g] },
          }));
          onClose();
        })}
      >
        <Stack>
          <Text size="sm" c="dimmed">A router OPF can send traffic to: a second internet connection, a VPN peer, or another router on your network.</Text>
          <TextInput label="Name" placeholder="WAN2" {...form.getInputProps('name')} onChange={(e) => form.setFieldValue('name', e.currentTarget.value.toUpperCase())} />
          <Select label="Reached through" data={staged.interfaces.map((i) => ({ value: i.id, label: i.name }))} allowDeselect={false} {...form.getInputProps('iface')} />
          <TextInput label="Address" placeholder="192.168.1.254" styles={mono} {...form.getInputProps('address')} />
          <TextInput label="Health check address" description="OPF pings this to tell whether the gateway works." placeholder="9.9.9.9" styles={mono} {...form.getInputProps('monitor')} />
          <TextInput label="Description" {...form.getInputProps('description')} />
          <Group justify="flex-end" mt="sm">
            <Button variant="default" onClick={onClose}>Cancel</Button>
            <Button type="submit">Save</Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}

function RouteModal({ opened, onClose, route }: { opened: boolean; onClose: () => void; route: StaticRoute | null }) {
  const { staged, edit } = useStore();
  const form = useForm({
    initialValues: { network: '', gateway: staged.routing.gateways[0]?.id ?? '', description: '', enabled: true },
    validate: { network: (v) => (isCIDR(v) ? null : 'Enter a network like 10.20.0.0/16') },
  });
  useEffect(() => {
    if (opened) form.setValues(route ? { ...route } : { network: '', gateway: staged.routing.gateways[0]?.id ?? '', description: '', enabled: true });
  }, [opened, route]); // form is stable
  return (
    <Modal opened={opened} onClose={onClose} title={<Text fw={600}>{route ? 'Edit route' : 'Add route'}</Text>}>
      <form
        onSubmit={form.onSubmit((v) => {
          const r: StaticRoute = { id: route?.id ?? newId('rt'), ...v };
          const g = staged.routing.gateways.find((x) => x.id === v.gateway);
          edit('routing', route ? `Edited route ${r.network}` : `Added route ${r.network} via ${g?.name}`, (m) => ({
            ...m,
            routing: { ...m.routing, routes: route ? m.routing.routes.map((x) => (x.id === r.id ? r : x)) : [...m.routing.routes, r] },
          }));
          onClose();
        })}
      >
        <Stack>
          <TextInput label="Network" placeholder="10.20.0.0/16" styles={mono} {...form.getInputProps('network')} />
          <Select label="Via gateway" data={staged.routing.gateways.map((g) => ({ value: g.id, label: `${g.name} · ${g.address === 'dhcp' ? 'DHCP' : g.address}` }))} allowDeselect={false} {...form.getInputProps('gateway')} />
          <TextInput label="Description" {...form.getInputProps('description')} />
          <Switch label="Enabled" {...form.getInputProps('enabled', { type: 'checkbox' })} />
          <Group justify="flex-end" mt="sm">
            <Button variant="default" onClick={onClose}>Cancel</Button>
            <Button type="submit">Save</Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}

function Gateways() {
  const { staged, edit } = useStore();
  const { data: health } = useLive('gateways');
  const { data: routes } = useLive('routes');
  const r = staged.routing;
  const [modal, setModal] = useState<{ open: boolean; gateway: Gateway | null }>({ open: false, gateway: null });
  const inUse = (id: string) => r.routes.some((x) => x.gateway === id) || staged.firewall.rules.some((x) => x.kind === 'form' && (x.gateway === id || x.replyTo === id)) || r.defaultGateway === id;
  return (
    <>
      {/* What's happening, then the gateways themselves. */}
      {staged.routing.gateways.length > 0 && (
        <Card mb="md">
          <HistoryCard
            title="Latency"
            series={staged.routing.gateways.map((g, i) => ({ key: `gw.${g.id}.rtt`, label: g.name, color: ['harbor.6', 'amber.6', 'grape.6', 'teal.6'][i % 4] }))}
            format={(n) => `${n < 10 ? n.toFixed(1) : Math.round(n)} ms`}
            peaks
            markSubjects={staged.routing.gateways.map((g) => g.id)}
          />
        </Card>
      )}
      <Group justify="space-between" mb="md">
        <Text size="sm" c="dimmed">The default gateway carries internet traffic. Others are used by static routes and by firewall rules that route traffic.</Text>
        <Button leftSection={<IconPlus size={16} />} onClick={() => setModal({ open: true, gateway: null })}>Add gateway</Button>
      </Group>
      <Card padding={0}>
        <Table.ScrollContainer minWidth={760}>
          <Table highlightOnHover>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Default</Table.Th>
                <Table.Th>Gateway</Table.Th>
                <Table.Th>Interface</Table.Th>
                <Table.Th>Address</Table.Th>
                <Table.Th ta="right">Latency</Table.Th>
                <Table.Th ta="right">Loss</Table.Th>
                <Table.Th />
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {r.gateways.map((g) => {
                const s = health?.gateways[g.id];
                const device = staged.interfaces.find((i) => i.id === g.iface)?.device ?? '';
                const address = g.address === 'dhcp' ? defaultGateway(routes, device) : g.address;
                const answered = s && !s.error;
                return (
                  <Table.Tr key={g.id}>
                    <Table.Td w={80}>
                      <Radio
                        checked={r.defaultGateway === g.id}
                        onChange={() => edit('routing', `Default gateway set to ${g.name}`, (m) => ({ ...m, routing: { ...m.routing, defaultGateway: g.id } }))}
                        aria-label={`Make ${g.name} the default gateway`}
                      />
                    </Table.Td>
                    <Table.Td>
                      <StatusDot ok={answered ? (s.online && s.lossPct > 5 ? 'warn' : s.online) : false} label={g.name} />
                      <Text size="xs" c="dimmed" ml={16}>{g.description}</Text>
                    </Table.Td>
                    <Table.Td><Text size="sm">{ifaceName(staged, g.iface)}</Text></Table.Td>
                    <Table.Td>
                      <Mono>{address ?? '—'}</Mono>
                      {g.address === 'dhcp' && <Text span size="xs" c="dimmed"> (DHCP)</Text>}
                      {s?.address && s.address !== address && <Text size="xs" c="dimmed">checked by pinging <Mono>{s.address}</Mono></Text>}
                      {s?.error && <Text size="xs" c="dimmed">{s.error}</Text>}
                    </Table.Td>
                    <Table.Td ta="right"><Text size="sm" className="num">{answered && s.rttMs !== undefined ? `${s.rttMs.toFixed(1)} ms` : answered ? 'No answer' : '—'}</Text></Table.Td>
                    <Table.Td ta="right"><Text size="sm" className="num">{answered ? `${Math.round(s.lossPct)}%` : '—'}</Text></Table.Td>
                    <Table.Td w={44}>
                      <Menu position="bottom-end">
                        <Menu.Target><ActionIcon variant="subtle" color="gray" aria-label="Actions"><IconDots size={16} /></ActionIcon></Menu.Target>
                        <Menu.Dropdown>
                          <Menu.Item leftSection={<IconPencil size={16} />} onClick={() => setModal({ open: true, gateway: g })}>Edit</Menu.Item>
                          {(s?.address ?? address) && (
                            <Menu.Item leftSection={<IconActivity size={16} />} component={Link} to={`/diagnostics/tools?tool=ping&host=${encodeURIComponent(s?.address ?? address ?? '')}`}>Ping</Menu.Item>
                          )}
                          <Tooltip label="Still used by a route, rule or as the default" disabled={!inUse(g.id)} position="left">
                            <Menu.Item leftSection={<IconTrash size={16} />} color="red" disabled={inUse(g.id)} onClick={() => edit('routing', `Deleted gateway ${g.name}`, (m) => ({ ...m, routing: { ...m.routing, gateways: m.routing.gateways.filter((x) => x.id !== g.id) } }))}>
                              Delete
                            </Menu.Item>
                          </Tooltip>
                        </Menu.Dropdown>
                      </Menu>
                    </Table.Td>
                  </Table.Tr>
                );
              })}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      </Card>
      <GatewayModal opened={modal.open} onClose={() => setModal((x) => ({ ...x, open: false }))} gateway={modal.gateway} />
    </>
  );
}

function Routes() {
  const { staged, edit } = useStore();
  const [modal, setModal] = useState<{ open: boolean; route: StaticRoute | null }>({ open: false, route: null });
  const routes = staged.routing.routes;
  return (
    <>
      <Group justify="space-between" mb="md">
        <Text size="sm" c="dimmed">Send traffic for specific networks to a gateway other than the default.</Text>
        <Button leftSection={<IconPlus size={16} />} onClick={() => setModal({ open: true, route: null })}>Add route</Button>
      </Group>
      <Card padding={0}>
        <Table.ScrollContainer minWidth={620}>
          <Table highlightOnHover>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>On</Table.Th>
                <Table.Th>Network</Table.Th>
                <Table.Th>Via</Table.Th>
                <Table.Th>Description</Table.Th>
                <Table.Th />
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {routes.map((r) => {
                const g = staged.routing.gateways.find((x) => x.id === r.gateway);
                return (
                  <Table.Tr key={r.id} style={{ opacity: r.enabled ? 1 : 0.6 }}>
                    <Table.Td w={56}><Switch size="xs" checked={r.enabled} onChange={() => edit('routing', `${r.enabled ? 'Disabled' : 'Enabled'} route ${r.network}`, (m) => ({ ...m, routing: { ...m.routing, routes: m.routing.routes.map((x) => (x.id === r.id ? { ...x, enabled: !x.enabled } : x)) } }))} aria-label="Enabled" /></Table.Td>
                    <Table.Td><Mono>{r.network}</Mono></Table.Td>
                    <Table.Td><Text size="sm">{g?.name}</Text><Mono c="dimmed">{g?.address}</Mono></Table.Td>
                    <Table.Td><Text size="sm">{r.description}</Text></Table.Td>
                    <Table.Td w={44}>
                      <Menu position="bottom-end">
                        <Menu.Target><ActionIcon variant="subtle" color="gray" aria-label="Actions"><IconDots size={16} /></ActionIcon></Menu.Target>
                        <Menu.Dropdown>
                          <Menu.Item leftSection={<IconPencil size={16} />} onClick={() => setModal({ open: true, route: r })}>Edit</Menu.Item>
                          <Menu.Item leftSection={<IconTrash size={16} />} color="red" onClick={() => edit('routing', `Deleted route ${r.network}`, (m) => ({ ...m, routing: { ...m.routing, routes: m.routing.routes.filter((x) => x.id !== r.id) } }))}>Delete</Menu.Item>
                        </Menu.Dropdown>
                      </Menu>
                    </Table.Td>
                  </Table.Tr>
                );
              })}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
        {routes.length === 0 && <Empty>No static routes.</Empty>}
      </Card>
      <RouteModal opened={modal.open} onClose={() => setModal((x) => ({ ...x, open: false }))} route={modal.route} />
    </>
  );
}

const POLL_MS = 30_000;

function useRoutingTable() {
  const [data, setData] = useState<RoutingTableResource | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    const load = () =>
      backend.routingTable().then(
        (d) => { if (live) { setData(d); setError(null); } },
        (e) => { if (live) setError(e instanceof Error ? e.message : String(e)); },
      );
    load();
    const t = setInterval(load, POLL_MS);
    return () => { live = false; clearInterval(t); };
  }, []);

  return { data, error };
}

function sourceColor(source?: string): string {
  switch (source) {
    case 'static': return 'blue';
    case 'dhcp': return 'green';
    case 'interface': return 'gray';
    case 'dynamic': return 'orange';
    default: return 'gray';
  }
}

function LiveRoutes() {
  const { applied } = useStore();
  const { data, error } = useRoutingTable();
  const [q, setQ] = useState('');
  const [family, setFamily] = useState<'ipv4' | 'ipv6'>('ipv4');

  if (error) {
    return (
      <Alert color="red" icon={<IconAlertCircle size={16} />} title="Error">
        {error}
      </Alert>
    );
  }

  if (!data) {
    return <Text c="dimmed">Loading...</Text>;
  }

  if (data.error) {
    return (
      <Alert color="yellow" icon={<IconAlertCircle size={16} />}>
        {data.error}
      </Alert>
    );
  }

  const routes = (family === 'ipv4' ? data.ipv4 : data.ipv6 ?? []).filter(
    (r) => !q || `${r.destination} ${r.gateway} ${r.iface}`.toLowerCase().includes(q.toLowerCase().trim()),
  );

  const hasIPv6 = (data.ipv6?.length ?? 0) > 0;

  return (
    <>
      <Group gap="sm" mb="md">
        <Text size="sm" c="dimmed" style={{ flex: 1 }}>What the kernel is using right now (netstat -rn).</Text>
        {hasIPv6 && (
          <SegmentedControl
            size="xs"
            value={family}
            onChange={(v) => setFamily(v as 'ipv4' | 'ipv6')}
            data={[{ value: 'ipv4', label: 'IPv4' }, { value: 'ipv6', label: 'IPv6' }]}
          />
        )}
      </Group>
      <TextInput
        placeholder="Filter by destination, gateway, or interface"
        leftSection={<IconSearch size={16} />}
        value={q}
        onChange={(e) => setQ(e.currentTarget.value)}
        maw={400}
        mb="md"
      />
      <Card padding={0}>
        <Table.ScrollContainer minWidth={620}>
          <Table striped highlightOnHover>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Destination</Table.Th>
                <Table.Th>Gateway</Table.Th>
                <Table.Th>Flags</Table.Th>
                <Table.Th>Interface</Table.Th>
                <Table.Th>Source</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {routes.length === 0 ? (
                <Table.Tr>
                  <Table.Td colSpan={5}>
                    <Text c="dimmed" ta="center" py="md">
                      {q ? 'No matching routes' : 'No routes'}
                    </Text>
                  </Table.Td>
                </Table.Tr>
              ) : (
                routes.map((r, i) => (
                  <Table.Tr key={`${r.destination}-${i}`}>
                    <Table.Td><Mono>{r.destination}</Mono></Table.Td>
                    <Table.Td><Mono>{r.gateway}</Mono></Table.Td>
                    <Table.Td><Mono c="dimmed">{r.flags}</Mono></Table.Td>
                    <Table.Td><Text size="sm">{deviceName(applied, r.iface)}</Text></Table.Td>
                    <Table.Td>
                      {r.source ? (
                        <Badge size="sm" color={sourceColor(r.source)}>{r.source}</Badge>
                      ) : (
                        <Text size="sm" c="dimmed">—</Text>
                      )}
                    </Table.Td>
                  </Table.Tr>
                ))
              )}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      </Card>
      <Text size="xs" c="dimmed" mt="sm">
        {routes.length} {routes.length === 1 ? 'route' : 'routes'}
        {q && routes.length !== (family === 'ipv4' ? data.ipv4 : data.ipv6 ?? []).length
          ? ` (${(family === 'ipv4' ? data.ipv4 : data.ipv6 ?? []).length} total)`
          : ''}
      </Text>
    </>
  );
}

export function Routing() {
  const { tab } = useParams();
  const navigate = useNavigate();
  const current = tab === 'routes' || tab === 'table' ? tab : 'gateways';
  return (
    <>
      <PageHeader title="Routing" description="Where OPF sends traffic that isn’t for one of its own networks." />
      <Tabs value={current} onChange={(v) => navigate(`/network/routing${v === 'gateways' ? '' : `/${v}`}`)} mb="md">
        <Tabs.List>
          <Tabs.Tab value="gateways">Gateways</Tabs.Tab>
          <Tabs.Tab value="routes">Static routes</Tabs.Tab>
          <Tabs.Tab value="table">Routing table</Tabs.Tab>
        </Tabs.List>
      </Tabs>
      {current === 'gateways' ? <Gateways /> : current === 'routes' ? <Routes /> : <LiveRoutes />}
    </>
  );
}
