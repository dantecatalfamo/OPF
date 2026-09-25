import { useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router';
import { ActionIcon, Badge, Button, Card, Group, Menu, Modal, Radio, Select, Stack, Switch, Table, Tabs, Text, TextInput, Tooltip } from '@mantine/core';
import { useForm } from '@mantine/form';
import { IconDots, IconPencil, IconPlus, IconTrash } from '@tabler/icons-react';
import { newId, useStore } from '../model/store';
import { gatewayStatus, routingTable } from '../model/live';
import type { Gateway, StaticRoute } from '../model/types';
import { ifaceName } from '../lib/labels';
import { isCIDR, isIPv4 } from '../lib/ip';
import { Empty, Mono, PageHeader, StatusDot } from '../components/ui';

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
  const r = staged.routing;
  const [modal, setModal] = useState<{ open: boolean; gateway: Gateway | null }>({ open: false, gateway: null });
  const inUse = (id: string) => r.routes.some((x) => x.gateway === id) || staged.firewall.rules.some((x) => x.kind === 'form' && (x.gateway === id || x.replyTo === id)) || r.defaultGateway === id;
  return (
    <>
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
                const s = gatewayStatus[g.id];
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
                      <StatusDot ok={s ? (s.lossPct > 5 ? 'warn' : s.online) : false} label={g.name} />
                      <Text size="xs" c="dimmed" ml={16}>{g.description}</Text>
                    </Table.Td>
                    <Table.Td><Text size="sm">{ifaceName(staged, g.iface)}</Text></Table.Td>
                    <Table.Td>
                      <Mono>{g.address === 'dhcp' ? s?.address ?? '—' : g.address}</Mono>
                      {g.address === 'dhcp' && <Text span size="xs" c="dimmed"> (DHCP)</Text>}
                    </Table.Td>
                    <Table.Td ta="right"><Text size="sm" className="num">{s ? `${s.rttMs} ms` : '—'}</Text></Table.Td>
                    <Table.Td ta="right"><Text size="sm" className="num">{s ? `${s.lossPct}%` : '—'}</Text></Table.Td>
                    <Table.Td w={44}>
                      <Menu position="bottom-end">
                        <Menu.Target><ActionIcon variant="subtle" color="gray" aria-label="Actions"><IconDots size={16} /></ActionIcon></Menu.Target>
                        <Menu.Dropdown>
                          <Menu.Item leftSection={<IconPencil size={16} />} onClick={() => setModal({ open: true, gateway: g })}>Edit</Menu.Item>
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

function LiveRoutes() {
  return (
    <>
      <Text size="sm" c="dimmed" mb="md">What the kernel is using right now (netstat -rn).</Text>
      <Card padding={0}>
        <Table.ScrollContainer minWidth={620}>
          <Table striped>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Destination</Table.Th>
                <Table.Th>Gateway</Table.Th>
                <Table.Th>Flags</Table.Th>
                <Table.Th>Interface</Table.Th>
                <Table.Th>From</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {routingTable.map((r) => (
                <Table.Tr key={r.destination}>
                  <Table.Td><Mono>{r.destination}</Mono></Table.Td>
                  <Table.Td><Mono>{r.gateway}</Mono></Table.Td>
                  <Table.Td><Mono c="dimmed">{r.flags}</Mono></Table.Td>
                  <Table.Td><Mono>{r.iface}</Mono></Table.Td>
                  <Table.Td><Badge color="gray">{r.source}</Badge></Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      </Card>
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
