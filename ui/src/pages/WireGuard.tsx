import { useEffect, useState } from 'react';
import { Link } from 'react-router';
import {
  ActionIcon, Alert, Anchor, Badge, Button, Card, Code, CopyButton, Drawer, Grid, Group, NumberInput, SegmentedControl, Stack, Switch, Table, TagsInput, Text, TextInput, ThemeIcon, Timeline, Tooltip,
} from '@mantine/core';
import { useForm } from '@mantine/form';
import { IconArrowsSplit2, IconCheck, IconCopy, IconPlugConnected, IconPlus, IconShieldHalf, IconTrash, IconWorld } from '@tabler/icons-react';
import { newId, useStore } from '../model/store';
import { ifaceStatus, peerStatus } from '../model/live';
import type { Model, Peer } from '../model/types';
import { automaticNat } from '../model/generate';
import { formatAgo, formatBytes } from '../lib/format';
import { isCIDR } from '../lib/ip';
import { Mono, PageHeader, SectionTitle, StatusDot } from '../components/ui';

// Stand-in for a real key pair; the appliance generates these like wg(8).
function fakeKey(): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  let s = '';
  for (let i = 0; i < 43; i++) s += chars[Math.floor(Math.random() * 64)];
  return s + '=';
}

function Copyable({ value }: { value: string }) {
  return (
    <Group gap={4} wrap="nowrap">
      <Mono>{value}</Mono>
      <CopyButton value={value}>
        {({ copied, copy }) => (
          <Tooltip label={copied ? 'Copied' : 'Copy'}>
            <ActionIcon variant="subtle" color={copied ? 'teal' : 'gray'} size="sm" onClick={copy} aria-label="Copy">
              {copied ? <IconCheck size={14} /> : <IconCopy size={14} />}
            </ActionIcon>
          </Tooltip>
        )}
      </CopyButton>
    </Group>
  );
}

function nextAddress(peers: Peer[], tunnel: string): string {
  const [base] = tunnel.split('/');
  const prefix = base.split('.').slice(0, 3).join('.');
  const used = new Set(peers.map((p) => Number(p.address.split('/')[0].split('.')[3])));
  used.add(Number(base.split('.')[3]));
  let n = 2;
  while (used.has(n)) n++;
  return `${prefix}.${n}/32`;
}

// Networks a client should send into the tunnel for "office only".
function officeNetworks(m: Model): string[] {
  const nets = m.interfaces
    .filter((i) => i.enabled && i.role !== 'wan' && i.ipv4.mode === 'static' && i.ipv4.address)
    .map((i) => `${i.ipv4.address!.replace(/\.\d+$/, '.0')}/${i.ipv4.prefix}`);
  return [...nets, ...m.wireguard.peers.flatMap((p) => p.networks)];
}

const routesLabel: Record<Peer['clientRoutes'], string> = { split: 'Office networks', full: 'All traffic', site: 'Site-to-site' };

function AddPeer({ opened, onClose }: { opened: boolean; onClose: () => void }) {
  const { staged, edit } = useStore();
  const wg = staged.wireguard;
  const [keys, setKeys] = useState({ priv: '', pub: '' });
  const [created, setCreated] = useState<Peer | null>(null);
  const form = useForm({
    initialValues: { name: '', address: '', clientRoutes: 'split' as Peer['clientRoutes'], networks: [] as string[], endpoint: '' },
    validate: {
      name: (v) => (v.trim() ? null : 'Name the device, like “Alex phone”'),
      networks: (v, vals) => (vals.clientRoutes !== 'site' || (v.length && v.every(isCIDR)) ? null : 'Enter the networks behind this router, like 10.30.0.0/16'),
    },
  });
  useEffect(() => {
    if (!opened) return;
    setKeys({ priv: fakeKey(), pub: fakeKey() });
    setCreated(null);
    form.setValues({ name: '', address: nextAddress(wg.peers, wg.address), clientRoutes: 'split', networks: [], endpoint: '' });
  }, [opened]); // form is stable

  const v = form.values;
  const wan = ifaceStatus.wan?.address?.split('/')[0] ?? 'your-public-address';
  const allowed = v.clientRoutes === 'full' ? '0.0.0.0/0' : officeNetworks(staged).join(', ');
  const clientConfig = `[Interface]
PrivateKey = ${keys.priv}
Address = ${v.address}
DNS = ${wg.address.split('/')[0]}

[Peer]
PublicKey = ${wg.publicKey}
Endpoint = ${wan}:${wg.listenPort}
AllowedIPs = ${allowed}
PersistentKeepalive = 25`;

  return (
    <Drawer opened={opened} onClose={onClose} size="xl" title={<Text fw={600} size="lg">Add a device</Text>}>
      {created ? (
        <Stack>
          <Alert color="teal" variant="light" icon={<IconCheck size={18} />} title={`${created.name} is ready`}>
            Import this into the WireGuard app on the device. It contains the device’s private key, so OPF won’t show it again.
          </Alert>
          <Code block>{clientConfig}</Code>
          <Group justify="flex-end">
            <CopyButton value={clientConfig}>
              {({ copied, copy }) => (
                <Button variant="light" leftSection={copied ? <IconCheck size={16} /> : <IconCopy size={16} />} onClick={copy}>{copied ? 'Copied' : 'Copy configuration'}</Button>
              )}
            </CopyButton>
            <Button onClick={onClose}>Done</Button>
          </Group>
        </Stack>
      ) : (
        <form
          onSubmit={form.onSubmit((x) => {
            const peer: Peer = {
              id: newId('p'), name: x.name.trim(), publicKey: keys.pub, address: x.address, keepalive: 25, clientRoutes: x.clientRoutes,
              networks: x.clientRoutes === 'site' ? x.networks : [], ...(x.endpoint ? { endpoint: x.endpoint } : {}),
            };
            edit('wireguard', `Added VPN device “${peer.name}” (${peer.address}${peer.networks.length ? `, routes ${peer.networks.join(', ')}` : ''})`, (m) => ({
              ...m,
              wireguard: { ...m.wireguard, peers: [...m.wireguard.peers, peer] },
            }));
            if (peer.networks.length) {
              // The networks behind a router peer need routes into the tunnel.
              const wgIface = staged.interfaces.find((i) => i.role === 'vpn')?.id ?? 'wg';
              const gw = { id: newId('gw'), name: peer.name.toUpperCase().replace(/[^A-Z0-9]+/g, '_').slice(0, 32), iface: wgIface, address: peer.address.split('/')[0], description: `${peer.name} over WireGuard` };
              edit('routing', `Added gateway ${gw.name} and route${peer.networks.length === 1 ? '' : 's'} ${peer.networks.join(', ')} through it`, (m) => ({
                ...m,
                routing: {
                  ...m.routing,
                  gateways: [...m.routing.gateways, gw],
                  routes: [...m.routing.routes, ...peer.networks.map((n) => ({ id: newId('rt'), enabled: true, network: n, gateway: gw.id, description: peer.name }))],
                },
              }));
            }
            setCreated(peer);
          })}
        >
          <Stack>
            <TextInput label="Device name" placeholder="Alex phone" data-autofocus {...form.getInputProps('name')} />
            <TextInput label="VPN address" description="Picked from the tunnel network." styles={{ input: { fontFamily: 'var(--mantine-font-family-monospace)' } }} {...form.getInputProps('address')} />
            <Stack gap={6}>
              <Text size="sm" fw={500}>What this device sends through the VPN</Text>
              <SegmentedControl
                data={[{ value: 'split', label: 'Office networks' }, { value: 'full', label: 'All traffic' }, { value: 'site', label: 'It’s a router (site-to-site)' }]}
                {...form.getInputProps('clientRoutes')}
              />
              <Text size="xs" c="dimmed">
                {v.clientRoutes === 'split' && `Only traffic for ${officeNetworks(staged).join(', ')} uses the tunnel. The device’s own internet stays as it is.`}
                {v.clientRoutes === 'full' && 'Everything goes through the office and out its internet connection, translated to the WAN address by outbound NAT.'}
                {v.clientRoutes === 'site' && 'Another router with networks behind it. OPF adds routes for those networks into the tunnel.'}
              </Text>
            </Stack>
            {v.clientRoutes === 'site' && (
              <>
                <TagsInput label="Networks behind this router" placeholder="10.30.0.0/16" {...form.getInputProps('networks')} />
                <TextInput label="Its public address" description="Optional. Lets OPF start the connection." placeholder="branch.example.net:51820" {...form.getInputProps('endpoint')} />
              </>
            )}
            <Group justify="flex-end" mt="sm">
              <Button variant="default" onClick={onClose}>Cancel</Button>
              <Button type="submit">Create device</Button>
            </Group>
          </Stack>
        </form>
      )}
    </Drawer>
  );
}

function TrafficFlow() {
  const { staged } = useStore();
  const wg = staged.wireguard;
  const wgIface = staged.interfaces.find((i) => i.role === 'vpn');
  const wan = staged.interfaces.find((i) => i.role === 'wan');
  const wanRule = staged.firewall.rules.find((r) => r.enabled && r.kind === 'form' && r.interfaces.includes(wan?.id ?? '') && r.protocol === 'udp' && r.port === String(wg.listenPort));
  const wgRules = staged.firewall.rules.filter((r) => r.enabled && wgIface && r.interfaces.length === 1 && r.interfaces[0] === wgIface.id);
  const routes = staged.routing.routes.filter((r) => r.enabled && staged.routing.gateways.find((g) => g.id === r.gateway)?.iface === wgIface?.id);
  const nat = staged.firewall.outboundNat;
  const natAuto = nat.mode !== 'manual' && automaticNat(staged).some((n) => n.source.type === 'net' && n.source.iface === wgIface?.id);
  const fullPeers = wg.peers.filter((p) => p.clientRoutes === 'full');

  return (
    <Card>
      <SectionTitle>How traffic flows</SectionTitle>
      <Timeline bulletSize={28} lineWidth={2}>
        <Timeline.Item bullet={<ThemeIcon size={28} radius="xl" variant="light"><IconPlugConnected size={16} /></ThemeIcon>} title={<Text size="sm" fw={600}>Devices connect</Text>}>
          <Text size="sm" c="dimmed">
            To <Mono>{ifaceStatus.wan?.address?.split('/')[0]}:{wg.listenPort}</Mono> over UDP.{' '}
            {wanRule ? (
              <>Allowed by the WAN rule <Anchor component={Link} to={`/firewall/rules/${wan?.id}`} size="sm">“{wanRule.description}”</Anchor>.</>
            ) : (
              <Text span c="red" size="sm">No WAN rule allows this port, so devices can’t connect.</Text>
            )}
          </Text>
        </Timeline.Item>
        <Timeline.Item bullet={<ThemeIcon size={28} radius="xl" variant="light"><IconArrowsSplit2 size={16} /></ThemeIcon>} title={<Text size="sm" fw={600}>Routing</Text>}>
          <Text size="sm" c="dimmed">
            Each device gets an address in <Mono>{wg.address.replace(/\.\d+\//, '.0/')}</Mono> on <Mono>{wgIface?.device}</Mono>.
            {routes.length > 0 && (
              <>
                {' '}Routes into the tunnel:{' '}
                {routes.map((r, i) => (
                  <span key={r.id}>
                    {i > 0 && ', '}
                    <Mono>{r.network}</Mono> via {staged.routing.gateways.find((g) => g.id === r.gateway)?.name}
                  </span>
                ))}{' '}
                (<Anchor component={Link} to="/network/routing/routes" size="sm">static routes</Anchor>).
              </>
            )}
          </Text>
        </Timeline.Item>
        <Timeline.Item bullet={<ThemeIcon size={28} radius="xl" variant="light"><IconShieldHalf size={16} /></ThemeIcon>} title={<Text size="sm" fw={600}>Firewall</Text>}>
          <Text size="sm" c="dimmed">
            Traffic arriving from the tunnel is checked by{' '}
            <Anchor component={Link} to={`/firewall/rules/${wgIface?.id}`} size="sm">{wgRules.length} {wgIface?.name} rule{wgRules.length === 1 ? '' : 's'}</Anchor>
            {wgRules.length ? `: ${wgRules.map((r) => r.description).join('; ')}.` : '. With none, everything from the tunnel is blocked.'}
          </Text>
        </Timeline.Item>
        <Timeline.Item bullet={<ThemeIcon size={28} radius="xl" variant="light"><IconWorld size={16} /></ThemeIcon>} title={<Text size="sm" fw={600}>Internet access</Text>}>
          <Text size="sm" c="dimmed">
            {fullPeers.length ? `${fullPeers.map((p) => p.name).join(', ')} send${fullPeers.length === 1 ? 's' : ''} all traffic through the office. ` : 'No device sends all its traffic through the office. '}
            {natAuto ? (
              <>It leaves through {wan?.name}, translated to the WAN address by <Anchor component={Link} to="/firewall/nat/outbound" size="sm">automatic outbound NAT</Anchor>.</>
            ) : (
              <Text span c={fullPeers.length ? 'red' : 'dimmed'} size="sm">
                No <Anchor component={Link} to="/firewall/nat/outbound" size="sm">outbound NAT</Anchor> rule covers the tunnel network, so it can’t reach the internet.
              </Text>
            )}
          </Text>
        </Timeline.Item>
      </Timeline>
    </Card>
  );
}

export function WireGuardPage() {
  const { staged, edit } = useStore();
  const wg = staged.wireguard;
  const [adding, setAdding] = useState(false);
  const form = useForm({ initialValues: { enabled: wg.enabled, listenPort: wg.listenPort as number | string } });
  useEffect(() => {
    form.setValues({ enabled: wg.enabled, listenPort: wg.listenPort });
    form.resetDirty();
  }, [wg.enabled, wg.listenPort]); // form is stable

  return (
    <>
      <PageHeader
        title="WireGuard VPN"
        description="Lets phones, laptops and other sites reach your networks securely from anywhere."
        actions={<Button leftSection={<IconPlus size={16} />} onClick={() => setAdding(true)}>Add device</Button>}
      />
      <Grid gutter="md">
        <Grid.Col span={{ base: 12, lg: 5 }}>
          <Stack gap="md">
            <Card>
              <form
                onSubmit={form.onSubmit((x) =>
                  edit('wireguard', x.enabled !== wg.enabled ? `${x.enabled ? 'Turned on' : 'Turned off'} WireGuard VPN` : `WireGuard now listens on port ${x.listenPort}`, (m) => ({
                    ...m,
                    wireguard: { ...m.wireguard, enabled: x.enabled, listenPort: Number(x.listenPort) },
                  })),
                )}
              >
                <SectionTitle right={<Switch label="Enabled" {...form.getInputProps('enabled', { type: 'checkbox' })} />}>Tunnel</SectionTitle>
                <Stack gap="md">
                  <NumberInput label="Port" min={1} max={65535} {...form.getInputProps('listenPort')} />
                  <Stack gap={2}>
                    <Text size="sm" fw={500}>Tunnel address</Text>
                    <Mono>{wg.address}</Mono>
                  </Stack>
                  <Stack gap={2}>
                    <Text size="sm" fw={500}>Public key</Text>
                    <Copyable value={wg.publicKey} />
                  </Stack>
                  <Group justify="flex-end">
                    <Button type="submit" disabled={!form.isDirty()}>Save</Button>
                  </Group>
                </Stack>
              </form>
            </Card>
          </Stack>
        </Grid.Col>
        <Grid.Col span={{ base: 12, lg: 7 }}>
          <TrafficFlow />
        </Grid.Col>
        <Grid.Col span={12}>
          <Card padding={0}>
            <Group p="lg" pb="xs"><Text fw={600}>Devices</Text></Group>
            <Table.ScrollContainer minWidth={820}>
              <Table highlightOnHover>
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>Device</Table.Th>
                    <Table.Th>VPN address</Table.Th>
                    <Table.Th>Uses the tunnel for</Table.Th>
                    <Table.Th>Last seen</Table.Th>
                    <Table.Th ta="right">Transferred</Table.Th>
                    <Table.Th />
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {wg.peers.map((p) => {
                    const s = peerStatus[p.id];
                    const online = s?.handshakeSecAgo != null && s.handshakeSecAgo < 180;
                    return (
                      <Table.Tr key={p.id}>
                        <Table.Td>
                          <StatusDot ok={online ? true : s ? 'warn' : false} label={p.name} />
                          <Text size="xs" c="dimmed" ml={16}>{s?.endpoint ?? p.endpoint ?? 'Not connected yet'}</Text>
                        </Table.Td>
                        <Table.Td>
                          <Mono>{p.address}</Mono>
                          {p.networks.length > 0 && <Text size="xs" c="dimmed">routes {p.networks.join(', ')}</Text>}
                        </Table.Td>
                        <Table.Td><Badge color={p.clientRoutes === 'full' ? 'amber' : 'gray'}>{routesLabel[p.clientRoutes]}</Badge></Table.Td>
                        <Table.Td>
                          {s?.handshakeSecAgo != null ? (online ? <Badge color="teal">Online</Badge> : <Text size="sm" c="dimmed">{formatAgo(s.handshakeSecAgo)}</Text>) : <Text size="sm" c="dimmed">Never</Text>}
                        </Table.Td>
                        <Table.Td ta="right"><Text size="sm" className="num">{s ? `↓ ${formatBytes(s.tx)} · ↑ ${formatBytes(s.rx)}` : '—'}</Text></Table.Td>
                        <Table.Td w={44}>
                          <Tooltip label="Remove device">
                            <ActionIcon variant="subtle" color="gray" aria-label="Remove device" onClick={() => edit('wireguard', `Removed VPN device “${p.name}”`, (m) => ({ ...m, wireguard: { ...m.wireguard, peers: m.wireguard.peers.filter((x) => x.id !== p.id) } }))}>
                              <IconTrash size={16} />
                            </ActionIcon>
                          </Tooltip>
                        </Table.Td>
                      </Table.Tr>
                    );
                  })}
                </Table.Tbody>
              </Table>
            </Table.ScrollContainer>
          </Card>
        </Grid.Col>
      </Grid>
      <AddPeer opened={adding} onClose={() => setAdding(false)} />
    </>
  );
}
