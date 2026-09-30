import { useEffect, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router';
import {
  ActionIcon, Alert, Anchor, Badge, Button, Card, Checkbox, Code, CopyButton, Drawer, Grid, Group, Modal, NumberInput, SegmentedControl, Stack, Switch, Table, Tabs, TagsInput, Text, TextInput, ThemeIcon, Timeline, Tooltip,
} from '@mantine/core';
import { useForm } from '@mantine/form';
import { IconAlertTriangle, IconArrowsSplit2, IconCheck, IconCopy, IconPencil, IconPlugConnected, IconPlus, IconShieldHalf, IconTrash, IconWorld } from '@tabler/icons-react';
import { newId, useStore } from '../model/store';
import { firstIPv4, ifaceState, peerOnline, peerState, useLive } from '../lib/live';
import { tunnels, type Iface, type Model, type Peer, type Tunnel } from '../model/types';
import { useDerived } from '../lib/generated';
import { formRule } from '../model/sample';
import { isFloating } from '../lib/rules';
import { formatAgo, formatBits, formatBytes } from '../lib/format';
import { HistoryCard } from '../components/HistoryChart';

import { fromInt, isCIDR, isIPv4, network, toInt } from '../lib/ip';
import { Mono, PageHeader, SectionTitle, StatusDot } from '../components/ui';
import { DeleteInterface } from '../components/DeleteInterface';

// Stand-in for a real key pair; the appliance generates these like wg(8).
function fakeKey(): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  let s = '';
  for (let i = 0; i < 42; i++) s += chars[Math.floor(Math.random() * 64)];
  // The 43rd character carries only 4 bits of the 32-byte key.
  return s + 'AEIMQUYcgkosw048'[Math.floor(Math.random() * 16)] + '=';
}

// The WAN's address, where devices reach the tunnel. Behind another
// router it's a private address, and the device needs the public one.
function usePublicAddress(): string {
  const { staged } = useStore();
  const { data } = useLive('interfaces');
  const wan = staged.interfaces.find((i) => i.role === 'wan');
  return (wan && firstIPv4(ifaceState(data, wan))) ?? 'your-public-address';
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

const tunnelNet = (t: Iface) => `${network(t.ipv4.address!, t.ipv4.prefix!)}/${t.ipv4.prefix}`;

// The first free address in the tunnel's network, as a /32.
function nextAddress(t: Tunnel): string {
  const base = toInt(network(t.ipv4.address!, t.ipv4.prefix!));
  const size = 2 ** (32 - t.ipv4.prefix!);
  const used = new Set([toInt(t.ipv4.address!), ...t.wireguard.peers.map((p) => toInt(p.address.split('/')[0]))]);
  for (let n = 1; n < size - 1; n++) if (!used.has(base + n)) return `${fromInt(base + n)}/32`;
  return '';
}

// Networks already used here: interfaces, and everything behind peers.
function usedNetworks(m: Model): [number, number][] {
  const spans: [number, number][] = [];
  const add = (addr: string, prefix: number) => {
    const lo = toInt(network(addr, prefix));
    spans.push([lo, lo + 2 ** (32 - prefix) - 1]);
  };
  for (const i of m.interfaces) if (i.ipv4.mode === 'static' && i.ipv4.address && i.ipv4.prefix !== undefined) add(i.ipv4.address, i.ipv4.prefix);
  for (const t of tunnels(m)) for (const p of t.wireguard.peers) for (const n of p.networks) add(n.split('/')[0], Number(n.split('/')[1]));
  for (const r of m.routing.routes) add(r.network.split('/')[0], Number(r.network.split('/')[1]));
  return spans;
}

// A /24 for a new tunnel that nothing here uses yet: 10.8.0.0, 10.9.0.0…
function freeTunnelNetwork(m: Model): string {
  const used = usedNetworks(m);
  for (let second = 8; second < 255; second++) {
    const lo = toInt(`10.${second}.0.0`);
    if (!used.some(([a, b]) => a <= lo + 255 && lo <= b)) return `10.${second}.0.1`;
  }
  return '';
}

const routesLabel: Record<Peer['clientRoutes'], string> = { split: 'Your networks', full: 'All traffic', site: 'Site-to-site' };

// Replaces one tunnel's settings in the model.
const withTunnel = (m: Model, id: string, f: (t: Tunnel) => Iface): Model => ({
  ...m,
  interfaces: m.interfaces.map((i) => (i.id === id && i.wireguard ? f(i as Tunnel) : i)),
});

function AddTunnel({ opened, onClose, onAdded }: { opened: boolean; onClose: () => void; onAdded: (id: string) => void }) {
  const { staged, edit } = useStore();
  const wan = staged.interfaces.find((i) => i.role === 'wan');
  const vpns = tunnels(staged);
  const form = useForm({
    initialValues: { name: '', listenPort: 51820 as number | string, address: '', prefix: 24 as number | string, allow: true },
    validate: {
      name: (v) => (v.trim() && /^[A-Za-z0-9][A-Za-z0-9 _.-]{0,62}$/.test(v.trim()) ? null : 'Name the tunnel, like “Remote access” (letters, digits, spaces)'),
      listenPort: (v) => {
        const n = Number(v);
        if (!Number.isInteger(n) || n < 1 || n > 65535) return 'A port from 1 to 65535';
        const other = vpns.find((t) => t.wireguard.listenPort === n);
        return other ? `${other.name} already uses port ${n}` : null;
      },
      address: (v) => (isIPv4(v) ? null : 'The tunnel’s own address, like 10.9.0.1'),
      prefix: (v, vals) => {
        const n = Number(v);
        if (!Number.isInteger(n) || n < 8 || n > 30) return 'A prefix from 8 to 30';
        if (!isIPv4(vals.address)) return null;
        const lo = toInt(network(vals.address, n));
        const clash = usedNetworks(staged).some(([a, b]) => a <= lo + 2 ** (32 - n) - 1 && lo <= b);
        return clash ? 'This network overlaps one that’s already in use' : null;
      },
    },
  });
  useEffect(() => {
    if (!opened) return;
    const ports = new Set(vpns.map((t) => t.wireguard.listenPort));
    let port = 51820;
    while (ports.has(port)) port++;
    form.setValues({ name: '', listenPort: port, address: freeTunnelNetwork(staged), prefix: 24, allow: !!wan });
    form.clearErrors();
  }, [opened]); // form is stable

  const submit = form.onSubmit((v) => {
    const devices = new Set(staged.interfaces.map((i) => i.device));
    let n = 0;
    while (devices.has(`wg${n}`)) n++;
    const device = `wg${n}`;
    const id = staged.interfaces.some((i) => i.id === device) ? newId('wg') : device;
    const port = Number(v.listenPort);
    const tunnel: Tunnel = {
      id, name: v.name.trim(), device, role: 'vpn', enabled: true,
      ipv4: { mode: 'static', address: v.address, prefix: Number(v.prefix) }, ipv6: 'none',
      wireguard: { listenPort: port, publicKey: fakeKey(), peers: [] },
    };
    edit('interfaces', `Added WireGuard tunnel “${tunnel.name}” (${device}, ${tunnelNet(tunnel)}, port ${port})`, (m) => ({ ...m, interfaces: [...m.interfaces, tunnel] }));
    if (v.allow && wan) {
      const rule = formRule({
        id: newId('r'), interfaces: [wan.id], description: `Allow ${tunnel.name} VPN`, protocol: 'udp', destination: { type: 'self' }, port: String(port),
      });
      edit('firewall', `Added ${wan.name} rule “${rule.description}” (UDP port ${port})`, (m) => ({ ...m, firewall: { ...m.firewall, rules: [...m.firewall.rules, rule] } }));
    }
    onClose();
    onAdded(id);
  });

  return (
    <Modal opened={opened} onClose={onClose} title={<Text fw={600}>Add a WireGuard tunnel</Text>} size="md">
      <form onSubmit={submit}>
        <Stack>
          <Text size="sm" c="dimmed">
            Each tunnel is its own interface with its own port, network and devices, and its own firewall rules. Use separate tunnels
            to keep groups apart, like staff laptops and other offices.
          </Text>
          <TextInput label="Name" placeholder="Branch offices" data-autofocus {...form.getInputProps('name')} />
          <NumberInput label="Port" description="The UDP port devices connect to." min={1} max={65535} {...form.getInputProps('listenPort')} />
          <Group grow align="flex-start">
            <TextInput label="Tunnel address" description="OPF’s address inside the tunnel." styles={{ input: { fontFamily: 'var(--mantine-font-family-monospace)' } }} {...form.getInputProps('address')} />
            <NumberInput label="Prefix" description="Size of the tunnel network." min={8} max={30} {...form.getInputProps('prefix')} />
          </Group>
          {wan && <Checkbox label={`Allow connections to this port from ${wan.name}`} {...form.getInputProps('allow', { type: 'checkbox' })} />}
          <Group justify="flex-end" mt="sm">
            <Button variant="default" onClick={onClose}>Cancel</Button>
            <Button type="submit">Add tunnel</Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}

function AddPeer({ tunnel, opened, onClose }: { tunnel: Tunnel; opened: boolean; onClose: () => void }) {
  const { staged, edit } = useStore();
  const wg = tunnel.wireguard;
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
    form.setValues({ name: '', address: nextAddress(tunnel), clientRoutes: 'split', networks: [], endpoint: '' });
  }, [opened]); // form is stable

  const v = form.values;
  const wan = usePublicAddress();
  const local = useDerived(staged).data?.localNetworks ?? [];
  const allowed = v.clientRoutes === 'full' ? '0.0.0.0/0' : local.join(', ');
  const clientConfig = `[Interface]
PrivateKey = ${keys.priv}
Address = ${v.address}
DNS = ${tunnel.ipv4.address}

[Peer]
PublicKey = ${wg.publicKey}
Endpoint = ${wan}:${wg.listenPort}
AllowedIPs = ${allowed}
PersistentKeepalive = 25`;

  return (
    <Drawer opened={opened} onClose={onClose} size="xl" title={<Text fw={600} size="lg">Add a device to {tunnel.name}</Text>}>
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
            edit('wireguard', `Added VPN device “${peer.name}” to ${tunnel.name} (${peer.address}${peer.networks.length ? `, routes ${peer.networks.join(', ')}` : ''})`, (m) =>
              withTunnel(m, tunnel.id, (t) => ({ ...t, wireguard: { ...t.wireguard, peers: [...t.wireguard.peers, peer] } })));
            if (peer.networks.length) {
              // The networks behind a router peer need routes into its tunnel.
              const gw = { id: newId('gw'), name: peer.name.toUpperCase().replace(/[^A-Z0-9]+/g, '_').slice(0, 32), iface: tunnel.id, address: peer.address.split('/')[0], description: `${peer.name} over WireGuard` };
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
            <TextInput label="VPN address" description={`Picked from ${tunnelNet(tunnel)}.`} styles={{ input: { fontFamily: 'var(--mantine-font-family-monospace)' } }} {...form.getInputProps('address')} />
            <Stack gap={6}>
              <Text size="sm" fw={500}>What to tell this device to send through the VPN</Text>
              <SegmentedControl
                data={[{ value: 'split', label: 'Only your networks' }, { value: 'full', label: 'All traffic' }, { value: 'site', label: 'It’s a router (site-to-site)' }]}
                {...form.getInputProps('clientRoutes')}
              />
              <Text size="xs" c="dimmed">
                {v.clientRoutes === 'split' && `The device’s configuration sends only traffic for ${local.join(', ')} through the tunnel, and its own internet connection handles the rest. OPF also blocks anything else the device sends, so it can’t reach the internet through OPF even if its configuration is changed.`}
                {v.clientRoutes === 'full' && `The device’s configuration sends everything through the tunnel and out OPF’s internet connection, translated to the WAN address by outbound NAT. Your ${tunnel.name} rules decide what it may reach.`}
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

function TrafficFlow({ tunnel }: { tunnel: Tunnel }) {
  const { staged } = useStore();
  const publicAddress = usePublicAddress();
  const wg = tunnel.wireguard;
  const wan = staged.interfaces.find((i) => i.role === 'wan');
  const wanRule = staged.firewall.rules.find((r) => r.enabled && r.kind === 'form' && r.interfaces.includes(wan?.id ?? '') && r.protocol === 'udp' && r.port === String(wg.listenPort));
  const tunnelRules = staged.firewall.rules.filter((r) => r.enabled && !isFloating(r) && r.interfaces[0] === tunnel.id);
  const routes = staged.routing.routes.filter((r) => r.enabled && staged.routing.gateways.find((g) => g.id === r.gateway)?.iface === tunnel.id);
  const nat = staged.firewall.outboundNat;
  const automatic = useDerived(staged).data?.automaticNat ?? [];
  const natAuto = nat.mode !== 'manual' && automatic.some((n) => n.source.type === 'iface' && n.source.iface === tunnel.id);
  const fullPeers = wg.peers.filter((p) => p.clientRoutes === 'full');
  const splitPeers = wg.peers.filter((p) => p.clientRoutes === 'split');

  return (
    <Card>
      <SectionTitle>How traffic flows</SectionTitle>
      <Timeline bulletSize={28} lineWidth={2}>
        <Timeline.Item bullet={<ThemeIcon size={28} radius="xl" variant="light"><IconPlugConnected size={16} /></ThemeIcon>} title={<Text size="sm" fw={600}>Devices connect</Text>}>
          <Text size="sm" c="dimmed">
            To <Mono>{publicAddress}:{wg.listenPort}</Mono> over UDP.{' '}
            {wanRule ? (
              <>Allowed by the WAN rule <Anchor component={Link} to={`/firewall/rules/${wan?.id}`} size="sm">“{wanRule.description}”</Anchor>.</>
            ) : (
              <Text span c="red" size="sm">No WAN rule allows this port, so devices can’t connect.</Text>
            )}
          </Text>
        </Timeline.Item>
        <Timeline.Item bullet={<ThemeIcon size={28} radius="xl" variant="light"><IconArrowsSplit2 size={16} /></ThemeIcon>} title={<Text size="sm" fw={600}>Routing</Text>}>
          <Text size="sm" c="dimmed">
            Each device gets an address in <Mono>{tunnelNet(tunnel)}</Mono> on <Mono>{tunnel.device}</Mono>.
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
            <Anchor component={Link} to={`/firewall/rules/${tunnel.id}`} size="sm">{tunnelRules.length} {tunnel.name} rule{tunnelRules.length === 1 ? '' : 's'}</Anchor>
            {tunnelRules.length ? `: ${tunnelRules.map((r) => r.description).join('; ')}.` : '. With none, everything from the tunnel is blocked.'}
            {splitPeers.length > 0 && tunnel.enabled && ` Before those, OPF blocks ${splitPeers.map((p) => p.name).join(', ')} from reaching anything but your networks.`}
          </Text>
        </Timeline.Item>
        <Timeline.Item bullet={<ThemeIcon size={28} radius="xl" variant="light"><IconWorld size={16} /></ThemeIcon>} title={<Text size="sm" fw={600}>Internet access</Text>}>
          <Text size="sm" c="dimmed">
            {fullPeers.length ? `${fullPeers.map((p) => p.name).join(', ')} send${fullPeers.length === 1 ? 's' : ''} all traffic through OPF. ` : 'No device sends all its traffic through OPF. '}
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

function TunnelSettings({ tunnel }: { tunnel: Tunnel }) {
  const { staged, edit } = useStore();
  const navigate = useNavigate();
  const [deleting, setDeleting] = useState(false);
  const vpns = tunnels(staged);
  const form = useForm({
    initialValues: { name: tunnel.name, enabled: tunnel.enabled, listenPort: tunnel.wireguard.listenPort as number | string },
    validate: {
      name: (v) => (/^[A-Za-z0-9][A-Za-z0-9 _.-]{0,62}$/.test(v.trim()) ? null : 'Letters, digits and spaces'),
      listenPort: (v) => {
        const n = Number(v);
        if (!Number.isInteger(n) || n < 1 || n > 65535) return 'A port from 1 to 65535';
        const other = vpns.find((t) => t.id !== tunnel.id && t.wireguard.listenPort === n);
        return other ? `${other.name} already uses port ${n}` : null;
      },
    },
  });
  useEffect(() => {
    form.setValues({ name: tunnel.name, enabled: tunnel.enabled, listenPort: tunnel.wireguard.listenPort });
    form.resetDirty();
  }, [tunnel.id, tunnel.name, tunnel.enabled, tunnel.wireguard.listenPort]); // form is stable

  const save = form.onSubmit((x) => {
    const name = x.name.trim();
    if (name !== tunnel.name || x.enabled !== tunnel.enabled) {
      const what = x.enabled !== tunnel.enabled ? `${x.enabled ? 'Turned on' : 'Turned off'} WireGuard tunnel “${name}”` : `Renamed WireGuard tunnel “${tunnel.name}” to “${name}”`;
      edit('interfaces', what, (m) => withTunnel(m, tunnel.id, (t) => ({ ...t, name, enabled: x.enabled })));
    }
    const port = Number(x.listenPort);
    if (port !== tunnel.wireguard.listenPort) {
      edit('wireguard', `${name} now listens on port ${port}`, (m) => withTunnel(m, tunnel.id, (t) => ({ ...t, wireguard: { ...t.wireguard, listenPort: port } })));
    }
  });

  return (
    <Card>
      <form onSubmit={save}>
        <SectionTitle right={<Switch label="Enabled" {...form.getInputProps('enabled', { type: 'checkbox' })} />}>Tunnel</SectionTitle>
        <Stack gap="md">
          <TextInput label="Name" {...form.getInputProps('name')} />
          <NumberInput label="Port" min={1} max={65535} {...form.getInputProps('listenPort')} />
          <Stack gap={2}>
            <Text size="sm" fw={500}>Tunnel address</Text>
            <Group gap="xs">
              <Mono>{tunnel.ipv4.address}/{tunnel.ipv4.prefix}</Mono>
              <Text size="xs" c="dimmed">on <Mono>{tunnel.device}</Mono> · <Anchor component={Link} to={`/interfaces/${tunnel.id}`} size="xs">change</Anchor></Text>
            </Group>
          </Stack>
          <Stack gap={2}>
            <Text size="sm" fw={500}>Public key</Text>
            <Copyable value={tunnel.wireguard.publicKey} />
          </Stack>
          <Group justify="space-between">
            <Button variant="subtle" color="red" onClick={() => setDeleting(true)}>Delete tunnel</Button>
            <Button type="submit" disabled={!form.isDirty()}>Save</Button>
          </Group>
        </Stack>
      </form>
      <DeleteInterface iface={tunnel} kind="WireGuard tunnel" opened={deleting} onClose={() => setDeleting(false)} onDeleted={() => navigate('/services/wireguard')} />
    </Card>
  );
}

// The device's configuration after an edit. Its private key is the one
// it already has: OPF never sees it again after creating the device.
function deviceConfig(local: string[], wan: string, t: Tunnel, p: Pick<Peer, 'address' | 'clientRoutes'>): string {
  const allowed = p.clientRoutes === 'full' ? '0.0.0.0/0' : local.join(', ');
  return `[Interface]
PrivateKey = <the device’s existing private key>
Address = ${p.address}
DNS = ${t.ipv4.address}

[Peer]
PublicKey = ${t.wireguard.publicKey}
Endpoint = ${wan}:${t.wireguard.listenPort}
AllowedIPs = ${allowed}
PersistentKeepalive = 25`;
}

// Keeps a site-to-site peer's gateway and routes in step with it: the
// gateway follows the peer's address, and its routes the networks behind
// it. A peer that stops being a router loses its routes, and its gateway
// unless a rule still routes through it.
function syncPeerRouting(m: Model, t: Tunnel, before: Peer, after: Peer): Model {
  const oldIP = before.address.split('/')[0];
  const newIP = after.address.split('/')[0];
  const gw = m.routing.gateways.find((g) => g.iface === t.id && g.address === oldIP);
  const nets = after.clientRoutes === 'site' ? after.networks : [];
  let gateways = m.routing.gateways;
  let routes = m.routing.routes;
  if (nets.length) {
    const g = gw
      ? { ...gw, address: newIP }
      : { id: newId('gw'), name: after.name.toUpperCase().replace(/[^A-Z0-9]+/g, '_').slice(0, 32), iface: t.id, address: newIP, description: `${after.name} over WireGuard` };
    gateways = gw ? gateways.map((x) => (x.id === gw.id ? g : x)) : [...gateways, g];
    const kept = routes.filter((r) => r.gateway !== g.id || nets.includes(r.network));
    const have = new Set(kept.filter((r) => r.gateway === g.id).map((r) => r.network));
    routes = [...kept, ...nets.filter((n) => !have.has(n)).map((n) => ({ id: newId('rt'), enabled: true, network: n, gateway: g.id, description: after.name }))];
  } else if (gw) {
    routes = routes.filter((r) => r.gateway !== gw.id);
    const used = m.routing.defaultGateway === gw.id || m.firewall.rules.some((r) => r.kind === 'form' && (r.gateway === gw.id || r.replyTo === gw.id));
    gateways = used ? gateways.map((x) => (x.id === gw.id ? { ...gw, address: newIP } : x)) : gateways.filter((x) => x.id !== gw.id);
  }
  return { ...m, routing: { ...m.routing, gateways, routes } };
}

function EditPeer({ tunnel, peer, onClose }: { tunnel: Tunnel; peer: Peer | null; onClose: () => void }) {
  const { staged, edit } = useStore();
  const [saved, setSaved] = useState<Peer | null>(null);
  const local = useDerived(staged).data?.localNetworks ?? [];
  const wan = usePublicAddress();
  const form = useForm({
    initialValues: { name: '', address: '', clientRoutes: 'split' as Peer['clientRoutes'], networks: [] as string[], endpoint: '', keepalive: 25 as number | string },
    validate: {
      name: (v) => (v.trim() ? null : 'Name the device'),
      address: (v) => (isCIDR(v) ? null : 'An address in the tunnel, like 10.8.0.5/32'),
      networks: (v, vals) => (vals.clientRoutes !== 'site' || (v.length && v.every(isCIDR)) ? null : 'Enter the networks behind this router, like 10.30.0.0/16'),
      keepalive: (v) => (v === '' || (Number.isInteger(Number(v)) && Number(v) >= 0 && Number(v) <= 65535) ? null : 'Seconds, 0 to 65535'),
    },
  });
  useEffect(() => {
    if (!peer) return;
    setSaved(null);
    form.setValues({ name: peer.name, address: peer.address, clientRoutes: peer.clientRoutes, networks: peer.networks, endpoint: peer.endpoint ?? '', keepalive: peer.keepalive ?? '' });
    form.resetDirty();
  }, [peer]); // form is stable

  if (!peer) return null;
  const v = form.values;
  const save = form.onSubmit((x) => {
    const after: Peer = {
      ...peer, name: x.name.trim(), address: x.address, clientRoutes: x.clientRoutes,
      networks: x.clientRoutes === 'site' ? x.networks : [],
      ...(x.clientRoutes === 'site' && x.endpoint ? { endpoint: x.endpoint } : { endpoint: undefined }),
      keepalive: x.keepalive === '' ? undefined : Number(x.keepalive),
    };
    edit('wireguard', `Edited VPN device “${after.name}” on ${tunnel.name}`, (m) =>
      syncPeerRouting(withTunnel(m, tunnel.id, (t) => ({ ...t, wireguard: { ...t.wireguard, peers: t.wireguard.peers.map((p) => (p.id === peer.id ? after : p)) } })), tunnel, peer, after));
    // The device only needs a new configuration when what it's told changes.
    if (after.address !== peer.address || after.clientRoutes !== peer.clientRoutes) setSaved(after);
    else onClose();
  });

  return (
    <Drawer opened onClose={onClose} size="xl" title={<Text fw={600} size="lg">Edit {peer.name}</Text>}>
      {saved ? (
        <Stack>
          <Alert color="yellow" variant="light" icon={<IconAlertTriangle size={18} />} title="Update the device too">
            Its address or what it sends through the VPN changed, so the device needs the new settings below. Keep the private key it already has.
          </Alert>
          <Code block>{deviceConfig(local, wan, tunnel, saved)}</Code>
          <Group justify="flex-end">
            <CopyButton value={deviceConfig(local, wan, tunnel, saved)}>
              {({ copied, copy }) => (
                <Button variant="light" leftSection={copied ? <IconCheck size={16} /> : <IconCopy size={16} />} onClick={copy}>{copied ? 'Copied' : 'Copy configuration'}</Button>
              )}
            </CopyButton>
            <Button onClick={onClose}>Done</Button>
          </Group>
        </Stack>
      ) : (
        <form onSubmit={save}>
          <Stack>
            <TextInput label="Device name" {...form.getInputProps('name')} />
            <TextInput label="VPN address" description={`In ${tunnelNet(tunnel)}.`} styles={{ input: { fontFamily: 'var(--mantine-font-family-monospace)' } }} {...form.getInputProps('address')} />
            <Stack gap={6}>
              <Text size="sm" fw={500}>What to tell this device to send through the VPN</Text>
              <SegmentedControl
                data={[{ value: 'split', label: 'Only your networks' }, { value: 'full', label: 'All traffic' }, { value: 'site', label: 'It’s a router (site-to-site)' }]}
                {...form.getInputProps('clientRoutes')}
              />
            </Stack>
            {v.clientRoutes === 'site' && (
              <>
                <TagsInput label="Networks behind this router" placeholder="10.30.0.0/16" {...form.getInputProps('networks')} />
                <TextInput label="Its public address" description="Optional. Lets OPF start the connection." placeholder="branch.example.net:51820" {...form.getInputProps('endpoint')} />
              </>
            )}
            <NumberInput label="Keepalive" description="Seconds between keepalive packets; empty for none." min={0} max={65535} {...form.getInputProps('keepalive')} />
            <Text size="xs" c="dimmed">The device’s key stays the same. To replace it, remove the device and add it again.</Text>
            <HistoryCard
              title="Traffic"
              series={[{ key: `wg.${peer.id}.rx`, label: 'From the device', color: 'harbor.6' }, { key: `wg.${peer.id}.tx`, label: 'To the device', color: 'amber.6' }]}
              format={formatBits}
              h={150}
              empty="Nothing recorded for this device yet."
            />
            <Group justify="flex-end" mt="sm">
              <Button variant="default" onClick={onClose}>Cancel</Button>
              <Button type="submit" disabled={!form.isDirty()}>Save</Button>
            </Group>
          </Stack>
        </form>
      )}
    </Drawer>
  );
}

function Devices({ tunnel }: { tunnel: Tunnel }) {
  const { edit } = useStore();
  const { data: live } = useLive('interfaces');
  const [editing, setEditing] = useState<Peer | null>(null);
  return (
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
            {tunnel.wireguard.peers.length === 0 && (
              <Table.Tr><Table.Td colSpan={6}><Text size="sm" c="dimmed" ta="center" py="md">No devices yet.</Text></Table.Td></Table.Tr>
            )}
            {tunnel.wireguard.peers.map((p) => {
              const s = peerState(live, tunnel, p);
              const online = peerOnline(s);
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
                    {s?.handshakeAgo !== undefined ? (online ? <Badge color="teal">Online</Badge> : <Text size="sm" c="dimmed">{formatAgo(s.handshakeAgo)}</Text>) : <Text size="sm" c="dimmed">{live ? 'Never' : '…'}</Text>}
                  </Table.Td>
                  <Table.Td ta="right"><Text size="sm" className="num">{s ? `↓ ${formatBytes(s.txBytes)} · ↑ ${formatBytes(s.rxBytes)}` : '—'}</Text></Table.Td>
                  <Table.Td w={88}>
                    <Group gap={4} wrap="nowrap">
                    <Tooltip label="Edit device">
                      <ActionIcon variant="subtle" color="gray" aria-label="Edit device" onClick={() => setEditing(p)}>
                        <IconPencil size={16} />
                      </ActionIcon>
                    </Tooltip>
                    <Tooltip label="Remove device">
                      <ActionIcon
                        variant="subtle" color="gray" aria-label="Remove device"
                        onClick={() => edit('wireguard', `Removed VPN device “${p.name}” from ${tunnel.name}${p.networks.length ? `, and its routes to ${p.networks.join(', ')}` : ''}`, (m) =>
                          // A router's routes, and its gateway unless a rule still uses it, go with it.
                          syncPeerRouting(withTunnel(m, tunnel.id, (t) => ({ ...t, wireguard: { ...t.wireguard, peers: t.wireguard.peers.filter((x) => x.id !== p.id) } })),
                            tunnel, p, { ...p, clientRoutes: 'split', networks: [] }))}
                      >
                        <IconTrash size={16} />
                      </ActionIcon>
                    </Tooltip>
                    </Group>
                  </Table.Td>
                </Table.Tr>
              );
            })}
          </Table.Tbody>
        </Table>
      </Table.ScrollContainer>
      <EditPeer tunnel={tunnel} peer={editing} onClose={() => setEditing(null)} />
    </Card>
  );
}

// The tunnel's traffic over time: all of it, and each device's, in
// and out added together.
const deviceColors = ['harbor.6', 'amber.6', 'grape.6', 'teal.6', 'pink.6', 'lime.6', 'indigo.6', 'orange.6'];

function TunnelTraffic({ tunnel }: { tunnel: Tunnel }) {
  const series = [
    { key: `if.${tunnel.device}.rx`, plus: `if.${tunnel.device}.tx`, label: 'All devices', color: 'gray.5' },
    ...tunnel.wireguard.peers.map((p, i) => ({ key: `wg.${p.id}.rx`, plus: `wg.${p.id}.tx`, label: p.name, color: deviceColors[i % deviceColors.length] })),
  ];
  return (
    <Card>
      <HistoryCard title="Traffic" series={series} format={formatBits} h={180} empty="Nothing recorded for this tunnel yet." />
    </Card>
  );
}

export function WireGuardPage() {
  const { staged } = useStore();
  const { tunnel: param } = useParams();
  const navigate = useNavigate();
  const vpns = tunnels(staged);
  const tunnel = vpns.find((t) => t.id === param) ?? vpns[0];
  const [adding, setAdding] = useState(false);
  const [addingTunnel, setAddingTunnel] = useState(false);

  return (
    <>
      <PageHeader
        title="WireGuard VPN"
        description="Lets phones, laptops and other sites reach your networks securely from anywhere."
        actions={
          <Group gap="sm">
            <Button variant="default" leftSection={<IconPlus size={16} />} onClick={() => setAddingTunnel(true)}>Add tunnel</Button>
            {tunnel && <Button leftSection={<IconPlus size={16} />} onClick={() => setAdding(true)}>Add device</Button>}
          </Group>
        }
      />
      {!tunnel ? (
        <Card>
          <Stack align="center" py="xl" gap="sm">
            <Text fw={600}>No tunnels yet</Text>
            <Text size="sm" c="dimmed" ta="center" maw={420}>A tunnel is a VPN network devices connect to. Add one, then add the devices that may use it.</Text>
            <Button leftSection={<IconPlus size={16} />} onClick={() => setAddingTunnel(true)}>Add tunnel</Button>
          </Stack>
        </Card>
      ) : (
        <>
          {vpns.length > 1 && (
            <Tabs value={tunnel.id} onChange={(v) => v && navigate(`/services/wireguard/${v}`)} mb="md">
              <Tabs.List>
                {vpns.map((t) => (
                  <Tabs.Tab key={t.id} value={t.id} rightSection={<Badge size="sm" color="gray" circle>{t.wireguard.peers.length}</Badge>}>
                    {t.name}{!t.enabled && <Text span size="xs" c="dimmed"> (off)</Text>}
                  </Tabs.Tab>
                ))}
              </Tabs.List>
            </Tabs>
          )}
          <Grid gutter="md">
            <Grid.Col span={12}>
              <TunnelTraffic tunnel={tunnel} />
            </Grid.Col>
            <Grid.Col span={{ base: 12, lg: 5 }}>
              <TunnelSettings tunnel={tunnel} />
            </Grid.Col>
            <Grid.Col span={{ base: 12, lg: 7 }}>
              <TrafficFlow tunnel={tunnel} />
            </Grid.Col>
            <Grid.Col span={12}>
              <Devices tunnel={tunnel} />
            </Grid.Col>
          </Grid>
          <AddPeer tunnel={tunnel} opened={adding} onClose={() => setAdding(false)} />
        </>
      )}
      <AddTunnel opened={addingTunnel} onClose={() => setAddingTunnel(false)} onAdded={(id) => navigate(`/services/wireguard/${id}`)} />
    </>
  );
}
