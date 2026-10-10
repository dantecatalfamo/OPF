// Ways out: tunnels to a VPN provider that some networks leave through,
// appearing at the provider's address, while OPF's own traffic keeps
// the normal way out. The rest of the WireGuard page is about tunnels
// devices connect in to.
import { useEffect, useState } from 'react';
import { Link } from 'react-router';
import { Alert, Anchor, Badge, Button, Card, Group, Modal, MultiSelect, NumberInput, Stack, Switch, TagsInput, Text, Textarea, TextInput, ThemeIcon, Timeline } from '@mantine/core';
import { useForm } from '@mantine/form';
import { IconAlertTriangle, IconArrowsSplit2, IconLock, IconPlugConnected, IconWorld } from '@tabler/icons-react';
import { backend, useStore } from '../model/store';
import { tunnels, upstream, type Iface, type Model, type Tunnel } from '../model/types';
import { peerOnline, peerState, useLive } from '../lib/live';
import { formatAgo, formatBytes } from '../lib/format';
import { isIPv4 } from '../lib/ip';
import { Mono, SectionTitle } from '../components/ui';
import { DeleteInterface } from '../components/DeleteInterface';
import { PeerNameCheck } from '../components/PeerNameCheck';
import { Copyable, withTunnel } from './WireGuard';
import { FileLink } from './ConfigFiles';

/** What OPF needs from a provider's WireGuard configuration. */
export interface ProviderConfig {
  privateKey: string;
  address: string;
  prefix: number;
  dns: string[];
  publicKey: string;
  presharedKey?: string;
  endpoint: string;
  keepalive?: number;
}

const keyRE = /^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$/;

/** parseProviderConfig reads the wg-quick file a VPN provider hands out:
 *  [Interface] PrivateKey, Address, DNS; [Peer] PublicKey, PresharedKey,
 *  Endpoint, PersistentKeepalive. IPv6 addresses are left out (OPF's
 *  tunnels are IPv4), and AllowedIPs too: everything goes to the
 *  provider. */
export function parseProviderConfig(text: string): { config?: ProviderConfig; problems: string[] } {
  const sections: { name: string; values: Record<string, string> }[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/[#;].*$/, '').trim();
    if (!line) continue;
    const head = /^\[(\w+)\]$/.exec(line);
    if (head) {
      sections.push({ name: head[1].toLowerCase(), values: {} });
      continue;
    }
    const eq = line.indexOf('=');
    if (eq < 0 || !sections.length) continue;
    sections[sections.length - 1].values[line.slice(0, eq).trim().toLowerCase()] = line.slice(eq + 1).trim();
  }
  const iface = sections.filter((s) => s.name === 'interface');
  const peers = sections.filter((s) => s.name === 'peer');
  const problems: string[] = [];
  if (iface.length !== 1) problems.push('It needs one [Interface] section.');
  if (peers.length !== 1) problems.push(peers.length ? 'It has more than one [Peer]. Pick one server’s configuration.' : 'It needs a [Peer] section for the provider’s server.');
  if (problems.length) return { problems };
  const i = iface[0].values;
  const p = peers[0].values;
  const list = (v = '') => v.split(',').map((x) => x.trim()).filter(Boolean);
  const v4 = list(i.address).find((a) => isIPv4(a.split('/')[0]));
  const dns = list(i.dns).filter(isIPv4);
  if (!keyRE.test(i.privatekey ?? '')) problems.push('Its PrivateKey isn’t a WireGuard key.');
  if (!v4) problems.push('It has no IPv4 Address.');
  if (!keyRE.test(p.publickey ?? '')) problems.push('The peer’s PublicKey isn’t a WireGuard key.');
  if (p.presharedkey && !keyRE.test(p.presharedkey)) problems.push('The peer’s PresharedKey isn’t a WireGuard key.');
  if (!/^(\[[0-9a-f:]+\]|[A-Za-z0-9.-]+):\d{1,5}$/i.test(p.endpoint ?? '')) problems.push('The peer has no Endpoint (host:port).');
  if (problems.length) return { problems };
  const [address, bits] = v4!.split('/');
  const keepalive = Number(p.persistentkeepalive);
  return {
    problems,
    config: {
      privateKey: i.privatekey, address, prefix: bits ? Number(bits) : 32, dns, publicKey: p.publickey,
      presharedKey: p.presharedkey || undefined, endpoint: p.endpoint, keepalive: Number.isInteger(keepalive) && keepalive > 0 ? keepalive : 25,
    },
  };
}

// The interfaces whose networks may leave through a way out.
const insidesOf = (m: Model): Iface[] => m.interfaces.filter((i) => i.role === 'lan' || i.role === 'opt');

// Networks already leaving through another way out.
const takenFrom = (m: Model, except?: string) =>
  new Map(tunnels(m).filter((t) => t.wireguard.exit && t.id !== except).flatMap((t) => t.wireguard.exit!.from.map((id) => [id, t.name] as const)));

export function AddExit({ opened, onClose, onAdded }: { opened: boolean; onClose: () => void; onAdded: (id: string) => void }) {
  const { staged, edit } = useStore();
  const insides = insidesOf(staged);
  const taken = takenFrom(staged);
  const [text, setText] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const parsed = text.trim() ? parseProviderConfig(text) : undefined;
  const form = useForm({
    initialValues: { name: 'VPN provider', from: [] as string[], dns: true },
    validate: {
      name: (v) => (/^[A-Za-z0-9][A-Za-z0-9 _.-]{0,62}$/.test(v.trim()) ? null : 'Use letters, digits and spaces'),
      from: (v) => (v.length ? null : 'Pick the networks that leave through it'),
    },
  });
  useEffect(() => {
    if (!opened) return;
    setText('');
    setError(undefined);
    const lan = insides.find((i) => i.role === 'lan' && !taken.has(i.id));
    form.setValues({ name: 'VPN provider', from: lan ? [lan.id] : [], dns: true });
    form.clearErrors();
  }, [opened]); // form is stable

  const submit = form.onSubmit(async (v) => {
    const c = parsed?.config;
    if (!c) return;
    const devices = new Set(staged.interfaces.map((i) => i.device));
    let n = 0;
    while (devices.has(`wg${n}`)) n++;
    if (n > 55) {
      setError('Every device from wg0 to wg55 is taken. Each way out uses routing table 200 plus its device number, and 255 is the highest table.');
      return;
    }
    setBusy(true);
    setError(undefined);
    try {
      // The private key goes to the firewall, which keeps it root-only
      // as it keeps its own; the model only gets the public one.
      const publicKey = await backend.importTunnelKey(c.privateKey);
      const psk = c.presharedKey ? (await backend.setPresharedKey(c.presharedKey)).id : undefined;
      const device = `wg${n}`;
      const id = staged.interfaces.some((i) => i.id === device) ? `exit${n}` : device;
      const tunnel: Tunnel = {
        id, name: v.name.trim(), device, role: 'vpn', enabled: true,
        ipv4: { mode: 'static', address: c.address, prefix: c.prefix }, ipv6: 'none',
        wireguard: {
          listenPort: 0, publicKey, peers: [],
          exit: {
            publicKey: c.publicKey, endpoint: c.endpoint, keepalive: c.keepalive, from: v.from,
            ...(psk ? { presharedKey: psk } : {}), ...(v.dns && c.dns.length ? { dns: c.dns } : {}),
          },
        },
      };
      const names = v.from.map((x) => insides.find((i) => i.id === x)?.name ?? x).join(' and ');
      edit('interfaces', `Added way out “${tunnel.name}” (${device}, through ${c.endpoint}) for ${names}`, (m) => ({ ...m, interfaces: [...m.interfaces, tunnel] }));
      onClose();
      onAdded(id);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  });

  const c = parsed?.config;
  return (
    <Modal opened={opened} onClose={onClose} title={<Text fw={600}>Add a way out through a VPN provider</Text>} size="lg">
      <form onSubmit={submit}>
        <Stack>
          <Text size="sm" c="dimmed">
            The networks you pick reach the internet through the provider and appear at its address. If the tunnel is down,
            their traffic stops rather than going out with your own address. OPF’s own traffic, such as updates, downloads and the
            tunnel itself, keeps going out the usual way.
          </Text>
          <Textarea
            label="The provider’s WireGuard configuration" description="The .conf file it gives you. Its private key is kept on the firewall, readable only by root."
            placeholder={'[Interface]\nPrivateKey = …\nAddress = 10.64.1.2/32\nDNS = 10.64.0.1\n\n[Peer]\nPublicKey = …\nEndpoint = vpn.example.net:51820'}
            autosize minRows={7} maxRows={14} spellCheck={false} styles={{ input: { fontFamily: 'var(--mantine-font-family-monospace)', fontSize: 12 } }}
            value={text} onChange={(e) => setText(e.currentTarget.value)} data-autofocus
          />
          {parsed && parsed.problems.length > 0 && (
            <Alert color="red" variant="light" p="sm">{parsed.problems.join(' ')}</Alert>
          )}
          {c && (
            <Text size="sm">
              Tunnel address <Mono>{c.address}/{c.prefix}</Mono>, to <Mono>{c.endpoint}</Mono>
              {c.dns.length > 0 && <>, its DNS <Mono>{c.dns.join(', ')}</Mono></>}{c.presharedKey ? ', with a preshared key' : ''}.
            </Text>
          )}
          {c && <PeerNameCheck endpoint={c.endpoint} />}
          <TextInput label="Name" {...form.getInputProps('name')} />
          <MultiSelect label="Networks that leave through it"
            data={insides.map((i) => ({ value: i.id, label: taken.has(i.id) ? `${i.name} (leaves through ${taken.get(i.id)})` : i.name, disabled: taken.has(i.id) }))}
            {...form.getInputProps('from')} />
          {c && c.dns.length > 0 && (
            <Switch label="Ask the provider’s DNS" description={`OPF’s resolver sends every lookup to ${c.dns.join(', ')} through the tunnel, so no lookup leaves from your own address. Devices still ask OPF, so its local names and blocking keep working.`}
              {...form.getInputProps('dns', { type: 'checkbox' })} />
          )}
          {error && <Alert color="red" variant="light" p="sm">{error}</Alert>}
          <Group justify="flex-end" mt="sm">
            <Button variant="default" onClick={onClose}>Cancel</Button>
            <Button type="submit" loading={busy} disabled={!c}>Add way out</Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}

export function ExitSettings({ tunnel, onDeleted }: { tunnel: Tunnel; onDeleted: () => void }) {
  const { staged, edit } = useStore();
  const e = tunnel.wireguard.exit!;
  const insides = insidesOf(staged);
  const taken = takenFrom(staged, tunnel.id);
  const [deleting, setDeleting] = useState(false);
  const values = () => ({ name: tunnel.name, enabled: tunnel.enabled, endpoint: e.endpoint, keepalive: (e.keepalive ?? '') as number | string, from: e.from, dns: e.dns ?? [] });
  const form = useForm({
    initialValues: values(),
    validate: {
      name: (v) => (/^[A-Za-z0-9][A-Za-z0-9 _.-]{0,62}$/.test(v.trim()) ? null : 'Use letters, digits and spaces'),
      endpoint: (v) => (/^(\[[0-9a-f:]+\]|[A-Za-z0-9.-]+):\d{1,5}$/i.test(v.trim()) ? null : 'Enter host:port, like vpn.example.net:51820'),
      dns: (v) => (v.every(isIPv4) ? null : 'Enter IPv4 addresses only'),
    },
  });
  useEffect(() => {
    form.setValues(values());
    form.resetDirty();
  }, [JSON.stringify(tunnel)]); // form is stable

  const save = form.onSubmit((x) => {
    const name = x.name.trim();
    const keepalive = x.keepalive === '' ? undefined : Number(x.keepalive);
    const exit = {
      ...e, endpoint: x.endpoint.trim(), keepalive, from: x.from,
      dns: x.dns.length ? x.dns : undefined,
    };
    for (const k of ['keepalive', 'dns'] as const) if (exit[k] === undefined) delete exit[k];
    edit('wireguard', `Changed way out “${name}”`, (m) => withTunnel(m, tunnel.id, (t) => ({ ...t, name, enabled: x.enabled, wireguard: { ...t.wireguard, exit } })));
  });

  return (
    <Card>
      <form onSubmit={save}>
        <SectionTitle right={<Switch label="Enabled" {...form.getInputProps('enabled', { type: 'checkbox' })} />}>Way out</SectionTitle>
        <Stack gap="md">
          <TextInput label="Name" {...form.getInputProps('name')} />
          <TextInput label="Provider’s server" spellCheck={false} {...form.getInputProps('endpoint')} />
          <PeerNameCheck endpoint={form.values.endpoint} />
          <MultiSelect label="Networks that leave through it"
            data={insides.map((i) => ({ value: i.id, label: taken.has(i.id) ? `${i.name} (leaves through ${taken.get(i.id)})` : i.name, disabled: taken.has(i.id) }))}
            {...form.getInputProps('from')} />
          <TagsInput label="Provider’s DNS" placeholder="None: OPF resolves as usual" spellCheck={false}
            description="OPF’s resolver sends every lookup to these servers through the tunnel."
            inputWrapperOrder={['label', 'input', 'description', 'error']} {...form.getInputProps('dns')} />
          <NumberInput label="Keepalive" description="Seconds between keepalive packets. Leave it empty to send none." min={0} max={65535} {...form.getInputProps('keepalive')} />
          <Stack gap={2}>
            <Text size="sm" fw={500}>Tunnel address</Text>
            <Text size="sm"><Mono>{tunnel.ipv4.address}/{tunnel.ipv4.prefix}</Mono> <Text span size="xs" c="dimmed">on <Mono>{tunnel.device}</Mono>, from the provider · <FileLink path={`/etc/hostname.${tunnel.device}`} /></Text></Text>
          </Stack>
          <Stack gap={2}>
            <Text size="sm" fw={500}>Provider’s public key</Text>
            <Copyable value={e.publicKey} />
          </Stack>
          <Group justify="space-between">
            <Button variant="subtle" color="red" onClick={() => setDeleting(true)}>Delete way out</Button>
            <Button type="submit" disabled={!form.isDirty()}>Save</Button>
          </Group>
        </Stack>
      </form>
      <DeleteInterface iface={tunnel} kind="way out" opened={deleting} onClose={() => setDeleting(false)} onDeleted={onDeleted} />
    </Card>
  );
}

export function ExitFlow({ tunnel }: { tunnel: Tunnel }) {
  const { staged } = useStore();
  const { data: live } = useLive('interfaces');
  const e = tunnel.wireguard.exit!;
  const s = peerState(live, tunnel, e);
  const online = peerOnline(s);
  const from = e.from.map((id) => staged.interfaces.find((i) => i.id === id)).filter((i): i is Iface => !!i);
  const names = from.map((i) => i.name).join(' and ') || 'No network';
  const out = upstream(staged);
  const table = 200 + Number(tunnel.device.replace(/^wg/, ''));
  return (
    <Card>
      <SectionTitle right={<Badge color={online ? 'teal' : tunnel.enabled ? 'red' : 'gray'}>{online ? 'Connected' : tunnel.enabled ? 'Not connected' : 'Off'}</Badge>}>How traffic flows</SectionTitle>
      <Timeline bulletSize={28} lineWidth={2}>
        <Timeline.Item bullet={<ThemeIcon size={28} radius="xl" variant="light"><IconPlugConnected size={16} /></ThemeIcon>} title={<Text size="sm" fw={600}>The tunnel</Text>}>
          <Text size="sm" c="dimmed">
            Connects to <Mono>{e.endpoint}</Mono>.
            {s?.handshakeAgo !== undefined ? ` Last handshake ${formatAgo(s.handshakeAgo)}.` : s?.lastSeen ? ` Last seen ${formatAgo((Date.now() - Date.parse(s.lastSeen)) / 1000)}.` : ' No handshake yet.'}
            {s && ` It has received ${formatBytes(s.rxBytes)} and sent ${formatBytes(s.txBytes)}.`} The tunnel itself goes out through {out?.name ?? 'the default route'}, like OPF’s own traffic.
          </Text>
        </Timeline.Item>
        <Timeline.Item bullet={<ThemeIcon size={28} radius="xl" variant="light"><IconArrowsSplit2 size={16} /></ThemeIcon>} title={<Text size="sm" fw={600}>Who leaves through it</Text>}>
          <Text size="sm" c="dimmed">
            {names} send{from.length === 1 ? 's' : ''} all traffic that leaves your networks through it, using the tunnel’s address. On the internet, {from.length === 1 ? 'it appears' : 'they appear'} at the provider’s address.
            Each network’s own rules still decide what may leave. OPF only chooses the route, using routing table {table}. Traffic between your networks, and to OPF itself, stays local.
          </Text>
        </Timeline.Item>
        <Timeline.Item bullet={<ThemeIcon size={28} radius="xl" variant="light"><IconLock size={16} /></ThemeIcon>} title={<Text size="sm" fw={600}>If the tunnel is down</Text>}>
          <Text size="sm" c="dimmed">Their traffic stops. It has no other way out, so nothing leaves with your own address. It starts flowing again by itself once the tunnel is back.</Text>
        </Timeline.Item>
        <Timeline.Item bullet={<ThemeIcon size={28} radius="xl" variant="light"><IconWorld size={16} /></ThemeIcon>} title={<Text size="sm" fw={600}>DNS</Text>}>
          {e.dns?.length ? (
            <Text size="sm" c="dimmed">
              OPF’s resolver sends every lookup to the provider’s <Mono>{e.dns.join(', ')}</Mono> through the tunnel. Devices still ask OPF, so
              its <Anchor component={Link} to="/services/dns" size="sm">local names and blocking</Anchor> still work.
            </Text>
          ) : (
            <Text size="sm" c="yellow">
              <IconAlertTriangle size={14} style={{ verticalAlign: -2 }} /> Devices ask OPF, which looks names up from your own address. Anyone watching your
              connection can see which sites they visit. Add the provider’s DNS servers to send lookups through the tunnel.
            </Text>
          )}
        </Timeline.Item>
      </Timeline>
    </Card>
  );
}
