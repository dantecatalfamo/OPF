import { useEffect, useState } from 'react';
import { ActionIcon, Alert, Badge, Button, Card, Code, CopyButton, Drawer, Grid, Group, NumberInput, Stack, Switch, Table, Text, TextInput, Tooltip } from '@mantine/core';
import { useForm } from '@mantine/form';
import { IconCheck, IconCopy, IconInfoCircle, IconPlus, IconTrash } from '@tabler/icons-react';
import { newId, useStore } from '../model/store';
import { ifaceStatus, peerStatus } from '../model/live';
import type { Peer } from '../model/types';
import { formatAgo, formatBytes } from '../lib/format';
import { Mono, PageHeader, SectionTitle, StatusDot } from '../components/ui';

// Stand-in for a real key pair; the appliance generates these with wg(8) semantics.
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

function AddPeer({ opened, onClose }: { opened: boolean; onClose: () => void }) {
  const { staged, edit } = useStore();
  const wg = staged.wireguard;
  const [keys, setKeys] = useState({ priv: '', pub: '' });
  const [created, setCreated] = useState<Peer | null>(null);
  const form = useForm({
    initialValues: { name: '', address: '', fullTunnel: false },
    validate: { name: (v) => (v.trim() ? null : 'Name the device, like “Alex phone”') },
  });
  useEffect(() => {
    if (!opened) return;
    setKeys({ priv: fakeKey(), pub: fakeKey() });
    setCreated(null);
    form.setValues({ name: '', address: nextAddress(wg.peers, wg.address), fullTunnel: false });
  }, [opened]); // form is stable

  const wan = ifaceStatus.wan?.address?.split('/')[0] ?? 'your-public-address';
  const lan = staged.interfaces.find((i) => i.role === 'lan');
  const allowed = form.values.fullTunnel ? '0.0.0.0/0' : `${wg.address.replace(/\.\d+\/\d+$/, '.0/24')}, ${lan?.ipv4.address?.replace(/\d+$/, '0')}/${lan?.ipv4.prefix}`;
  const clientConfig = `[Interface]
PrivateKey = ${keys.priv}
Address = ${form.values.address}
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
            Import this configuration into the WireGuard app on the device. It contains the device’s private key, so
            OPF won’t show it again.
          </Alert>
          <Code block>{clientConfig}</Code>
          <Group justify="flex-end">
            <CopyButton value={clientConfig}>
              {({ copied, copy }) => (
                <Button variant="light" leftSection={copied ? <IconCheck size={16} /> : <IconCopy size={16} />} onClick={copy}>
                  {copied ? 'Copied' : 'Copy configuration'}
                </Button>
              )}
            </CopyButton>
            <Button onClick={onClose}>Done</Button>
          </Group>
        </Stack>
      ) : (
        <form
          onSubmit={form.onSubmit((v) => {
            const peer: Peer = { id: newId('p'), name: v.name.trim(), publicKey: keys.pub, address: v.address, keepalive: 25 };
            edit('wireguard', `Added VPN device “${peer.name}” (${peer.address})`, (m) => ({ ...m, wireguard: { ...m.wireguard, peers: [...m.wireguard.peers, peer] } }));
            setCreated(peer);
          })}
        >
          <Stack>
            <Text size="sm" c="dimmed">OPF creates the keys and a ready-made configuration for the WireGuard app on the phone or laptop.</Text>
            <TextInput label="Device name" placeholder="Alex phone" data-autofocus {...form.getInputProps('name')} />
            <TextInput label="VPN address" description="Picked automatically from the tunnel network." styles={{ input: { fontFamily: 'var(--mantine-font-family-monospace)' } }} {...form.getInputProps('address')} />
            <Switch
              label="Send all of the device’s traffic through the office"
              description="Otherwise only traffic for the office networks uses the VPN."
              {...form.getInputProps('fullTunnel', { type: 'checkbox' })}
            />
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
        <Grid.Col span={{ base: 12, lg: 4 }}>
          <Card>
            <form
              onSubmit={form.onSubmit((v) =>
                edit('wireguard', v.enabled !== wg.enabled ? `${v.enabled ? 'Turned on' : 'Turned off'} WireGuard VPN` : `WireGuard now listens on port ${v.listenPort}`, (m) => ({ ...m, wireguard: { ...m.wireguard, enabled: v.enabled, listenPort: Number(v.listenPort) } })),
              )}
            >
              <SectionTitle right={<Switch label="Enabled" {...form.getInputProps('enabled', { type: 'checkbox' })} />}>Tunnel</SectionTitle>
              <Stack gap="md">
                <NumberInput label="Port" min={1} max={65535} {...form.getInputProps('listenPort')} />
                <Stack gap={2}>
                  <Text size="sm" fw={500}>Tunnel network</Text>
                  <Mono>{wg.address}</Mono>
                </Stack>
                <Stack gap={2}>
                  <Text size="sm" fw={500}>Public key</Text>
                  <Copyable value={wg.publicKey} />
                </Stack>
                <Alert variant="light" color="harbor" icon={<IconInfoCircle size={18} />} p="sm">
                  <Text size="xs">A firewall rule on WAN allowing UDP port {wg.listenPort} is required. It exists already.</Text>
                </Alert>
                <Group justify="flex-end">
                  <Button type="submit" disabled={!form.isDirty()}>Save</Button>
                </Group>
              </Stack>
            </form>
          </Card>
        </Grid.Col>
        <Grid.Col span={{ base: 12, lg: 8 }}>
          <Card padding={0}>
            <Group p="lg" pb="xs">
              <Text fw={600}>Devices</Text>
            </Group>
            <Table.ScrollContainer minWidth={640}>
              <Table highlightOnHover>
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>Device</Table.Th>
                    <Table.Th>VPN address</Table.Th>
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
                          <Text size="xs" c="dimmed" ml={16}>{s?.endpoint ?? 'Not connected yet'}</Text>
                        </Table.Td>
                        <Table.Td><Mono>{p.address}</Mono></Table.Td>
                        <Table.Td>
                          {s?.handshakeSecAgo != null ? (
                            online ? <Badge color="teal">Online</Badge> : <Text size="sm" c="dimmed">{formatAgo(s.handshakeSecAgo)}</Text>
                          ) : (
                            <Text size="sm" c="dimmed">Never</Text>
                          )}
                        </Table.Td>
                        <Table.Td ta="right">
                          <Text size="sm" className="num">{s ? `↓ ${formatBytes(s.tx)} · ↑ ${formatBytes(s.rx)}` : '—'}</Text>
                        </Table.Td>
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
