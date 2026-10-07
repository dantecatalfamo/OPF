import { Link, useNavigate } from 'react-router';
import { Alert, Anchor, Badge, Button, Card, Group, Modal, NumberInput, SegmentedControl, Select, SimpleGrid, Stack, Text, TextInput } from '@mantine/core';
import { useEffect, useState } from 'react';
import { useDisclosure } from '@mantine/hooks';
import { useForm } from '@mantine/form';
import { IconAlertTriangle, IconPencil, IconPlus } from '@tabler/icons-react';
import { newId, useStore } from '../model/store';
import { defaultGateway, firstIPv4, ifaceState, mediaLabel, useLive } from '../lib/live';
import type { Iface } from '../model/types';
import type { InterfaceState, InterfacesResource } from '../lib/api';
import { formatBits } from '../lib/format';
import { isIPv4 } from '../lib/ip';
import { PageHeader, StatusDot, Mono } from '../components/ui';
import { TrafficSpark } from '../components/HistoryChart';
import { useHistory } from '../lib/history';

const roleLabel: Record<Iface['role'], string> = { wan: 'Internet', lan: 'Local network', opt: 'Extra network', vpn: 'VPN' };

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <Group justify="space-between" wrap="nowrap" gap="md">
      <Text size="sm" c="dimmed">
        {label}
      </Text>
      <Text size="sm" ta="right" component="div">
        {children}
      </Text>
    </Group>
  );
}

function AddVlan({ opened, onClose }: { opened: boolean; onClose: () => void }) {
  const { staged, edit } = useStore();
  const navigate = useNavigate();
  const { data: live } = useLive('interfaces');
  // OPF's own ports, and the firewall's other ports, which then only
  // carry VLANs (OPF brings them up for it).
  const physical = (dev: string) => !/^(vlan|svlan|aggr|trunk|carp|pppoe|tun|tap|gif|etherip|gre|egre|nvgre|eoip|vxlan|pflow|wg|bridge|veb|vport|tpmr|vether|lo|enc|pflog|pfsync)\d/.test(dev);
  const own = staged.interfaces.filter((i) => !i.vlan && i.role !== 'vpn' && physical(i.device));
  const bare = (live?.interfaces ?? []).filter((s) => settable(s) && physical(s.name) && !staged.interfaces.some((i) => i.device === s.name));
  const parents = [
    ...own.map((p) => ({ value: p.device, label: `${p.name} (${p.device})` })),
    ...bare.map((s) => ({ value: s.name, label: `${s.name}, only to carry VLANs` })),
  ];
  const form = useForm({
    initialValues: { name: '', parent: parents[0]?.value ?? '', tag: 30 as number | string, address: '', prefix: '24' },
    validate: {
      name: (v) => (v.trim() ? null : 'Give the network a name'),
      tag: (v) => {
        const n = Number(v);
        if (!Number.isInteger(n) || n < 1 || n > 4094) return 'VLAN IDs are 1 to 4094';
        return staged.interfaces.some((i) => i.vlan?.tag === n) ? 'That VLAN ID is already used' : null;
      },
      address: (v) => (isIPv4(v) ? null : 'Enter an IPv4 address like 192.168.30.1'),
    },
  });

  const submit = form.onSubmit((v) => {
    const id = newId('net');
    const iface: Iface = {
      id, name: v.name.trim(), device: `vlan${v.tag}`, role: 'opt', enabled: true,
      ipv4: { mode: 'static', address: v.address, prefix: Number(v.prefix) }, ipv6: 'none',
      vlan: { parent: v.parent, tag: Number(v.tag) },
    };
    edit('interfaces', `Added network “${iface.name}” (VLAN ${v.tag} on ${v.parent})`, (m) => ({
      ...m,
      interfaces: [...m.interfaces, iface],
    }));
    form.reset();
    onClose();
    navigate(`/interfaces/${id}`);
  });

  return (
    <Modal opened={opened} onClose={onClose} title={<Text fw={600}>Add a VLAN network</Text>} size="md">
      <form onSubmit={submit}>
        <Stack>
          <Text size="sm" c="dimmed">
            A VLAN is a separate network carried over an existing port, for example to keep guest or IoT devices apart.
            Your switch needs to tag this VLAN ID too. A port OPF doesn’t use yet can carry VLANs only: OPF brings it up for them.
          </Text>
          <TextInput label="Name" placeholder="Guests" data-autofocus {...form.getInputProps('name')} />
          <Group grow>
            <Select
              label="Carried on"
              data={parents}
              allowDeselect={false}
              {...form.getInputProps('parent')}
            />
            <NumberInput label="VLAN ID" min={1} max={4094} {...form.getInputProps('tag')} />
          </Group>
          <Group grow align="flex-start">
            <TextInput label="Firewall address" placeholder="192.168.30.1" {...form.getInputProps('address')} />
            <Select label="Size" data={['24', '25', '26', '27', '28', '16']} allowDeselect={false} {...form.getInputProps('prefix')} renderOption={({ option }) => `/${option.value}`} />
          </Group>
          <Group justify="flex-end" mt="sm">
            <Button variant="default" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit">Add network</Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}

// Interfaces the system has that aren't worth offering: loopback,
// IPsec's enc, pflog's and pfsync's.
const pseudo = /^(lo|enc|pflog|pfsync|pflow)\d+$/;

// A port OPF can set up: one with a hardware address that isn't a
// VLAN, tunnel, bridge or carp interface (those need their own forms).
const settable = (s: InterfaceState) => !!s.mac && !s.vlan && !s.wireguard && !s.carp && !/^(bridge|veb|tun|tap|gif|gre|carp|trunk|aggr|lo|enc|vport)\d/.test(s.name);

function SetUp({ port, onClose }: { port: InterfaceState | null; onClose: () => void }) {
  const { staged, edit } = useStore();
  const navigate = useNavigate();
  const current = port?.ipv4[0];
  const form = useForm({
    initialValues: { name: '', role: 'opt' as 'lan' | 'opt', mode: 'static' as 'static' | 'dhcp' | 'none', address: '', prefix: '24' },
    validate: {
      name: (v) => (v.trim() ? null : 'Give the network a name'),
      address: (v, vals) => (vals.mode !== 'static' || isIPv4(v) ? null : 'Enter an IPv4 address like 192.168.30.1'),
    },
  });
  useEffect(() => {
    if (!port) return;
    const [addr, prefix] = (current ?? '').split('/');
    form.setValues({ name: '', role: staged.interfaces.some((i) => i.role === 'lan') ? 'opt' : 'lan', mode: current ? 'static' : 'none', address: addr ?? '', prefix: prefix ?? '24' });
  }, [port]); // form is stable
  if (!port) return null;
  const submit = form.onSubmit((v) => {
    const id = newId('net');
    const iface: Iface = {
      id, name: v.name.trim(), device: port.name, role: v.role, enabled: true, ipv6: 'none',
      ipv4: v.mode === 'static' ? { mode: 'static', address: v.address, prefix: Number(v.prefix) } : { mode: v.mode },
    };
    edit('interfaces', `Set up ${port.name} as network “${iface.name}”`, (m) => ({ ...m, interfaces: [...m.interfaces, iface] }));
    onClose();
    navigate(`/interfaces/${id}`);
  });
  return (
    <Modal opened onClose={onClose} title={<Text fw={600}>Set up {port.name}</Text>} size="md">
      <form onSubmit={submit}>
        <Stack>
          <Text size="sm" c="dimmed">
            OPF will manage this port: its address, and firewall rules for its network (nothing gets in until you add some).
          </Text>
          {(port.ipv4.length > 0 || port.ipv6.some((a) => !a.startsWith('fe80'))) && (
            <Alert color="yellow" variant="light" p="sm" icon={<IconAlertTriangle size={16} />}>
              It has {[...port.ipv4, ...port.ipv6.filter((a) => !a.startsWith('fe80'))].join(', ')} now, set outside OPF, which replaces it with what you choose here. If a hostname.{port.name} file set it, applying says the file changed outside OPF and offers to replace it.
            </Alert>
          )}
          <TextInput label="Name" placeholder="Guests" data-autofocus {...form.getInputProps('name')} />
          <Select label="Role" data={[{ value: 'lan', label: 'Local network' }, { value: 'opt', label: 'Extra network' }]} allowDeselect={false} {...form.getInputProps('role')} />
          <SegmentedControl data={[{ value: 'static', label: 'Fixed address' }, { value: 'dhcp', label: 'From DHCP' }, { value: 'none', label: 'None' }]} {...form.getInputProps('mode')} />
          {form.values.mode === 'static' && (
            <Group grow align="flex-start">
              <TextInput label="Firewall address" placeholder="192.168.30.1" {...form.getInputProps('address')} />
              <Select label="Size" data={['24', '25', '26', '27', '28', '16']} allowDeselect={false} {...form.getInputProps('prefix')} renderOption={({ option }) => `/${option.value}`} />
            </Group>
          )}
          <Group justify="flex-end" mt="sm">
            <Button variant="default" onClick={onClose}>Cancel</Button>
            <Button type="submit">Set up</Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}

// The system's interfaces that OPF doesn't manage: a spare port, one
// set up by hand. Ports can be set up here; other kinds are listed. A
// port that only carries VLANs is OPF's (it brings it up for them), and
// its VLANs' cards say so.
function Unmanaged({ ifs }: { ifs?: InterfacesResource }) {
  const { staged } = useStore();
  const [port, setPort] = useState<InterfaceState | null>(null);
  const managed = new Set(staged.interfaces.flatMap((i) => (i.vlan && i.enabled ? [i.device, i.vlan.parent] : [i.device])));
  const others = (ifs?.interfaces ?? []).filter((s) => !managed.has(s.name) && !pseudo.test(s.name));
  if (!others.length) return null;
  return (
    <>
      <Text fw={600} mt="xl" mb={4}>Not set up by OPF</Text>
      <Text size="sm" c="dimmed" mb="md">Interfaces this machine has that OPF doesn’t manage: a spare port, or one configured by hand.</Text>
      <SimpleGrid cols={{ base: 1, md: 2 }} spacing="md">
        {others.map((s) => {
          const link = !s.up ? 'Down' : s.status === 'no carrier' ? 'No link' : 'Up';
          return (
            <Card key={s.name} padding="md">
              <Group justify="space-between" wrap="nowrap" align="flex-start">
                <Stack gap={4}>
                  <Group gap="sm">
                    <Text fw={600} className="mono">{s.name}</Text>
                    <StatusDot ok={link === 'Up'} label={link} />
                  </Group>
                  <Text size="xs" c="dimmed">
                    {[s.mac, s.vlan ? `VLAN ${s.vlan.id} on ${s.vlan.parent}` : mediaLabel(s), ...s.ipv4].filter(Boolean).join(' · ') || 'No address'}
                  </Text>
                </Stack>
                {settable(s) ? (
                  <Button size="xs" variant="light" leftSection={<IconPlus size={14} />} onClick={() => setPort(s)}>Set up</Button>
                ) : (
                  <Text size="xs" c="dimmed" ta="right">OPF doesn’t set up this kind yet</Text>
                )}
              </Group>
            </Card>
          );
        })}
      </SimpleGrid>
      <SetUp port={port} onClose={() => setPort(null)} />
    </>
  );
}

export function Interfaces() {
  const { staged } = useStore();
  const [opened, dlg] = useDisclosure();
  const { data: ifs } = useLive('interfaces');
  const { data: routes } = useLive('routes');
  // The last hour of every interface's traffic, in one request.
  const { data: history } = useHistory(staged.interfaces.flatMap((i) => [`if.${i.device}.rx`, `if.${i.device}.tx`]), 3600);

  return (
    <>
      <PageHeader
        title="Interfaces"
        description="The networks OPF connects. Each one gets its own firewall rules and, if you want, its own DHCP server."
        actions={
          <Button leftSection={<IconPlus size={16} />} onClick={dlg.open}>
            Add VLAN
          </Button>
        }
      />
      <SimpleGrid cols={{ base: 1, md: 2 }} spacing="md">
        {staged.interfaces.map((i) => {
          const s = ifaceState(ifs, i);
          const address =
            i.ipv4.mode === 'static' ? `${i.ipv4.address}/${i.ipv4.prefix}` : i.ipv4.mode === 'dhcp' ? s?.ipv4[0] ?? 'Waiting for DHCP' : 'None';
          const gateway = i.ipv4.mode === 'dhcp' && firstIPv4(s) ? defaultGateway(routes, i.device) : undefined;
          const link = !i.enabled ? 'Disabled' : !ifs ? '…' : !s ? 'Not on this system' : !s.up ? 'Down' : s.status === 'no carrier' ? 'No link' : 'Up';
          const errors = (s?.counters?.rxErrors ?? 0) + (s?.counters?.txErrors ?? 0);
          return (
            <Card key={i.id} style={{ display: 'flex', flexDirection: 'column', overflow: 'visible' }}>
              <Group justify="space-between" mb="md" wrap="nowrap">
                <Stack gap={2}>
                  <Group gap="sm">
                    <Text fw={600} size="lg">
                      {i.name}
                    </Text>
                    <Badge color={i.role === 'wan' ? 'amber' : 'harbor'}>{roleLabel[i.role]}</Badge>
                  </Group>
                  <StatusDot ok={link === 'Up'} label={link} />
                </Stack>
                <Button variant="default" size="xs" leftSection={<IconPencil size={14} />} component={Link} to={`/interfaces/${i.id}`}>
                  Edit
                </Button>
              </Group>
              <Stack gap={8}>
                <Field label="IPv4">
                  <Mono>{address}</Mono>
                  {i.ipv4.mode === 'dhcp' && (
                    <Text span size="xs" c="dimmed">
                      {' '}
                      (DHCP)
                    </Text>
                  )}
                </Field>
                {gateway && (
                  <Field label="Gateway">
                    <Mono>{gateway}</Mono>
                  </Field>
                )}
                <Field label="Port">
                  <Mono>{i.device}</Mono> ·{' '}
                  {i.wireguard ? (
                    // Its keys, port and devices are set on its WireGuard tab.
                    <Anchor component={Link} to={`/services/wireguard/${i.id}`} size="sm">WireGuard tunnel</Anchor>
                  ) : s?.vlan ? `VLAN ${s.vlan.id} on ${s.vlan.parent}` : i.vlan ? `VLAN ${i.vlan.tag} on ${i.vlan.parent}` : mediaLabel(s) ?? '—'}
                </Field>
                <Field label="Traffic">
                  <span className="num">
                    {s?.rxBps !== undefined && s.txBps !== undefined ? `↓ ${formatBits(s.rxBps)} · ↑ ${formatBits(s.txBps)}` : '—'}
                  </span>
                </Field>
                {errors > 0 && (
                  <Field label="Errors">
                    <Text span size="sm" c="yellow" className="num">{errors.toLocaleString()} since it came up</Text>
                  </Field>
                )}
              </Stack>
              {i.enabled && (
                <Card.Section mt="auto" pt="md" className="spark-bottom">
                  <Text size="xs" c="dimmed" px="lg" mb={2}>Last hour</Text>
                  <TrafficSpark data={history} dev={i.device} range={3600} />
                </Card.Section>
              )}
            </Card>
          );
        })}
      </SimpleGrid>
      <Unmanaged ifs={ifs} />
      <AddVlan opened={opened} onClose={dlg.close} />
    </>
  );
}
