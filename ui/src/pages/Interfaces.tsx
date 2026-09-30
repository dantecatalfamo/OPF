import { Link, useNavigate } from 'react-router';
import { Anchor, Badge, Button, Card, Group, Modal, NumberInput, Select, SimpleGrid, Stack, Text, TextInput } from '@mantine/core';
import { useDisclosure } from '@mantine/hooks';
import { useForm } from '@mantine/form';
import { IconPencil, IconPlus } from '@tabler/icons-react';
import { newId, useStore } from '../model/store';
import { defaultGateway, firstIPv4, ifaceState, mediaLabel, useLive } from '../lib/live';
import type { Iface } from '../model/types';
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
  const parents = staged.interfaces.filter((i) => !i.vlan && i.role !== 'vpn' && i.role !== 'wan');
  const form = useForm({
    initialValues: { name: '', parent: parents[0]?.device ?? '', tag: 30 as number | string, address: '', prefix: '24' },
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
            Your switch needs to tag this VLAN ID too.
          </Text>
          <TextInput label="Name" placeholder="Guests" data-autofocus {...form.getInputProps('name')} />
          <Group grow>
            <Select
              label="Carried on"
              data={parents.map((p) => ({ value: p.device, label: `${p.name} (${p.device})` }))}
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
                  ) : s?.vlan ? `VLAN ${s.vlan.id} on ${s.vlan.parent}` : mediaLabel(s) ?? '—'}
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
      <AddVlan opened={opened} onClose={dlg.close} />
    </>
  );
}
