import { useEffect, useState } from 'react';
import { ActionIcon, Autocomplete, Button, Card, Drawer, Group, Menu, Select, Stack, Switch, Table, Text, TextInput } from '@mantine/core';
import { useForm } from '@mantine/form';
import { IconArrowRight, IconDots, IconPencil, IconPlus, IconTrash } from '@tabler/icons-react';
import { newId, useStore } from '../model/store';
import type { PortForward } from '../model/types';
import { ifaceName } from '../lib/labels';
import { isIPv4, isPortSpec } from '../lib/ip';
import { Empty, Mono, PageHeader } from '../components/ui';

type Values = Omit<PortForward, 'id'>;

const blank: Values = { enabled: true, iface: 'wan', protocol: 'tcp', externalPort: '', target: '', targetPort: '', description: '' };

function ForwardDrawer({ opened, onClose, forward, onSave }: {
  opened: boolean; onClose: () => void; forward: PortForward | null; onSave: (v: Values) => void;
}) {
  const { staged } = useStore();
  const form = useForm<Values>({
    initialValues: blank,
    validate: {
      externalPort: (v) => (isPortSpec(v) ? null : 'Use a port like 443'),
      target: (v) => (isIPv4(v) ? null : 'Enter the device’s address, like 192.168.1.20'),
      targetPort: (v) => (!v || isPortSpec(v) ? null : 'Use a port like 443'),
      description: (v) => (v.trim() ? null : 'Describe what this is for'),
    },
  });
  useEffect(() => {
    if (opened) form.setValues(forward ? { ...forward } : blank);
  }, [opened, forward]); // form is stable

  const reservations = staged.dhcp.flatMap((d) => d.reservations).map((r) => ({ value: r.ip, label: `${r.hostname} · ${r.ip}` }));

  return (
    <Drawer opened={opened} onClose={onClose} title={<Text fw={600} size="lg">{forward ? 'Edit port forward' : 'Add port forward'}</Text>}>
      <form
        onSubmit={form.onSubmit((v) => {
          onSave({ ...v, targetPort: v.targetPort || v.externalPort, description: v.description.trim() });
          onClose();
        })}
      >
        <Stack gap="lg">
          <Text size="sm" c="dimmed">
            Send connections that arrive from the internet on a port to a device inside your network. A firewall rule
            allowing them is added for you.
          </Text>
          <Group grow align="flex-start">
            <Select
              label="Arriving on"
              data={staged.interfaces.filter((i) => i.role === 'wan').map((i) => ({ value: i.id, label: i.name }))}
              allowDeselect={false}
              {...form.getInputProps('iface')}
            />
            <Select
              label="Protocol"
              data={[{ value: 'tcp', label: 'TCP' }, { value: 'udp', label: 'UDP' }, { value: 'tcp/udp', label: 'TCP and UDP' }]}
              allowDeselect={false}
              {...form.getInputProps('protocol')}
            />
          </Group>
          <TextInput label="Public port" placeholder="443" {...form.getInputProps('externalPort')} />
          <Group grow align="flex-start">
            <Autocomplete
              label="Send to device"
              placeholder="192.168.1.20"
              data={reservations.map((r) => r.value)}
              renderOption={({ option }) => <Text size="sm">{reservations.find((r) => r.value === option.value)?.label}</Text>}
              {...form.getInputProps('target')}
            />
            <TextInput label="Device port" placeholder="Same as public port" {...form.getInputProps('targetPort')} />
          </Group>
          <TextInput label="Description" placeholder="Security camera recorder" {...form.getInputProps('description')} />
          <Switch label="Enabled" {...form.getInputProps('enabled', { type: 'checkbox' })} />
          <Group justify="flex-end">
            <Button variant="default" onClick={onClose}>Cancel</Button>
            <Button type="submit">{forward ? 'Save' : 'Add port forward'}</Button>
          </Group>
        </Stack>
      </form>
    </Drawer>
  );
}

export function PortForwards() {
  const { staged, edit } = useStore();
  const [drawer, setDrawer] = useState<{ open: boolean; forward: PortForward | null }>({ open: false, forward: null });
  const forwards = staged.firewall.forwards;
  const set = (summary: string, fn: (f: PortForward[]) => PortForward[]) =>
    edit('firewall', summary, (m) => ({ ...m, firewall: { ...m.firewall, forwards: fn(m.firewall.forwards) } }));

  return (
    <>
      <PageHeader
        title="Port forwarding"
        description="Make a device on your network reachable from the internet, like a web server or camera recorder."
        actions={<Button leftSection={<IconPlus size={16} />} onClick={() => setDrawer({ open: true, forward: null })}>Add port forward</Button>}
      />
      <Card padding={0}>
        <Table.ScrollContainer minWidth={720}>
          <Table highlightOnHover>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>On</Table.Th>
                <Table.Th>Description</Table.Th>
                <Table.Th>Public port</Table.Th>
                <Table.Th />
                <Table.Th>Device</Table.Th>
                <Table.Th />
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {forwards.map((f) => (
                <Table.Tr key={f.id} style={{ opacity: f.enabled ? 1 : 0.6 }}>
                  <Table.Td w={56}>
                    <Switch size="xs" checked={f.enabled} onChange={() => set(`${f.enabled ? 'Disabled' : 'Enabled'} port forward “${f.description}”`, (all) => all.map((x) => (x.id === f.id ? { ...x, enabled: !x.enabled } : x)))} aria-label="Enabled" />
                  </Table.Td>
                  <Table.Td>
                    <Text size="sm" fw={500}>{f.description}</Text>
                    <Text size="xs" c="dimmed">{f.protocol.toUpperCase()} on {ifaceName(staged, f.iface)}</Text>
                  </Table.Td>
                  <Table.Td><Mono>{f.externalPort}</Mono></Table.Td>
                  <Table.Td w={30}><IconArrowRight size={16} color="var(--mantine-color-dimmed)" /></Table.Td>
                  <Table.Td><Mono>{f.target}:{f.targetPort}</Mono></Table.Td>
                  <Table.Td w={44}>
                    <Menu position="bottom-end">
                      <Menu.Target>
                        <ActionIcon variant="subtle" color="gray" aria-label="Actions"><IconDots size={16} /></ActionIcon>
                      </Menu.Target>
                      <Menu.Dropdown>
                        <Menu.Item leftSection={<IconPencil size={16} />} onClick={() => setDrawer({ open: true, forward: f })}>Edit</Menu.Item>
                        <Menu.Item leftSection={<IconTrash size={16} />} color="red" onClick={() => set(`Deleted port forward “${f.description}”`, (all) => all.filter((x) => x.id !== f.id))}>Delete</Menu.Item>
                      </Menu.Dropdown>
                    </Menu>
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
        {forwards.length === 0 && <Empty>Nothing is reachable from the internet.</Empty>}
      </Card>
      <ForwardDrawer
        opened={drawer.open}
        onClose={() => setDrawer((d) => ({ ...d, open: false }))}
        forward={drawer.forward}
        onSave={(v) =>
          drawer.forward
            ? set(`Edited port forward “${v.description}”`, (all) => all.map((x) => (x.id === drawer.forward!.id ? { ...v, id: x.id } : x)))
            : set(`Forwarded port ${v.externalPort} to ${v.target}:${v.targetPort} (“${v.description}”)`, (all) => [...all, { ...v, id: newId('f') }])
        }
      />
    </>
  );
}
