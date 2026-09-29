import { useEffect, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router';
import {
  ActionIcon, Alert, Anchor, Autocomplete, Badge, Button, Card, Code, Drawer, Group, Menu, SegmentedControl, Select, SimpleGrid, Stack, Switch, Table, Tabs, Text, TextInput, Tooltip,
} from '@mantine/core';
import { useForm } from '@mantine/form';
import { IconArrowRight, IconDots, IconInfoCircle, IconLock, IconPencil, IconPlus, IconTrash } from '@tabler/icons-react';
import { newId, useStore } from '../model/store';
import type { NatRule, PortForward } from '../model/types';
import { automaticNat, forwardText, natText, pfComment } from '../model/generate';
import { endpointLabel, ifaceName } from '../lib/labels';
import { isCIDR, isIPv4, isPortSpec } from '../lib/ip';
import { EndpointField, validateEndpoint } from '../components/EndpointField';
import { Empty, Mono, PageHeader } from '../components/ui';

type ForwardValues = Omit<PortForward, 'id'>;
const blankForward: ForwardValues = {
  enabled: true, iface: 'wan', protocol: 'tcp', source: { type: 'any' }, externalPort: '', target: '', targetPort: '', reflection: true, log: false, description: '',
};

function ForwardDrawer({ opened, onClose, forward, onSave }: { opened: boolean; onClose: () => void; forward: PortForward | null; onSave: (v: ForwardValues) => void }) {
  const { staged } = useStore();
  const form = useForm<ForwardValues>({
    initialValues: blankForward,
    validate: {
      externalPort: (v) => (isPortSpec(v) ? null : 'Use a port like 443 or a range like 8000:8080'),
      target: (v) => (isIPv4(v) ? null : 'Enter the device’s address, like 192.168.1.20'),
      targetPort: (v) => (!v || isPortSpec(v) ? null : 'Use a port like 443'),
      description: (v) => (v.trim() ? null : 'Describe what this is for'),
      source: (v) => validateEndpoint(v, isIPv4, isCIDR),
    },
  });
  useEffect(() => {
    if (opened) form.setValues(forward ? { ...forward } : blankForward);
  }, [opened, forward]); // form is stable

  const reservations = staged.dhcp.flatMap((d) => d.reservations).map((r) => ({ value: r.ip, label: `${r.hostname} · ${r.ip}` }));
  const v = form.values;
  // With the forward's own id, so the preview shows its real label; a
  // new one has none until it's saved.
  const preview = [pfComment(v.description), ...forwardText({ ...v, id: forward?.id ?? '', targetPort: v.targetPort || v.externalPort }, staged)].filter(Boolean).join('\n');

  return (
    <Drawer opened={opened} onClose={onClose} size="xl" title={<Text fw={600} size="lg">{forward ? 'Edit port forward' : 'Add port forward'}</Text>}>
      <form
        onSubmit={form.onSubmit((vals) => {
          onSave({ ...vals, targetPort: vals.targetPort || vals.externalPort, description: vals.description.trim() });
          onClose();
        })}
      >
        <Stack gap="lg">
          <Text size="sm" c="dimmed">
            Connections arriving on a public port are redirected (rdr-to) to a device inside. The pass rule that lets them in is part of the forward.
          </Text>
          <SimpleGrid cols={{ base: 1, sm: 2 }}>
            <Select label="Arriving on" data={staged.interfaces.filter((i) => i.role === 'wan').map((i) => ({ value: i.id, label: i.name }))} allowDeselect={false} {...form.getInputProps('iface')} />
            <Select label="Protocol" data={[{ value: 'tcp', label: 'TCP' }, { value: 'udp', label: 'UDP' }, { value: 'tcp/udp', label: 'TCP and UDP' }]} allowDeselect={false} {...form.getInputProps('protocol')} />
          </SimpleGrid>
          <EndpointField label="Allowed from" value={v.source} onChange={(e) => form.setFieldValue('source', e)} model={staged} error={form.errors.source} />
          <SimpleGrid cols={{ base: 1, sm: 3 }}>
            <TextInput label="Public port" placeholder="443" {...form.getInputProps('externalPort')} />
            <Autocomplete
              label="Send to device"
              placeholder="192.168.1.20"
              data={reservations.map((r) => r.value)}
              renderOption={({ option }) => <Text size="sm">{reservations.find((r) => r.value === option.value)?.label}</Text>}
              {...form.getInputProps('target')}
            />
            <TextInput label="Device port" placeholder="Same" {...form.getInputProps('targetPort')} />
          </SimpleGrid>
          <TextInput label="Description" placeholder="Security camera recorder" {...form.getInputProps('description')} />
          <Stack gap="sm">
            <Switch
              label="Also works from inside the network"
              description="Devices on your networks can use the public address too (NAT reflection)."
              {...form.getInputProps('reflection', { type: 'checkbox' })}
            />
            <Switch label="Log connections" {...form.getInputProps('log', { type: 'checkbox' })} />
            <Switch label="Enabled" {...form.getInputProps('enabled', { type: 'checkbox' })} />
          </Stack>
          <Code block style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word', fontSize: 12 }}>{preview}</Code>
          <Group justify="flex-end">
            <Button variant="default" onClick={onClose}>Cancel</Button>
            <Button type="submit">{forward ? 'Save' : 'Add port forward'}</Button>
          </Group>
        </Stack>
      </form>
    </Drawer>
  );
}

function Forwards() {
  const { staged, edit } = useStore();
  const [drawer, setDrawer] = useState<{ open: boolean; forward: PortForward | null }>({ open: false, forward: null });
  const forwards = staged.firewall.forwards;
  const set = (summary: string, fn: (f: PortForward[]) => PortForward[]) => edit('firewall', summary, (m) => ({ ...m, firewall: { ...m.firewall, forwards: fn(m.firewall.forwards) } }));

  return (
    <>
      <Group justify="space-between" mb="md">
        <Text size="sm" c="dimmed">Make a device on your network reachable from the internet.</Text>
        <Button leftSection={<IconPlus size={16} />} onClick={() => setDrawer({ open: true, forward: null })}>Add port forward</Button>
      </Group>
      <Card padding={0}>
        <Table.ScrollContainer minWidth={760}>
          <Table highlightOnHover>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>On</Table.Th>
                <Table.Th>Description</Table.Th>
                <Table.Th>Allowed from</Table.Th>
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
                    <Group gap={6}>
                      <Text size="xs" c="dimmed">{f.protocol.toUpperCase()} on {ifaceName(staged, f.iface)}</Text>
                      {f.reflection && <Badge size="xs" color="gray">reflection</Badge>}
                      {f.log && <Badge size="xs" color="gray">logged</Badge>}
                    </Group>
                  </Table.Td>
                  <Table.Td><Text size="sm">{endpointLabel(f.source, staged)}</Text></Table.Td>
                  <Table.Td><Mono>{f.externalPort}</Mono></Table.Td>
                  <Table.Td w={30}><IconArrowRight size={16} color="var(--mantine-color-dimmed)" /></Table.Td>
                  <Table.Td><Mono>{f.target}:{f.targetPort}</Mono></Table.Td>
                  <Table.Td w={44}>
                    <Menu position="bottom-end">
                      <Menu.Target><ActionIcon variant="subtle" color="gray" aria-label="Actions"><IconDots size={16} /></ActionIcon></Menu.Target>
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

type NatValues = Omit<NatRule, 'id'> & { translationAddress: string };

function NatDrawer({ opened, onClose, rule, onSave }: { opened: boolean; onClose: () => void; rule: NatRule | null; onSave: (r: Omit<NatRule, 'id'>) => void }) {
  const { staged } = useStore();
  const wan = staged.interfaces.find((i) => i.role === 'wan')?.id ?? staged.interfaces[0].id;
  const blank: NatValues = { enabled: true, iface: wan, source: { type: 'any' }, destination: { type: 'any' }, translation: { type: 'ifaddr' }, translationAddress: '', staticPort: false, description: '' };
  const form = useForm<NatValues>({
    initialValues: blank,
    validate: {
      description: (v) => (v.trim() ? null : 'Describe what this is for'),
      translationAddress: (v, vals) => (vals.translation.type !== 'address' || isIPv4(v) || isCIDR(v) ? null : 'Enter an address or a range in CIDR form'),
      source: (v) => validateEndpoint(v, isIPv4, isCIDR),
      destination: (v) => validateEndpoint(v, isIPv4, isCIDR),
    },
  });
  useEffect(() => {
    if (!opened) return;
    form.setValues(rule ? { ...rule, translationAddress: rule.translation.type === 'address' ? rule.translation.value : '' } : blank);
  }, [opened, rule]); // form is stable

  const v = form.values;
  const toRule = (x: NatValues): Omit<NatRule, 'id'> => {
    const { translationAddress, ...rest } = x;
    const translation = x.translation.type === 'address' ? { type: 'address' as const, value: translationAddress } : x.translation;
    return { ...rest, translation, pool: translation.type === 'address' && translationAddress.includes('/') ? x.pool ?? 'round-robin' : undefined };
  };
  const preview = [pfComment(v.description), natText({ ...toRule(v), id: rule?.id ?? '' }, staged)].filter(Boolean).join('\n');

  return (
    <Drawer opened={opened} onClose={onClose} size="xl" title={<Text fw={600} size="lg">{rule ? 'Edit outbound NAT rule' : 'Add outbound NAT rule'}</Text>}>
      <form onSubmit={form.onSubmit((x) => { onSave({ ...toRule(x), description: x.description.trim() }); onClose(); })}>
        <Stack gap="lg">
          <Select label="Leaving through" data={staged.interfaces.map((i) => ({ value: i.id, label: i.name }))} allowDeselect={false} {...form.getInputProps('iface')} />
          <SimpleGrid cols={{ base: 1, sm: 2 }}>
            <EndpointField label="From" value={v.source} onChange={(e) => form.setFieldValue('source', e)} model={staged} error={form.errors.source} />
            <EndpointField label="To" value={v.destination} onChange={(e) => form.setFieldValue('destination', e)} model={staged} error={form.errors.destination} />
          </SimpleGrid>
          <Stack gap={6}>
            <Text size="sm" fw={500}>Translate the source address to</Text>
            <SegmentedControl
              data={[{ value: 'ifaddr', label: 'Interface address' }, { value: 'address', label: 'Other address' }, { value: 'none', label: 'Don’t translate' }]}
              value={v.translation.type}
              onChange={(t) => form.setFieldValue('translation', t === 'address' ? { type: 'address', value: '' } : { type: t as 'ifaddr' | 'none' })}
            />
          </Stack>
          {v.translation.type === 'address' && (
            <SimpleGrid cols={{ base: 1, sm: 2 }}>
              <TextInput label="Address or pool" placeholder="203.0.113.25 or 203.0.113.24/29" styles={{ input: { fontFamily: 'var(--mantine-font-family-monospace)' } }} {...form.getInputProps('translationAddress')} />
              <Select
                label="Choose from the pool by"
                data={[{ value: 'round-robin', label: 'Round robin' }, { value: 'source-hash', label: 'Source hash (sticky)' }, { value: 'random', label: 'Random' }]}
                disabled={!form.values.translationAddress.includes('/')}
                value={v.pool ?? 'round-robin'}
                onChange={(p) => form.setFieldValue('pool', (p ?? 'round-robin') as NatRule['pool'])}
              />
            </SimpleGrid>
          )}
          {v.translation.type !== 'none' && (
            <Switch label="Keep source ports (static-port)" description="Some protocols, like SIP and certain games, break when ports are rewritten." {...form.getInputProps('staticPort', { type: 'checkbox' })} />
          )}
          <TextInput label="Description" {...form.getInputProps('description')} />
          <Switch label="Enabled" {...form.getInputProps('enabled', { type: 'checkbox' })} />
          <Code block style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word', fontSize: 12 }}>{preview}</Code>
          <Group justify="flex-end">
            <Button variant="default" onClick={onClose}>Cancel</Button>
            <Button type="submit">{rule ? 'Save' : 'Add rule'}</Button>
          </Group>
        </Stack>
      </form>
    </Drawer>
  );
}

function translationLabel(n: NatRule, iface: string) {
  if (n.translation.type === 'none') return 'Not translated';
  const t = n.translation.type === 'ifaddr' ? `${iface} address` : n.translation.value;
  return `${t}${n.pool ? ` (${n.pool})` : ''}${n.staticPort ? ', same ports' : ''}`;
}

function Outbound() {
  const { staged, edit } = useStore();
  const nat = staged.firewall.outboundNat;
  const auto = automaticNat(staged);
  const [drawer, setDrawer] = useState<{ open: boolean; rule: NatRule | null }>({ open: false, rule: null });
  const set = (summary: string, fn: (n: typeof nat) => typeof nat) => edit('firewall', summary, (m) => ({ ...m, firewall: { ...m.firewall, outboundNat: fn(m.firewall.outboundNat) } }));
  const modeLabel = { auto: 'Automatic', hybrid: 'Automatic plus manual rules', manual: 'Manual only' };
  const vpnCovered = nat.mode !== 'manual' || nat.rules.some((r) => r.enabled && r.source.type === 'iface' && r.source.part === 'network' && r.source.iface === 'wg');

  return (
    <Stack gap="md">
      <Card>
        <Stack gap="sm">
          <Text fw={600}>How outgoing traffic is translated</Text>
          <SegmentedControl
            data={Object.entries(modeLabel).map(([value, label]) => ({ value, label }))}
            value={nat.mode}
            onChange={(mode) => set(`Outbound NAT mode: ${modeLabel[mode as keyof typeof modeLabel]}`, (n) => ({ ...n, mode: mode as typeof nat.mode }))}
          />
          <Text size="sm" c="dimmed">
            {nat.mode === 'auto' && 'Every internal network is translated to the WAN address when it goes to the internet. Right for almost everyone.'}
            {nat.mode === 'hybrid' && 'The automatic rules still apply, and your manual rules below take priority over them.'}
            {nat.mode === 'manual' && 'Only your rules below apply. Networks without a rule can’t reach the internet.'}
          </Text>
          {!vpnCovered && (
            <Alert color="yellow" variant="light" icon={<IconInfoCircle size={18} />} p="sm">
              No rule translates the WireGuard network, so VPN devices sending all traffic through the office can’t reach the internet.
            </Alert>
          )}
        </Stack>
      </Card>

      <Card padding={0}>
        <Group justify="space-between" p="lg" pb="xs">
          <Text fw={600}>Rules</Text>
          <Button size="xs" variant="light" leftSection={<IconPlus size={14} />} disabled={nat.mode === 'auto'} onClick={() => setDrawer({ open: true, rule: null })}>Add rule</Button>
        </Group>
        <Table.ScrollContainer minWidth={760}>
          <Table highlightOnHover>
            <Table.Thead>
              <Table.Tr>
                <Table.Th />
                <Table.Th>Description</Table.Th>
                <Table.Th>Leaving</Table.Th>
                <Table.Th>From</Table.Th>
                <Table.Th>To</Table.Th>
                <Table.Th>Translated to</Table.Th>
                <Table.Th />
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {nat.mode !== 'auto' &&
                nat.rules.map((n) => (
                  <Table.Tr key={n.id} style={{ opacity: n.enabled ? 1 : 0.6 }}>
                    <Table.Td w={56}><Switch size="xs" checked={n.enabled} onChange={() => set(`${n.enabled ? 'Disabled' : 'Enabled'} NAT rule “${n.description}”`, (x) => ({ ...x, rules: x.rules.map((r) => (r.id === n.id ? { ...r, enabled: !r.enabled } : r)) }))} aria-label="Enabled" /></Table.Td>
                    <Table.Td><Text size="sm" fw={500}>{n.description}</Text></Table.Td>
                    <Table.Td><Text size="sm">{ifaceName(staged, n.iface)}</Text></Table.Td>
                    <Table.Td><Text size="sm">{endpointLabel(n.source, staged)}</Text></Table.Td>
                    <Table.Td><Text size="sm">{endpointLabel(n.destination, staged)}</Text></Table.Td>
                    <Table.Td><Text size="sm">{translationLabel(n, ifaceName(staged, n.iface))}</Text></Table.Td>
                    <Table.Td w={44}>
                      <Menu position="bottom-end">
                        <Menu.Target><ActionIcon variant="subtle" color="gray" aria-label="Actions"><IconDots size={16} /></ActionIcon></Menu.Target>
                        <Menu.Dropdown>
                          <Menu.Item leftSection={<IconPencil size={16} />} onClick={() => setDrawer({ open: true, rule: n })}>Edit</Menu.Item>
                          <Menu.Item leftSection={<IconTrash size={16} />} color="red" onClick={() => set(`Deleted NAT rule “${n.description}”`, (x) => ({ ...x, rules: x.rules.filter((r) => r.id !== n.id) }))}>Delete</Menu.Item>
                        </Menu.Dropdown>
                      </Menu>
                    </Table.Td>
                  </Table.Tr>
                ))}
              {nat.mode !== 'manual' &&
                auto.map((n) => (
                  <Table.Tr key={n.id} style={{ background: 'var(--opf-bg)' }}>
                    <Table.Td><Tooltip label="Automatic. Follows your interfaces."><IconLock size={16} color="var(--mantine-color-dimmed)" style={{ marginLeft: 6 }} /></Tooltip></Table.Td>
                    <Table.Td><Text size="sm" c="dimmed">{n.description}</Text></Table.Td>
                    <Table.Td><Text size="sm" c="dimmed">{ifaceName(staged, n.iface)}</Text></Table.Td>
                    <Table.Td><Text size="sm" c="dimmed">{endpointLabel(n.source, staged)}</Text></Table.Td>
                    <Table.Td><Text size="sm" c="dimmed">Any</Text></Table.Td>
                    <Table.Td><Text size="sm" c="dimmed">{translationLabel(n, ifaceName(staged, n.iface))}</Text></Table.Td>
                    <Table.Td />
                  </Table.Tr>
                ))}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      </Card>
      <Text size="xs" c="dimmed">
        Manual rules take priority over automatic ones; exceptions that don’t translate are checked first. <Anchor component={Link} to="/firewall/ruleset" size="xs">See the generated rules</Anchor>
      </Text>
      <NatDrawer
        opened={drawer.open}
        onClose={() => setDrawer((d) => ({ ...d, open: false }))}
        rule={drawer.rule}
        onSave={(r) =>
          drawer.rule
            ? set(`Edited NAT rule “${r.description}”`, (x) => ({ ...x, rules: x.rules.map((y) => (y.id === drawer.rule!.id ? { ...r, id: y.id } : y)) }))
            : set(`Added NAT rule “${r.description}”`, (x) => ({ ...x, rules: [...x.rules, { ...r, id: newId('n') }] }))
        }
      />
    </Stack>
  );
}

export function Nat() {
  const { tab } = useParams();
  const navigate = useNavigate();
  const current = tab === 'outbound' ? 'outbound' : 'forwards';
  return (
    <>
      <PageHeader title="NAT" description="Address translation: letting the internet reach devices inside (port forwarding), and how inside devices appear when they go out." />
      <Tabs value={current} onChange={(v) => navigate(v === 'outbound' ? '/firewall/nat/outbound' : '/firewall/nat')} mb="md">
        <Tabs.List>
          <Tabs.Tab value="forwards">Port forwarding</Tabs.Tab>
          <Tabs.Tab value="outbound">Outbound</Tabs.Tab>
        </Tabs.List>
      </Tabs>
      {current === 'forwards' ? <Forwards /> : <Outbound />}
    </>
  );
}
