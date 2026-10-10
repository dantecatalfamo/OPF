// Firewall › Settings › Flow export: pflow(4) interfaces, each sending a
// record of every connection pf exports to a collector the admin runs.
// pf exports a connection when its state carries pflow, which
// state-defaults gives every rule here.
import { useEffect, useState } from 'react';
import { ActionIcon, Alert, Badge, Button, Card, Group, Menu, Modal, NumberInput, SegmentedControl, Select, Stack, Switch, Text, TextInput } from '@mantine/core';
import { useForm } from '@mantine/form';
import { IconAlertTriangle, IconDots, IconPencil, IconPlus, IconTrash } from '@tabler/icons-react';
import { newId, useStore } from '../model/store';
import type { FlowExport, Model } from '../model/types';
import { isIPv4, isIPv6 } from '../lib/ip';
import { useLive } from '../lib/live';
import { useRole } from '../lib/session';
import { Empty, SectionTitle } from '../components/ui';

// The usual ports: NetFlow's and IPFIX's (RFC 7011).
const defaultPort = { 5: 2055, 10: 4739 } as const;
const versionLabel = { 5: 'NetFlow v5', 10: 'IPFIX' } as const;

// The address and port as ifconfig's flowdst writes them.
export const collectorLabel = (e: Pick<FlowExport, 'collector' | 'port'>) => (e.collector.includes(':') ? `[${e.collector}]:${e.port}` : `${e.collector}:${e.port}`);

const nameRE = /^[A-Za-z0-9][A-Za-z0-9 _.-]{0,62}$/;

type Values = { name: string; collector: string; port: number | string; version: '5' | '10'; source: string };

function EditModal({ flow, onClose, onSave }: { flow: FlowExport | null; onClose: () => void; onSave: (v: Omit<FlowExport, 'id' | 'device' | 'enabled'>) => void }) {
  const { staged } = useStore();
  const form = useForm<Values>({
    initialValues: { name: '', collector: '', port: defaultPort[10], version: '10', source: '' },
    validate: {
      name: (v) => (nameRE.test(v.trim()) ? null : 'Use letters, digits, spaces, _ . and -'),
      collector: (v) => (!(isIPv4(v.trim()) || isIPv6(v.trim())) ? 'Enter an IP address like 192.168.1.5' : ['0.0.0.0', '::'].includes(v.trim()) ? 'Enter the collector’s own address' : null),
      port: (v) => (Number.isInteger(Number(v)) && Number(v) >= 1 && Number(v) <= 65535 ? null : '1 to 65535'),
    },
  });
  useEffect(() => {
    if (flow) form.setValues({ name: flow.name, collector: flow.collector, port: flow.port, version: String(flow.version) as Values['version'], source: flow.source ?? '' });
  }, [flow]); // form is stable
  const v = form.values;
  const v6 = v.collector.includes(':');
  const sources = staged.interfaces.filter((i) => i.enabled && i.ipv4.mode === 'static' && i.ipv4.address);
  // Changing the format moves the port along, unless it was chosen.
  const setVersion = (next: string) => {
    const was = Number(v.version) as 5 | 10;
    form.setFieldValue('version', next as Values['version']);
    if (Number(v.port) === defaultPort[was]) form.setFieldValue('port', defaultPort[Number(next) as 5 | 10]);
  };
  return (
    <Modal opened={!!flow} onClose={onClose} title={<Text fw={600}>{flow?.id ? `Edit ${flow.name}` : 'Add a collector'}</Text>}>
      <form onSubmit={form.onSubmit((v) => {
        onSave({ name: v.name.trim(), collector: v.collector.trim(), port: Number(v.port), version: Number(v.version) as 5 | 10, source: v.source && !v.collector.includes(':') ? v.source : undefined });
        onClose();
      })}>
        <Stack>
          <TextInput label="Name" placeholder="ntopng" data-autofocus {...form.getInputProps('name')} />
          <Group grow align="flex-start">
            <TextInput label="Collector’s address" placeholder="192.168.1.5" styles={{ input: { fontFamily: 'var(--mantine-font-family-monospace)' } }} {...form.getInputProps('collector')} />
            <NumberInput label="UDP port" min={1} max={65535} allowDecimal={false} hideControls {...form.getInputProps('port')} />
          </Group>
          <Stack gap={6}>
            <Text size="sm" fw={500}>Format</Text>
            <SegmentedControl size="xs" data={[{ value: '10', label: 'IPFIX' }, { value: '5', label: 'NetFlow v5' }]} value={v.version} onChange={setVersion} />
            <Text size="xs" c="dimmed">
              {v.version === '10' ? 'IPFIX records both IPv4 and IPv6 connections, and the addresses NAT translated them to.' : 'NetFlow v5 records only IPv4 connections. Use it for a collector that has nothing newer.'}
            </Text>
          </Stack>
          <Select
            label="Send from"
            description={v6 ? 'To an IPv6 collector, records are sent from the address the route to it picks.' : 'The collector sees records come from this address.'}
            inputWrapperOrder={['label', 'input', 'description', 'error']}
            disabled={v6}
            allowDeselect={false}
            data={[{ value: '', label: 'The address the route to the collector picks' }, ...sources.map((i) => ({ value: i.id, label: `${i.ipv4.address} (${i.name})` }))]}
            {...form.getInputProps('source')}
            value={v6 ? '' : v.source}
          />
          <Group justify="flex-end" mt="sm">
            <Button variant="default" onClick={onClose}>Cancel</Button>
            <Button type="submit">Save</Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}

// The lowest pflow device that isn't the model's or set up outside OPF.
function nextDevice(m: Model, applied: Model, live: string[]): string {
  const ours = new Set((applied.firewall.flowExports ?? []).map((e) => e.device));
  const taken = new Set([...(m.firewall.flowExports ?? []).map((e) => e.device), ...live.filter((n) => /^pflow\d+$/.test(n) && !ours.has(n))]);
  let n = 0;
  while (taken.has(`pflow${n}`)) n++;
  return `pflow${n}`;
}

export function FlowExportCard() {
  const { staged, applied, edit } = useStore();
  const { canEdit } = useRole();
  const { data: live } = useLive('interfaces');
  const [editing, setEditing] = useState<FlowExport | null>(null);
  const flows = staged.firewall.flowExports ?? [];
  const every = staged.firewall.options.stateDefaults?.includes('pflow') ?? false;

  const setFlows = (summary: string, fn: (all: FlowExport[]) => FlowExport[]) =>
    edit('firewall', summary, (m) => {
      const { flowExports, ...rest } = m.firewall;
      const next = fn(flowExports ?? []);
      return { ...m, firewall: next.length ? { ...rest, flowExports: next } : rest };
    });
  const setEvery = (on: boolean) =>
    edit('firewall', on ? 'Export every connection as a flow record' : 'Stopped exporting every connection as a flow record', (m) => {
      const rest = (m.firewall.options.stateDefaults ?? []).filter((d) => d !== 'pflow');
      const stateDefaults = on ? [...rest, 'pflow' as const] : rest;
      return { ...m, firewall: { ...m.firewall, options: { ...m.firewall.options, stateDefaults: stateDefaults.length ? stateDefaults : undefined } } };
    });
  const sourceLabel = (e: FlowExport) => {
    const i = staged.interfaces.find((x) => x.id === e.source);
    return i ? `from ${i.ipv4.address} (${i.name})` : null;
  };

  return (
    <Card id="flows">
      <SectionTitle right={canEdit && <Button size="xs" variant="light" leftSection={<IconPlus size={14} />} onClick={() => setEditing({ id: '', name: '', enabled: true, device: '', collector: '', port: defaultPort[10], version: 10 })}>Add collector</Button>}>
        Flow export
      </SectionTitle>
      <Stack gap="md">
        <Text size="sm" c="dimmed">
          The firewall can send a record of each connection to a collector you run, such as ntopng, nfdump or Elastiflow. A record says which addresses and ports talked, and how much each side sent. It’s sent once the connection ends. For TCP, that’s about a minute and a half after it closes.
        </Text>
        <Switch
          label="Export every connection"
          description="Every connection a rule lets through is recorded."
          checked={every}
          disabled={!canEdit}
          onChange={(e) => setEvery(e.currentTarget.checked)}
        />
        {flows.length > 0 && !every && (
          <Alert color="yellow" variant="light" p="sm" icon={<IconAlertTriangle size={16} />}>
            Unless a raw rule says pflow, nothing is sent. Turn on Export every connection to send them all.
          </Alert>
        )}
        {flows.length ? (
          <Stack gap="sm">
            {flows.map((e) => (
              <Group key={e.id} justify="space-between" align="flex-start" wrap="nowrap" gap="md">
                <Group align="flex-start" wrap="nowrap" gap="sm" style={{ minWidth: 0 }}>
                  <Switch mt={2} size="xs" checked={e.enabled} disabled={!canEdit} aria-label={e.enabled ? 'Turn off' : 'Turn on'}
                    onChange={() => setFlows(`${e.enabled ? 'Turned off' : 'Turned on'} flow export ${e.name}`, (all) => all.map((x) => (x.id === e.id ? { ...x, enabled: !x.enabled } : x)))} />
                  <Stack gap={2} style={{ minWidth: 0 }}>
                    <Group gap="xs">
                      <Text fw={500} size="sm">{e.name}</Text>
                      <Badge size="xs" variant="light">{versionLabel[e.version]}</Badge>
                    </Group>
                    <Text size="xs" c="dimmed">
                      To <Text span className="mono" size="xs">{collectorLabel(e)}</Text>{sourceLabel(e) ? ` ${sourceLabel(e)}` : ''}, through <Text span className="mono" size="xs">{e.device}</Text>
                    </Text>
                  </Stack>
                </Group>
                {canEdit && (
                  <Menu position="bottom-end">
                    <Menu.Target><ActionIcon variant="subtle" color="gray" aria-label="Actions"><IconDots size={16} /></ActionIcon></Menu.Target>
                    <Menu.Dropdown>
                      <Menu.Item leftSection={<IconPencil size={16} />} onClick={() => setEditing(e)}>Edit</Menu.Item>
                      <Menu.Item leftSection={<IconTrash size={16} />} color="red" onClick={() => setFlows(`Removed flow export ${e.name}`, (all) => all.filter((x) => x.id !== e.id))}>Remove</Menu.Item>
                    </Menu.Dropdown>
                  </Menu>
                )}
              </Group>
            ))}
          </Stack>
        ) : (
          <Empty>No collectors. Add one to start sending flow records.</Empty>
        )}
        <Text size="xs" c="dimmed">Records leave the firewall over UDP, unencrypted. Anyone on the way can read which devices talked to which. Send them only to a collector on a network you trust.</Text>
      </Stack>
      <EditModal
        flow={editing}
        onClose={() => setEditing(null)}
        onSave={(v) => {
          if (editing?.id) setFlows(`Edited flow export ${v.name}`, (all) => all.map((x) => (x.id === editing.id ? { ...x, ...v } : x)));
          else {
            const device = nextDevice(staged, applied, (live?.interfaces ?? []).map((s) => s.name));
            setFlows(`Added flow export ${v.name} on ${device}`, (all) => [...all, { ...v, id: newId('flow'), device, enabled: true }]);
          }
        }}
      />
    </Card>
  );
}
