import { useEffect } from 'react';
import { Autocomplete, Button, Drawer, Group, SegmentedControl, Select, Stack, Switch, Text, TextInput } from '@mantine/core';
import { useForm } from '@mantine/form';
import type { Endpoint, Model, Protocol, Rule, RuleAction } from '../model/types';
import { isCIDR, isIPv4, isPortSpec } from '../lib/ip';
import { commonPorts, ifaceName } from '../lib/labels';

type EndpointKind = 'any' | 'self' | `net:${string}` | 'host' | 'network' | `alias:${string}`;

interface Values {
  iface: string;
  enabled: boolean;
  action: RuleAction;
  protocol: Protocol;
  srcKind: EndpointKind;
  srcValue: string;
  dstKind: EndpointKind;
  dstValue: string;
  port: string;
  log: boolean;
  description: string;
}

function kindOf(e: Endpoint): { kind: EndpointKind; value: string } {
  switch (e.type) {
    case 'net':
      return { kind: `net:${e.iface}`, value: '' };
    case 'alias':
      return { kind: `alias:${e.alias}`, value: '' };
    case 'host':
    case 'network':
      return { kind: e.type, value: e.value };
    default:
      return { kind: e.type, value: '' };
  }
}

function endpointOf(kind: EndpointKind, value: string): Endpoint {
  if (kind.startsWith('net:')) return { type: 'net', iface: kind.slice(4) };
  if (kind.startsWith('alias:')) return { type: 'alias', alias: kind.slice(6) };
  if (kind === 'host' || kind === 'network') return { type: kind, value: value.trim() };
  return { type: kind as 'any' | 'self' };
}

function endpointOptions(m: Model) {
  return [
    { group: 'General', items: [{ value: 'any', label: 'Any' }, { value: 'self', label: 'This firewall' }] },
    {
      group: 'Networks',
      items: m.interfaces.filter((i) => i.role !== 'wan').map((i) => ({ value: `net:${i.id}`, label: `${i.name} network` })),
    },
    {
      group: 'Aliases',
      items: m.firewall.aliases.filter((a) => a.type !== 'ports').map((a) => ({ value: `alias:${a.name}`, label: a.name })),
    },
    { group: 'Custom', items: [{ value: 'host', label: 'Single address…' }, { value: 'network', label: 'Network range…' }] },
  ].filter((g) => g.items.length);
}

const portless = (p: Protocol) => p === 'any' || p === 'icmp';

const monoInput = { input: { fontFamily: 'var(--mantine-font-family-monospace)' } };

export function RuleDrawer({
  opened, onClose, model, rule, iface, onSave,
}: {
  opened: boolean;
  onClose: () => void;
  model: Model;
  rule: Rule | null; // null: new rule
  iface: string;
  onSave: (r: Omit<Rule, 'id'>) => void;
}) {
  const form = useForm<Values>({
    initialValues: blank(iface),
    validate: {
      srcValue: (v, vals) => validateCustom(vals.srcKind, v),
      dstValue: (v, vals) => validateCustom(vals.dstKind, v),
      port: (v, vals) => (portless(vals.protocol) || !v || v.startsWith('alias:') || isPortSpec(v) ? null : 'Use a port like 443 or a range like 8000-8080'),
      description: (v) => (v.trim() ? null : 'Describe what this rule is for'),
    },
  });

  useEffect(() => {
    if (!opened) return;
    if (!rule) {
      form.setValues(blank(iface));
      return;
    }
    const s = kindOf(rule.source);
    const d = kindOf(rule.destination);
    form.setValues({
      iface: rule.iface, enabled: rule.enabled, action: rule.action, protocol: rule.protocol,
      srcKind: s.kind, srcValue: s.value, dstKind: d.kind, dstValue: d.value,
      port: rule.port ?? '', log: rule.log, description: rule.description,
    });
    form.resetDirty();
  }, [opened, rule, iface]); // form is stable

  const options = endpointOptions(model);
  const portAliases = model.firewall.aliases.filter((a) => a.type === 'ports').map((a) => ({ value: `alias:${a.name}`, label: `${a.name} (${a.entries.join(', ')})` }));
  const portOptionLabel = (v: string) => [...commonPorts, ...portAliases].find((p) => p.value === v)?.label ?? v;

  const submit = form.onSubmit((v) => {
    onSave({
      iface: v.iface,
      enabled: v.enabled,
      action: v.action,
      protocol: v.protocol,
      source: endpointOf(v.srcKind, v.srcValue),
      destination: endpointOf(v.dstKind, v.dstValue),
      port: portless(v.protocol) || !v.port ? undefined : v.port.trim(),
      log: v.log,
      description: v.description.trim(),
    });
    onClose();
  });

  return (
    <Drawer opened={opened} onClose={onClose} title={<Text fw={600} size="lg">{rule ? 'Edit rule' : 'Add rule'}</Text>}>
      <form onSubmit={submit}>
        <Stack gap="lg">
          <Stack gap={6}>
            <Text size="sm" fw={500}>
              When traffic matches
            </Text>
            <SegmentedControl
              fullWidth
              data={[
                { value: 'pass', label: 'Allow it' },
                { value: 'block', label: 'Drop it' },
                { value: 'reject', label: 'Refuse it' },
              ]}
              color={form.values.action === 'pass' ? 'teal' : form.values.action === 'block' ? 'red' : 'orange'}
              {...form.getInputProps('action')}
            />
            <Text size="xs" c="dimmed">
              {form.values.action === 'pass' && 'Let the connection through. Replies are allowed automatically.'}
              {form.values.action === 'block' && 'Silently discard it. The sender sees nothing, like a timeout.'}
              {form.values.action === 'reject' && 'Discard it and tell the sender, so their connection fails quickly.'}
            </Text>
          </Stack>

          <Select
            label="Arriving on"
            data={model.interfaces.map((i) => ({ value: i.id, label: i.name }))}
            allowDeselect={false}
            {...form.getInputProps('iface')}
          />

          <Group grow align="flex-start">
            <Select label="From" data={options} allowDeselect={false} {...form.getInputProps('srcKind')} />
            <Select label="To" data={options} allowDeselect={false} {...form.getInputProps('dstKind')} />
          </Group>
          {(form.values.srcKind === 'host' || form.values.srcKind === 'network') && (
            <TextInput
              label="Source"
              placeholder={form.values.srcKind === 'host' ? '192.168.1.50' : '192.168.1.0/24'}
              styles={monoInput}
              {...form.getInputProps('srcValue')}
            />
          )}
          {(form.values.dstKind === 'host' || form.values.dstKind === 'network') && (
            <TextInput
              label="Destination"
              placeholder={form.values.dstKind === 'host' ? '192.168.1.50' : '192.168.1.0/24'}
              styles={monoInput}
              {...form.getInputProps('dstValue')}
            />
          )}

          <Group grow align="flex-start">
            <Select
              label="Protocol"
              data={[
                { value: 'any', label: 'Any' },
                { value: 'tcp', label: 'TCP' },
                { value: 'udp', label: 'UDP' },
                { value: 'tcp/udp', label: 'TCP and UDP' },
                { value: 'icmp', label: 'ICMP (ping)' },
              ]}
              allowDeselect={false}
              {...form.getInputProps('protocol')}
            />
            <Autocomplete
              label="Port"
              placeholder="Any port"
              data={[
                { group: 'Common', items: commonPorts.map((p) => p.value) },
                ...(portAliases.length ? [{ group: 'Aliases', items: portAliases.map((p) => p.value) }] : []),
              ]}
              renderOption={({ option }) => <Text size="sm">{portOptionLabel(option.value)}</Text>}
              disabled={portless(form.values.protocol)}
              styles={monoInput}
              {...form.getInputProps('port')}
            />
          </Group>

          <TextInput label="Description" placeholder="Allow the office printer to reach the print server" {...form.getInputProps('description')} />

          <Stack gap="sm">
            <Switch label="Log matching traffic" description="Shows up under Diagnostics → Firewall log." {...form.getInputProps('log', { type: 'checkbox' })} />
            <Switch label="Enabled" {...form.getInputProps('enabled', { type: 'checkbox' })} />
          </Stack>

          <Text size="xs" c="dimmed">
            {`This rule ${form.values.action === 'pass' ? 'allows' : 'blocks'} traffic arriving on ${ifaceName(model, form.values.iface)}. Rules are checked top to bottom and the first match wins.`}
          </Text>

          <Group justify="flex-end">
            <Button variant="default" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit">{rule ? 'Save rule' : 'Add rule'}</Button>
          </Group>
        </Stack>
      </form>
    </Drawer>
  );
}

function blank(iface: string): Values {
  return {
    iface, enabled: true, action: 'pass', protocol: 'tcp',
    srcKind: iface === 'wan' ? 'any' : `net:${iface}`, srcValue: '',
    dstKind: 'any', dstValue: '', port: '', log: false, description: '',
  };
}

function validateCustom(kind: EndpointKind, v: string): string | null {
  if (kind === 'host') return isIPv4(v) ? null : 'Enter an address like 192.168.1.50';
  if (kind === 'network') return isCIDR(v) ? null : 'Enter a network like 192.168.1.0/24';
  return null;
}
