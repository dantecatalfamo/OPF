import { useEffect, useRef, useState } from 'react';
import {
  Accordion, Alert, Autocomplete, Badge, Button, Code, Drawer, Group, Loader, MultiSelect, NumberInput, SegmentedControl, Select, SimpleGrid,
  Stack, Switch, Text, Textarea, TextInput, Tooltip,
} from '@mantine/core';
import { useForm } from '@mantine/form';
import { IconCode, IconForms, IconInfoCircle, IconWand } from '@tabler/icons-react';
import type { BlockReturn, FormRule, Model, Rule, RuleInput, StateOptions } from '../model/types';
import { formRule } from '../model/sample';
import { isCIDR, isIPv4, isPfPortExpr } from '../lib/ip';
import { commonPorts } from '../lib/labels';
import { checkPfLine } from '../lib/pfcheck';
import { EndpointField, validateEndpoint } from '../components/EndpointField';
import { getIcmpTypeOptions, getIcmpCodeOptions, returnIcmpCodes, returnIcmp6Codes } from '../lib/icmp';
import { tryParseAsFormRule, generateRule } from '../lib/api';

type Values = Omit<FormRule, 'id' | 'kind'> & { mode: 'form' | 'raw'; rawText: string };

const mono = { input: { fontFamily: 'var(--mantine-font-family-monospace)' } };
const hasPorts = (p: FormRule['protocol']) => p === 'tcp' || p === 'udp' || p === 'tcp/udp';
const isTcp = (p: FormRule['protocol']) => p === 'tcp' || p === 'tcp/udp';

function toValues(rule: Rule | null, iface: string | null): Values {
  const base = formRule({ id: 'new', interfaces: iface ? [iface] : [], description: '', protocol: 'tcp' });
  if (!rule) {
    const src = iface && iface !== 'wan' ? { type: 'net' as const, iface } : { type: 'any' as const };
    return { ...stripIds(base), source: src, mode: 'form', rawText: '' };
  }
  if (rule.kind === 'raw') {
    return { ...stripIds(base), interfaces: rule.interfaces, enabled: rule.enabled, description: rule.description, mode: 'raw', rawText: rule.text };
  }
  return { ...stripIds(rule), mode: 'form', rawText: '' };
}

function stripIds(r: FormRule): Omit<FormRule, 'id' | 'kind'> {
  const { id: _id, kind: _kind, ...rest } = r;
  return rest;
}

function toRule(v: Values): Omit<FormRule, 'id'> {
  const { mode: _m, rawText: _r, ...rest } = v;
  const r: Omit<FormRule, 'id'> = { ...rest, kind: 'form', description: v.description.trim() };
  if (!hasPorts(r.protocol)) {
    delete r.port;
    delete r.sourcePort;
  }
  if (!r.port?.trim()) delete r.port;
  if (!r.sourcePort?.trim()) delete r.sourcePort;
  if (!isTcp(r.protocol) || !r.tcpFlags?.trim()) delete r.tcpFlags;
  if (r.state && r.state.mode === 'keep' && !Object.entries(r.state).some(([k, val]) => k !== 'mode' && val !== undefined && val !== false && val !== '')) delete r.state;
  for (const k of ['gateway', 'replyTo', 'tag', 'tagged', 'osFingerprint', 'icmpType'] as const) if (!r[k]) delete r[k];
  if (r.rtable === undefined || (r.rtable as unknown) === '') delete r.rtable;
  if (r.prio === undefined || (r.prio as unknown) === '') delete r.prio;
  if (r.probability === undefined || (r.probability as unknown) === '' || r.probability === 100) delete r.probability;
  if (!r.once) delete r.once;
  return r;
}

function countSet(...vals: unknown[]) {
  return vals.filter((v) => v !== undefined && v !== '' && v !== false && v !== null).length;
}

function SectionLabel({ label, count }: { label: string; count: number }) {
  return (
    <Group gap="xs">
      <Text size="sm" fw={500}>{label}</Text>
      {count > 0 && <Badge size="xs" color="harbor">{count} set</Badge>}
    </Group>
  );
}

export function RuleDrawer({
  opened, onClose, model, rule, iface, onSave,
}: {
  opened: boolean;
  onClose: () => void;
  model: Model;
  rule: Rule | null; // null: new rule
  iface: string | null; // null: floating
  onSave: (r: RuleInput) => void;
}) {
  const form = useForm<Values>({
    initialValues: toValues(null, iface),
    validate: (v) => {
      const e: Record<string, string | null> = {};
      e.description = v.description.trim() ? null : 'Describe what this rule is for';
      if (v.mode === 'raw') {
        e.rawText = checkPfLine(v.rawText);
        return e;
      }
      e.source = validateEndpoint(v.source, isIPv4, isCIDR);
      e.destination = validateEndpoint(v.destination, isIPv4, isCIDR);
      const port = (s?: string) => (!s?.trim() || s.startsWith('alias:') || isPfPortExpr(s) ? null : 'Use pf port syntax: 443, 8000:8080, > 1023, != 22, or 80,443');
      if (hasPorts(v.protocol)) {
        e.port = port(v.port);
        e.sourcePort = port(v.sourcePort);
      }
      if (isTcp(v.protocol) && v.tcpFlags && !/^(any|[FSRPAUEW]*\/[FSRPAUEW]+)$/.test(v.tcpFlags)) e.tcpFlags = 'Like S/SA, or any';
      if (v.state?.overload && !model.firewall.aliases.some((a) => a.name === v.state!.overload && a.type === 'table')) e['state.overload'] = 'Pick a table alias';
      return e;
    },
  });

  useEffect(() => {
    if (!opened) return;
    form.setValues(toValues(rule, iface));
    form.resetDirty();
    form.clearErrors();
  }, [opened, rule, iface]); // form is stable

  const v = form.values;

  // Use backend API for rule preview generation (debounced)
  const [preview, setPreview] = useState('');
  const [previewLoading, setPreviewLoading] = useState(false);
  const previewAbortRef = useRef<AbortController | null>(null);

  useEffect(() => {
    if (v.mode !== 'form') {
      setPreview('');
      return;
    }

    // Cancel any pending request
    previewAbortRef.current?.abort();
    previewAbortRef.current = new AbortController();

    // Debounce preview generation
    const timer = setTimeout(async () => {
      setPreviewLoading(true);
      try {
        const rule: Rule = { ...toRule(v), id: 'preview' };
        const result = await generateRule(rule, model);
        if (result.text) {
          setPreview(result.text);
        } else if (result.error) {
          setPreview(`# Error: ${result.error}`);
        }
      } catch {
        // Request was aborted or failed
      } finally {
        setPreviewLoading(false);
      }
    }, 150); // 150ms debounce

    return () => clearTimeout(timer);
  }, [v, model]);

  const state: StateOptions = v.state ?? { mode: 'keep' };
  const setState = (patch: Partial<StateOptions>) => form.setFieldValue('state', { ...state, ...patch });

  const tables = model.firewall.aliases.filter((a) => a.type === 'table').map((a) => a.name);
  const portAliases = model.firewall.aliases.filter((a) => a.type === 'ports').map((a) => `alias:${a.name}`);
  const gateways = model.routing.gateways.map((g) => ({ value: g.id, label: `${g.name} (${g.address === 'dhcp' ? 'DHCP' : g.address})` }));

  // Parse rule from raw syntax state
  const [parseLoading, setParseLoading] = useState(false);
  const handleParseRule = async () => {
    if (!v.rawText.trim()) return;
    setParseLoading(true);
    try {
      const parsedRule = await tryParseAsFormRule(v.rawText, model);
      if (parsedRule && parsedRule.kind === 'form') {
        // Successfully parsed - switch to form mode with populated values
        const { id: _id, kind: _kind, ...formValues } = parsedRule;
        form.setValues({ ...formValues, mode: 'form', rawText: '' });
      } else {
        // Could not convert to form rule - show error
        form.setFieldError('rawText', 'This rule cannot be converted to the guided form. Complex features like NAT, anchors, or queues are only supported in raw mode.');
      }
    } catch {
      form.setFieldError('rawText', 'Failed to parse rule');
    } finally {
      setParseLoading(false);
    }
  };
  const portData = [{ group: 'Common', items: commonPorts.map((p) => p.value) }, ...(portAliases.length ? [{ group: 'Aliases', items: portAliases }] : [])];

  const switchMode = (mode: string) => {
    if (mode === 'raw' && v.mode === 'form') form.setValues({ mode: 'raw', rawText: preview });
    if (mode === 'form') form.setFieldValue('mode', 'form');
  };

  const submit = form.onSubmit((vals) => {
    if (vals.mode === 'raw') {
      onSave({ kind: 'raw', text: vals.rawText.trim(), interfaces: vals.interfaces, enabled: vals.enabled, description: vals.description.trim() });
    } else {
      onSave(toRule(vals));
    }
    onClose();
  });

  const ifaceData = model.interfaces.map((i) => ({ value: i.id, label: i.name }));

  return (
    <Drawer opened={opened} onClose={onClose} size="xl" title={<Text fw={600} size="lg">{rule ? 'Edit rule' : 'Add rule'}</Text>}>
      <form onSubmit={submit}>
        <Stack gap="lg">
          <SegmentedControl
            value={v.mode}
            onChange={switchMode}
            data={[
              { value: 'form', label: <Group gap={6} justify="center"><IconForms size={16} />Guided</Group> },
              { value: 'raw', label: <Group gap={6} justify="center"><IconCode size={16} />pf syntax</Group> },
            ]}
          />

          {v.mode === 'raw' ? (
            <>
              <Textarea
                label="Rule"
                description="Any single pf.conf(5) rule. Macros for interfaces ($wan, $lan…) and aliases (<name>) are available. OPF checks it with pfctl before applying."
                autosize
                minRows={3}
                styles={mono}
                {...form.getInputProps('rawText')}
              />
              <Group justify="flex-end">
                <Tooltip label="Try to convert this rule to the guided form">
                  <Button
                    variant="subtle"
                    size="xs"
                    leftSection={<IconWand size={14} />}
                    loading={parseLoading}
                    onClick={handleParseRule}
                    disabled={!v.rawText.trim()}
                  >
                    Parse to guided
                  </Button>
                </Tooltip>
              </Group>
              <MultiSelect
                label="List under"
                description="Only decides which tab shows this rule. The rule text itself says where it applies."
                placeholder="Floating"
                data={ifaceData}
                {...form.getInputProps('interfaces')}
              />
              <TextInput label="Description" {...form.getInputProps('description')} />
              <Switch label="Enabled" {...form.getInputProps('enabled', { type: 'checkbox' })} />
              <Text size="xs" c="dimmed">Switching back to Guided discards edits made here.</Text>
            </>
          ) : (
            <>
              <Stack gap={6}>
                <SegmentedControl
                  fullWidth
                  data={[
                    { value: 'pass', label: 'Allow' },
                    { value: 'block', label: 'Drop' },
                    { value: 'reject', label: 'Refuse' },
                    { value: 'match', label: 'Match only' },
                  ]}
                  color={v.action === 'pass' ? 'teal' : v.action === 'block' ? 'red' : v.action === 'reject' ? 'orange' : 'harbor'}
                  {...form.getInputProps('action')}
                />
                {v.action === 'block' && (
                  <SimpleGrid cols={{ base: 1, sm: 3 }}>
                    <Select
                      label="Block return type"
                      data={[
                        { value: 'drop', label: 'Silent drop' },
                        { value: 'return', label: 'Return (TCP RST or ICMP)' },
                        { value: 'return-rst', label: 'Return RST (TCP only)' },
                        { value: 'return-icmp', label: 'Return ICMP error' },
                        { value: 'return-icmp6', label: 'Return ICMPv6 error' },
                      ]}
                      value={v.blockReturn ?? 'drop'}
                      onChange={(val) => form.setFieldValue('blockReturn', (val ?? 'drop') as BlockReturn)}
                      allowDeselect={false}
                    />
                    {v.blockReturn === 'return-rst' && (
                      <NumberInput
                        label="RST TTL"
                        placeholder="Default"
                        min={1}
                        max={255}
                        {...form.getInputProps('returnRstTtl')}
                      />
                    )}
                    {v.blockReturn === 'return-icmp' && (
                      <Select
                        label="ICMP code"
                        placeholder="port-unr (default)"
                        data={returnIcmpCodes}
                        clearable
                        {...form.getInputProps('returnIcmpCode')}
                      />
                    )}
                    {v.blockReturn === 'return-icmp6' && (
                      <Select
                        label="ICMPv6 code"
                        placeholder="port-unr (default)"
                        data={returnIcmp6Codes}
                        clearable
                        {...form.getInputProps('returnIcmpCode')}
                      />
                    )}
                  </SimpleGrid>
                )}
                <Text size="xs" c="dimmed">
                  {v.action === 'pass' && 'Let matching connections through. Replies are allowed automatically.'}
                  {v.action === 'block' && !v.blockReturn && 'Silently discard. The sender sees nothing, like a timeout.'}
                  {v.action === 'block' && v.blockReturn === 'drop' && 'Silently discard. The sender sees nothing, like a timeout.'}
                  {v.action === 'block' && v.blockReturn === 'return' && 'Send TCP RST for TCP, ICMP unreachable for others.'}
                  {v.action === 'block' && v.blockReturn === 'return-rst' && 'Send TCP RST. Only works for TCP connections.'}
                  {v.action === 'block' && v.blockReturn === 'return-icmp' && 'Send ICMP unreachable error to IPv4 sender.'}
                  {v.action === 'block' && v.blockReturn === 'return-icmp6' && 'Send ICMPv6 unreachable error to IPv6 sender.'}
                  {v.action === 'reject' && 'Discard and tell the sender, so their connection fails quickly (block return).'}
                  {v.action === 'match' && 'Neither allow nor block. Apply options such as priority, tags or routing, then keep checking rules.'}
                </Text>
              </Stack>

              <SimpleGrid cols={{ base: 1, sm: 3 }}>
                <MultiSelect label="Interfaces" placeholder="Any interface" data={ifaceData} {...form.getInputProps('interfaces')} />
                <Select
                  label="Direction"
                  data={[{ value: 'in', label: 'Arriving (in)' }, { value: 'out', label: 'Leaving (out)' }, { value: 'any', label: 'Both' }]}
                  allowDeselect={false}
                  {...form.getInputProps('direction')}
                />
                <Select
                  label="Address family"
                  data={[{ value: 'inet', label: 'IPv4' }, { value: 'inet6', label: 'IPv6' }, { value: 'any', label: 'IPv4 and IPv6' }]}
                  allowDeselect={false}
                  {...form.getInputProps('family')}
                />
              </SimpleGrid>

              <Select
                label="Protocol"
                data={[
                  { value: 'any', label: 'Any' },
                  { value: 'tcp', label: 'TCP' },
                  { value: 'udp', label: 'UDP' },
                  { value: 'tcp/udp', label: 'TCP and UDP' },
                  { value: 'icmp', label: 'ICMP' },
                  { value: 'icmp6', label: 'ICMPv6' },
                  { value: 'esp', label: 'ESP (IPsec)' },
                  { value: 'gre', label: 'GRE' },
                ]}
                allowDeselect={false}
                {...form.getInputProps('protocol')}
              />

              <SimpleGrid cols={{ base: 1, sm: 2 }}>
                <Stack gap="xs">
                  <EndpointField label="From" value={v.source} onChange={(e) => form.setFieldValue('source', e)} model={model} error={form.errors.source} />
                  {hasPorts(v.protocol) && (
                    <Autocomplete label="From port" placeholder="Any" data={portData} styles={mono} {...form.getInputProps('sourcePort')} />
                  )}
                </Stack>
                <Stack gap="xs">
                  <EndpointField label="To" value={v.destination} onChange={(e) => form.setFieldValue('destination', e)} model={model} error={form.errors.destination} />
                  {hasPorts(v.protocol) && (
                    <Autocomplete label="To port" placeholder="Any" data={portData} styles={mono} {...form.getInputProps('port')} />
                  )}
                </Stack>
              </SimpleGrid>

              <TextInput label="Description" placeholder="Allow the office printer to reach the print server" {...form.getInputProps('description')} />

              <SimpleGrid cols={{ base: 1, sm: 2 }}>
                <Select
                  label="Logging"
                  data={[{ value: 'off', label: 'Off' }, { value: 'on', label: 'New connections' }, { value: 'all', label: 'Every packet' }]}
                  allowDeselect={false}
                  {...form.getInputProps('log')}
                />
                <Stack gap={8} pt={4}>
                  <Switch
                    label="Stop at this rule"
                    description={v.quick ? 'First match wins (quick).' : 'Later rules can still override this one.'}
                    {...form.getInputProps('quick', { type: 'checkbox' })}
                  />
                  <Switch label="Enabled" {...form.getInputProps('enabled', { type: 'checkbox' })} />
                </Stack>
              </SimpleGrid>

              <Accordion variant="separated" multiple radius="md">
                <Accordion.Item value="state">
                  <Accordion.Control>
                    <SectionLabel label="Connection tracking and limits" count={countSet(v.state?.mode !== 'keep' ? v.state?.mode : undefined, v.state?.maxStates, v.state?.maxSrcConn, v.state?.maxSrcConnRate, v.state?.overload, v.tcpFlags)} />
                  </Accordion.Control>
                  <Accordion.Panel>
                    <Stack>
                      {v.action !== 'pass' && <Text size="xs" c="dimmed">These only apply to Allow rules.</Text>}
                      <SimpleGrid cols={{ base: 1, sm: 2 }}>
                        <Select
                          label="State tracking"
                          data={[
                            { value: 'keep', label: 'Keep state (default)' },
                            { value: 'modulate', label: 'Modulate state (randomize TCP sequence numbers)' },
                            { value: 'synproxy', label: 'SYN proxy (complete handshakes first)' },
                            { value: 'none', label: 'No state (stateless)' },
                          ]}
                          value={state.mode}
                          allowDeselect={false}
                          onChange={(m) => m && setState({ mode: m as StateOptions['mode'] })}
                        />
                        {isTcp(v.protocol) && <TextInput label="TCP flags" placeholder="S/SA" styles={mono} {...form.getInputProps('tcpFlags')} />}
                      </SimpleGrid>
                      <SimpleGrid cols={{ base: 1, sm: 3 }}>
                        <NumberInput label="Max connections" placeholder="No limit" min={1} value={state.maxStates ?? ''} onChange={(n) => setState({ maxStates: n === '' ? undefined : Number(n) })} />
                        <NumberInput label="Max per source" placeholder="No limit" min={1} value={state.maxSrcConn ?? ''} onChange={(n) => setState({ maxSrcConn: n === '' ? undefined : Number(n) })} />
                        <Group gap={6} align="flex-end" wrap="nowrap">
                          <NumberInput label="New per source" placeholder="—" min={1} value={state.maxSrcConnRate?.count ?? ''} onChange={(n) => setState({ maxSrcConnRate: n === '' ? undefined : { count: Number(n), seconds: state.maxSrcConnRate?.seconds ?? 10 } })} />
                          <NumberInput label="per seconds" placeholder="—" min={1} value={state.maxSrcConnRate?.seconds ?? ''} disabled={!state.maxSrcConnRate} onChange={(n) => state.maxSrcConnRate && setState({ maxSrcConnRate: { ...state.maxSrcConnRate, seconds: Number(n) || 1 } })} />
                        </Group>
                      </SimpleGrid>
                      <SimpleGrid cols={{ base: 1, sm: 2 }}>
                        <Select
                          label="When a source exceeds a limit, add it to"
                          placeholder="Nothing"
                          data={tables}
                          clearable
                          value={state.overload ?? null}
                          error={form.errors['state.overload']}
                          onChange={(t) => setState({ overload: t ?? undefined })}
                        />
                        <Switch mt={30} label="…and close its existing connections" checked={!!state.flushGlobal} disabled={!state.overload} onChange={(e) => setState({ flushGlobal: e.currentTarget.checked })} />
                      </SimpleGrid>
                      <SimpleGrid cols={{ base: 1, sm: 2 }}>
                        <Select
                          label="State binding"
                          data={[{ value: 'default', label: 'Firewall default' }, { value: 'if-bound', label: 'Bound to this interface' }, { value: 'floating', label: 'Any interface' }]}
                          value={state.policy ?? 'default'}
                          allowDeselect={false}
                          onChange={(p) => setState({ policy: p === 'default' ? undefined : (p as StateOptions['policy']) })}
                        />
                        <Switch mt={30} label="Sloppy tracking (asymmetric routing)" checked={!!state.sloppy} onChange={(e) => setState({ sloppy: e.currentTarget.checked })} />
                      </SimpleGrid>
                    </Stack>
                  </Accordion.Panel>
                </Accordion.Item>

                <Accordion.Item value="routing">
                  <Accordion.Control>
                    <SectionLabel label="Routing" count={countSet(v.gateway, v.replyTo, v.rtable)} />
                  </Accordion.Control>
                  <Accordion.Panel>
                    <Stack>
                      <Text size="xs" c="dimmed">Send matching traffic somewhere other than the routing table says. Useful for multiple internet connections or sending one device through a VPN.</Text>
                      <SimpleGrid cols={{ base: 1, sm: 3 }}>
                        <Select label="Send via gateway" placeholder="Routing table" data={gateways} clearable {...form.getInputProps('gateway')} />
                        <Select label="Send replies via" placeholder="Routing table" data={gateways} clearable {...form.getInputProps('replyTo')} />
                        <NumberInput label="Routing table" placeholder="0" min={0} max={255} {...form.getInputProps('rtable')} />
                      </SimpleGrid>
                    </Stack>
                  </Accordion.Panel>
                </Accordion.Item>

                <Accordion.Item value="tags">
                  <Accordion.Control>
                    <SectionLabel label="Tags and priority" count={countSet(v.tag, v.tagged, v.prio)} />
                  </Accordion.Control>
                  <Accordion.Panel>
                    <SimpleGrid cols={{ base: 1, sm: 3 }}>
                      <TextInput label="Tag packets" placeholder="VOIP" styles={mono} {...form.getInputProps('tag')} />
                      <TextInput label="Only packets tagged" placeholder="VOIP" styles={mono} {...form.getInputProps('tagged')} />
                      <Select
                        label="Priority"
                        placeholder="Default (3)"
                        data={Array.from({ length: 8 }, (_, i) => ({ value: String(i), label: `${i}${i === 7 ? ' · highest' : i === 0 ? ' · lowest' : ''}` }))}
                        clearable
                        value={v.prio === undefined ? null : String(v.prio)}
                        onChange={(p) => form.setFieldValue('prio', p === null ? undefined : Number(p))}
                      />
                    </SimpleGrid>
                  </Accordion.Panel>
                </Accordion.Item>

                <Accordion.Item value="match">
                  <Accordion.Control>
                    <SectionLabel label="More matching options" count={countSet(v.icmpType, v.osFingerprint, v.probability !== undefined && v.probability < 100 ? v.probability : undefined, v.once)} />
                  </Accordion.Control>
                  <Accordion.Panel>
                    <Stack gap="md">
                      {(v.protocol === 'icmp' || v.protocol === 'icmp6') && (
                        <SimpleGrid cols={{ base: 1, sm: 2 }}>
                          <Select
                            label="ICMP type"
                            placeholder="Any"
                            clearable
                            searchable
                            data={getIcmpTypeOptions(v.protocol === 'icmp6')}
                            {...form.getInputProps('icmpType')}
                          />
                          {v.icmpType && getIcmpCodeOptions(v.icmpType, v.protocol === 'icmp6').length > 0 && (
                            <Select
                              label="ICMP code"
                              placeholder="Any"
                              clearable
                              data={getIcmpCodeOptions(v.icmpType, v.protocol === 'icmp6')}
                              description="Optional: filter by specific code"
                            />
                          )}
                        </SimpleGrid>
                      )}
                      <SimpleGrid cols={{ base: 1, sm: 2 }}>
                        <Select label="Operating system" placeholder="Any" clearable data={['Windows', 'Linux', 'OpenBSD', 'FreeBSD', 'Mac OS', 'unknown']} {...form.getInputProps('osFingerprint')} />
                        <NumberInput label="Match only this share of packets" suffix="%" min={1} max={100} placeholder="100%" {...form.getInputProps('probability')} />
                      </SimpleGrid>
                      <Switch label="Match once, then disable" {...form.getInputProps('once', { type: 'checkbox' })} />
                    </Stack>
                  </Accordion.Panel>
                </Accordion.Item>
              </Accordion>
            </>
          )}

          {v.mode === 'raw' && (
            <Alert variant="light" color="harbor" icon={<IconInfoCircle size={18} />}>
              <Text size="xs">Rules are checked from top to bottom. Floating rules come before interface rules. See the full ruleset under Firewall → Ruleset.</Text>
            </Alert>
          )}
        </Stack>

        <Stack
          gap={8}
          pt="sm"
          pb="md"
          mt="lg"
          style={{ position: 'sticky', bottom: 0, zIndex: 5, background: 'var(--mantine-color-body)', borderTop: '1px solid var(--opf-line)' }}
        >
          {v.mode === 'form' && (
            <Group gap="xs" align="flex-start">
              <Code block style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word', fontSize: 12, flex: 1 }}>
                {preview || '# Loading...'}
              </Code>
              {previewLoading && <Loader size="xs" />}
            </Group>
          )}
          <Group justify="flex-end">
            <Button variant="default" onClick={onClose}>Cancel</Button>
            <Button type="submit">{rule ? 'Save rule' : 'Add rule'}</Button>
          </Group>
        </Stack>
      </form>
    </Drawer>
  );
}
