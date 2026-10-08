import { useEffect, type ReactNode } from 'react';
import { Accordion, Alert, Box, Button, Card, Checkbox, Divider, Grid, Group, NumberInput, Select, SimpleGrid, Stack, Switch, TagsInput, Text, TextInput } from '@mantine/core';
import { useForm } from '@mantine/form';
import { IconAlertTriangle } from '@tabler/icons-react';
import { useStore } from '../model/store';
import { timeoutNames, type FirewallOptions } from '../model/types';
import { PageHeader, SectionTitle } from '../components/ui';
import { TrafficSettingsCard } from './Traffic';

// Number fields are '' while empty; empty means pf's default. The form
// library reads dots in a field's path as nesting, so timeouts are kept
// under keys with underscores (tcp_established) while editing.
const formKey = (name: string) => name.replace(/\./g, '_');
type Num = number | '';
type Values = Omit<FirewallOptions, 'syncookiesStart' | 'syncookiesEnd' | 'hostId' | 'limits' | 'timeouts' | 'scrub'> & {
  scrub: Omit<FirewallOptions['scrub'], 'maxMss' | 'minTtl'> & { maxMss: Num; minTtl: Num };
  syncookiesStart: Num;
  syncookiesEnd: Num;
  hostId: Num;
  limits: Record<LimitKey, Num>;
  timeouts: Record<string, Num>;
};

type LimitKey = keyof NonNullable<FirewallOptions['limits']>;

// pf's defaults, from pf.conf(5); frags depends on the machine's memory.
const limitFields: { key: LimitKey; label: string; pf: string; description?: string }[] = [
  { key: 'tableEntries', label: 'Addresses in all tables', pf: '200,000', description: 'Downloaded blocklists count against this, and pf refuses the whole ruleset when they don’t fit.' },
  { key: 'tables', label: 'Tables', pf: '1,000' },
  { key: 'srcNodes', label: 'Source-tracking entries', pf: '10,000', description: 'Used by per-source connection limits.' },
  { key: 'frags', label: 'Fragments held for reassembly', pf: 'depends on memory' },
  { key: 'pktdelayPkts', label: 'Delayed packets', pf: '10,000' },
  { key: 'anchors', label: 'Anchors', pf: '512' },
];

const toValues = (o: FirewallOptions): Values => ({
  ...o,
  scrub: { ...o.scrub, maxMss: o.scrub.maxMss ?? '', minTtl: o.scrub.minTtl ?? '' },
  syncookiesStart: o.syncookiesStart ?? '',
  syncookiesEnd: o.syncookiesEnd ?? '',
  hostId: o.hostId ?? '',
  limits: Object.fromEntries(limitFields.map((f) => [f.key, o.limits?.[f.key] ?? ''])) as Values['limits'],
  timeouts: Object.fromEntries(timeoutNames.map((k) => [formKey(k), o.timeouts?.[k] ?? ''])),
});

// Back to the model: empty fields, lists and groups are left out, so pf's
// defaults apply and nothing is written for them.
function fromValues(v: Values): FirewallOptions {
  const num = (n: Num) => (n === '' ? undefined : Number(n));
  const some = <T,>(r: Record<string, T | undefined>) => {
    const out = Object.fromEntries(Object.entries(r).filter(([, x]) => x !== undefined));
    return Object.keys(out).length ? out : undefined;
  };
  const o: FirewallOptions = {
    ...v,
    scrub: { ...v.scrub, maxMss: num(v.scrub.maxMss), minTtl: num(v.scrub.minTtl), reassembleTcp: v.scrub.reassembleTcp || undefined },
    syncookiesStart: num(v.syncookiesStart),
    syncookiesEnd: num(v.syncookiesEnd),
    hostId: num(v.hostId),
    limits: some(Object.fromEntries(Object.entries(v.limits).map(([k, n]) => [k, num(n)]))),
    timeouts: some(Object.fromEntries(timeoutNames.map((k) => [k, num(v.timeouts[formKey(k)] ?? '')]))) as FirewallOptions['timeouts'],
    stateDefaults: v.stateDefaults?.length ? v.stateDefaults : undefined,
    skipOn: v.skipOn?.length ? v.skipOn : undefined,
    reassemble: v.reassemble || undefined,
    reassembleNoDf: v.reassemble === 'yes' && v.reassembleNoDf ? true : undefined,
    rulesetOptimization: v.rulesetOptimization || undefined,
    debug: v.debug || undefined,
    fingerprints: v.fingerprints?.trim() || undefined,
    logInterface: v.logInterface || undefined,
  };
  return JSON.parse(JSON.stringify(o)); // drops the undefineds
}

// What changed, for review and history.
const fieldNames: Record<string, string> = {
  blockPolicy: 'blocked traffic', logDefaultBlock: 'logging blocked traffic', statePolicy: 'connection tracking', optimization: 'timeouts',
  maxStates: 'maximum connections', syncookies: 'SYN cookies', syncookiesStart: 'SYN cookie thresholds', syncookiesEnd: 'SYN cookie thresholds',
  scrub: 'packet normalization', limits: 'limits', timeouts: 'individual timeouts', stateDefaults: 'state defaults', reassemble: 'fragment reassembly',
  reassembleNoDf: 'fragment reassembly', rulesetOptimization: 'ruleset optimization', debug: 'debug level', hostId: 'host id',
  fingerprints: 'OS fingerprints', logInterface: 'statistics interface', skipOn: 'unfiltered interfaces',
};
function describe(before: FirewallOptions, after: FirewallOptions): string {
  const keys = new Set([...Object.keys(before), ...Object.keys(after)]) as Set<keyof FirewallOptions>;
  const changed = [...new Set([...keys].filter((k) => JSON.stringify(before[k]) !== JSON.stringify(after[k])).map((k) => fieldNames[k] ?? k))];
  return changed.length ? `Changed firewall settings: ${changed.join(', ')}` : 'Changed firewall settings';
}

// Descriptions go under the input, so inputs in a row line up however
// long their descriptions are.
const below: ('label' | 'input' | 'description' | 'error')[] = ['label', 'input', 'description', 'error'];

// The timeouts by what they apply to, labelled without the prefix.
const timeoutGroups = [
  { label: 'TCP', prefix: 'tcp.' },
  { label: 'UDP', prefix: 'udp.' },
  { label: 'ICMP', prefix: 'icmp.' },
  { label: 'Other protocols', prefix: 'other.' },
  { label: 'Adaptive (states)', prefix: 'adaptive.' },
  { label: 'Fragments and tracking', prefix: '' },
].map((g, _, all) => ({
  ...g,
  names: timeoutNames.filter((k) => (g.prefix ? k.startsWith(g.prefix) : !all.some((o) => o.prefix && k.startsWith(o.prefix)))),
}));

// A titled part of Advanced.
function Part({ title, description, children }: { title: string; description?: string; children: ReactNode }) {
  return (
    <Stack gap="sm">
      <Divider label={<Text size="sm" fw={600} c="var(--mantine-color-text)">{title}</Text>} labelPosition="left" />
      {description && <Text size="xs" c="dimmed" mt={-4}>{description}</Text>}
      {children}
    </Stack>
  );
}

export function FirewallSettings() {
  const { staged, edit } = useStore();
  const opts = staged.firewall.options;
  const form = useForm<Values>({ initialValues: toValues(opts) });
  useEffect(() => {
    form.setValues(toValues(opts));
    form.resetDirty();
  }, [opts]); // form is stable
  const v = form.values;
  const inside = staged.interfaces.filter((i) => i.role !== 'wan');
  const hasBlocklists = staged.firewall.aliases.some((a) => a.type === 'url');
  const scrubEmpty = v.scrub.enabled && !v.scrub.noDf && !v.scrub.randomId && v.scrub.maxMss === '' && v.scrub.minTtl === '' && !v.scrub.reassembleTcp;

  return (
    <>
    <form onSubmit={form.onSubmit((vals) => {
      const next = fromValues(vals);
      edit('firewall', describe(opts, next), (m) => ({ ...m, firewall: { ...m.firewall, options: next } }));
    })}>
      <PageHeader
        title="Firewall settings"
        description="How pf behaves as a whole. The defaults suit most networks; empty fields keep pf’s default."
        actions={<Button type="submit" disabled={!form.isDirty()}>Save</Button>}
      />
      <Grid gutter="md">
        <Grid.Col span={{ base: 12, lg: 6 }}>
          <Card h="100%" id="blocking">
            <SectionTitle>Blocking</SectionTitle>
            <Stack>
              <Select
                label="Blocked traffic is"
                description="Applies to rules set to Drop and to the default block."
                data={[{ value: 'drop', label: 'Dropped silently' }, { value: 'return', label: 'Refused (TCP reset or ICMP unreachable)' }]}
                allowDeselect={false}
                {...form.getInputProps('blockPolicy')}
              />
              <Switch label="Log traffic blocked by the default rule" description="Useful for troubleshooting; busy on a WAN." {...form.getInputProps('logDefaultBlock', { type: 'checkbox' })} />
            </Stack>
          </Card>
        </Grid.Col>
        <Grid.Col span={{ base: 12, lg: 6 }}>
          <Card h="100%" id="connections">
            <SectionTitle>Connection tracking</SectionTitle>
            <Stack>
              <Select
                label="Connections are tracked"
                data={[{ value: 'floating', label: 'Across all interfaces (floating)' }, { value: 'if-bound', label: 'Per interface (if-bound, stricter)' }]}
                allowDeselect={false}
                {...form.getInputProps('statePolicy')}
              />
              <Select
                label="Timeouts"
                description="Or set them one by one under Advanced."
                data={[
                  { value: 'normal', label: 'Normal' },
                  { value: 'high-latency', label: 'High latency (satellite links)' },
                  { value: 'aggressive', label: 'Aggressive (expire idle connections sooner)' },
                  { value: 'conservative', label: 'Conservative (keep idle connections longer)' },
                ]}
                allowDeselect={false}
                {...form.getInputProps('optimization')}
              />
              <NumberInput label="Maximum tracked connections" min={1000} step={10000} thousandSeparator="," {...form.getInputProps('maxStates')} />
              <Select
                label="SYN cookies"
                description="Protect against SYN floods by answering handshakes without keeping state."
                data={[{ value: 'never', label: 'Off' }, { value: 'adaptive', label: 'When the state table is filling up' }, { value: 'always', label: 'Always' }]}
                allowDeselect={false}
                {...form.getInputProps('syncookies')}
              />
              {v.syncookies === 'adaptive' && (
                <Group grow>
                  <NumberInput label="Start when the table is" placeholder="25" suffix="% full" min={1} max={100} {...form.getInputProps('syncookiesStart')} />
                  <NumberInput label="Stop when it’s back under" placeholder="12" suffix="% full" min={1} max={100} {...form.getInputProps('syncookiesEnd')} />
                </Group>
              )}
            </Stack>
          </Card>
        </Grid.Col>
        <Grid.Col span={12}>
          <Card>
            <SectionTitle right={<Switch label="Enabled" {...form.getInputProps('scrub.enabled', { type: 'checkbox' })} />}>Packet normalization (scrub)</SectionTitle>
            <Group grow align="flex-start">
              <Stack gap="sm">
                <NumberInput label="Clamp TCP MSS to" description="Avoids broken connections over tunnels and PPPoE." placeholder="Off" min={536} max={1460} disabled={!v.scrub.enabled} {...form.getInputProps('scrub.maxMss')} />
                <NumberInput label="Raise TTL to at least" description="For networks where a low TTL gets packets dropped." placeholder="Off" min={1} max={255} disabled={!v.scrub.enabled} {...form.getInputProps('scrub.minTtl')} />
              </Stack>
              <Stack gap="sm" pt={4}>
                <Switch label="Clear the don’t-fragment bit" disabled={!v.scrub.enabled} {...form.getInputProps('scrub.noDf', { type: 'checkbox' })} />
                <Switch label="Randomize IP identifiers" disabled={!v.scrub.enabled} {...form.getInputProps('scrub.randomId', { type: 'checkbox' })} />
                <Switch label="Normalize TCP connections" description="Hides the TTL and timestamps of hosts behind the firewall." disabled={!v.scrub.enabled} {...form.getInputProps('scrub.reassembleTcp', { type: 'checkbox' })} />
              </Stack>
            </Group>
            <Text size="xs" c={scrubEmpty ? 'yellow' : 'dimmed'} mt="md">
              {scrubEmpty ? 'Choose at least one option; with none, scrub does nothing and isn’t written.' : 'Applies to incoming traffic on every interface.'}
            </Text>
          </Card>
        </Grid.Col>
        <Grid.Col span={12}>
          <Card id="limits">
            <SectionTitle>Limits</SectionTitle>
            <SimpleGrid cols={{ base: 1, sm: 2, lg: 3 }} verticalSpacing="lg">
              {limitFields.map((f) => (
                <NumberInput key={f.key} label={f.label} description={f.description} inputWrapperOrder={below} placeholder={`pf default (${f.pf})`} min={1} thousandSeparator="," {...form.getInputProps(`limits.${f.key}`)} />
              ))}
            </SimpleGrid>
            {hasBlocklists && v.limits.tableEntries === '' && (
              <Text size="xs" c="dimmed" mt="md">You have downloaded blocklists; large ones can need more than pf’s 200,000 table addresses.</Text>
            )}
          </Card>
        </Grid.Col>
        <Grid.Col span={12}>
          <Accordion variant="contained" radius="md">
            <Accordion.Item value="advanced">
              <Accordion.Control><Text fw={600}>Advanced</Text></Accordion.Control>
              <Accordion.Panel>
                <Stack gap="xl">
                  <Part title="Individual timeouts" description="In seconds, except the adaptive values, which count states: timeouts shrink as the table fills past the start and reach zero at the end. Empty keeps the “Timeouts” preset’s value.">
                    <Stack gap="sm">
                      {timeoutGroups.map((g) => (
                        <Grid key={g.label} gutter="sm" align="flex-end">
                          <Grid.Col span={{ base: 12, sm: 2 }}>
                            <Text size="sm" c="dimmed" pb={{ sm: 6 }}>{g.label}</Text>
                          </Grid.Col>
                          <Grid.Col span={{ base: 12, sm: 10 }}>
                            <SimpleGrid cols={{ base: 3, sm: 4, lg: 7 }} spacing="sm">
                              {g.names.map((k) => (
                                <NumberInput key={k} label={k.slice(g.prefix.length)} min={0} size="xs" hideControls styles={{ label: { fontFamily: 'var(--mantine-font-family-monospace)' } }} {...form.getInputProps(`timeouts.${formKey(k)}`)} />
                              ))}
                            </SimpleGrid>
                          </Grid.Col>
                        </Grid>
                      ))}
                    </Stack>
                  </Part>
                  <Part title="State and fragments">
                    <SimpleGrid cols={{ base: 1, md: 2 }} spacing="xl">
                      <Checkbox.Group label="Every connection’s state" description="Applies to every rule that keeps state." inputWrapperOrder={below} {...form.getInputProps('stateDefaults')}>
                        <Stack gap={6} my={6}>
                          <Checkbox value="no-sync" label="Not synchronized to a failover partner (no-sync)" />
                          <Checkbox value="pflow" label="Exported as flow records (pflow)" />
                          <Checkbox value="sloppy" label="Sloppy TCP tracking, for asymmetric routing (sloppy)" />
                        </Stack>
                      </Checkbox.Group>
                      <Stack gap="sm">
                        <Select
                          label="Fragment reassembly"
                          data={[{ value: '', label: 'pf default (on)' }, { value: 'yes', label: 'On' }, { value: 'no', label: 'Off' }]}
                          {...form.getInputProps('reassemble')}
                          value={v.reassemble ?? ''}
                        />
                        {v.reassemble === 'yes' && <Switch label="Clear the don’t-fragment bit on reassembled packets" {...form.getInputProps('reassembleNoDf', { type: 'checkbox' })} />}
                      </Stack>
                    </SimpleGrid>
                  </Part>
                  <Part title="Loading and logging">
                    <SimpleGrid cols={{ base: 1, sm: 3 }} spacing="xl">
                      <Select
                        label="Ruleset optimization"
                        description="How pfctl tidies the rules as it loads them."
                        inputWrapperOrder={below}
                        data={[{ value: '', label: 'pf default (basic)' }, { value: 'none', label: 'None' }, { value: 'basic', label: 'Basic' }, { value: 'profile', label: 'Profile against current traffic' }]}
                        {...form.getInputProps('rulesetOptimization')}
                        value={v.rulesetOptimization ?? ''}
                      />
                      <Select
                        label="Statistics interface"
                        description="The interface pf keeps packet and byte counts for."
                        inputWrapperOrder={below}
                        data={[{ value: '', label: 'The WAN' }, ...staged.interfaces.map((i) => ({ value: i.id, label: `${i.name} (${i.device})` })), { value: 'none', label: 'None' }]}
                        {...form.getInputProps('logInterface')}
                        value={v.logInterface ?? ''}
                      />
                      <Select
                        label="pf debug level"
                        description="How much pf logs about itself."
                        inputWrapperOrder={below}
                        data={[{ value: '', label: 'pf default (err)' }, ...['emerg', 'alert', 'crit', 'err', 'warning', 'notice', 'info', 'debug'].map((d) => ({ value: d, label: d }))]}
                        {...form.getInputProps('debug')}
                        value={v.debug ?? ''}
                      />
                    </SimpleGrid>
                  </Part>
                  <Part title="Unfiltered interfaces">
                    <Stack gap="sm" maw={640}>
                      <TagsInput
                        label="Don’t filter at all on"
                        description="Interfaces or groups pf ignores entirely, besides loopback. The WAN can’t be listed."
                        inputWrapperOrder={below}
                        data={inside.map((i) => i.id)}
                        {...form.getInputProps('skipOn')}
                        value={v.skipOn ?? []}
                      />
                      {(v.skipOn?.length ?? 0) > 0 && (
                        <Alert color="red" variant="light" p="xs" icon={<IconAlertTriangle size={16} />}>
                          Nothing is blocked on {v.skipOn!.join(', ')}: every rule, including the default block, is skipped there.
                        </Alert>
                      )}
                    </Stack>
                  </Part>
                  <Part title="Failover and fingerprints">
                    <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="xl">
                      <NumberInput label="Host id" description="Identifies this firewall to a failover partner (pfsync)." inputWrapperOrder={below} placeholder="Random" min={1} max={4294967295} {...form.getInputProps('hostId')} />
                      <TextInput label="OS fingerprint file" description="Used by rules that match an operating system." inputWrapperOrder={below} placeholder="/etc/pf.os" styles={{ input: { fontFamily: 'var(--mantine-font-family-monospace)' } }} {...form.getInputProps('fingerprints')} value={v.fingerprints ?? ''} />
                    </SimpleGrid>
                  </Part>
                </Stack>
              </Accordion.Panel>
            </Accordion.Item>
          </Accordion>
        </Grid.Col>
      </Grid>
    </form>
    {/* A setting of its own, saved apart from the options above. */}
    <Box mt="md"><TrafficSettingsCard /></Box>
    </>
  );
}
