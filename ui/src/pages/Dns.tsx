import { useEffect, useState } from 'react';
import { Alert, Anchor, Badge, Button, Card, Divider, Grid, Group, MultiSelect, SegmentedControl, Stack, Switch, Table, Tabs, TagsInput, Text } from '@mantine/core';
import { useForm } from '@mantine/form';
import { DnsTools } from './DnsTools';
import { LocalNames } from './DnsRecords';
import { IconAlertTriangle } from '@tabler/icons-react';
import { backend, useStore } from '../model/store';
import type { LeaseNamesResource } from '../lib/api';
import { formatAgo } from '../lib/format';
import { useNow } from '../lib/useNow';
import type { Dns as DnsSettings, Iface } from '../model/types';
import { isIPv4 } from '../lib/ip';
import { Empty, Mono, PageHeader, SectionTitle } from '../components/ui';
import { DeviceLink } from '../components/DeviceLink';
import { DnsBlocklists, DnsOwnNames } from './DnsBlocklists';
import { DnsBlockedNames, DnsStatsCard } from './DnsActivity';
import { DnsActivitySettingsCard, DnsActivityTab } from './DnsHistory';
import { Link, useSearchParams } from 'react-router';
import { FileLink } from './ConfigFiles';

type Settings = Omit<DnsSettings, 'overrides'>;

// What changed in the resolver settings, for review and history.
// Whether the resolver can answer on an interface (pf.DNSEligible): an
// inside one with a fixed address, not a way out through a provider.
const answerable = (i: Iface) => i.enabled && i.role !== 'wan' && !i.wireguard?.exit && i.ipv4.mode === 'static' && !!i.ipv4.address;

const switches: [keyof Settings, string][] = [
  ['enabled', 'the DNS resolver'],
  ['forwardTls', 'encrypted lookups'],
  ['dnssec', 'DNSSEC checking'],
  ['registerReservations', 'names for reserved devices'],
  ['registerDynamicLeases', 'names for other DHCP devices'],
  ['rewriteInvalidLeaseNames', 'fixing invalid device names'],
];

function describeSettings(before: Settings, after: Settings, names: (ids: string[]) => string): string {
  const parts: string[] = [];
  if ((after.interfaces ?? []).join() !== (before.interfaces ?? []).join()) {
    parts.push(after.interfaces?.length ? `DNS now answers only on ${names(after.interfaces)}` : 'DNS now answers on every inside network');
  }
  if (after.mode !== before.mode) parts.push(after.mode === 'forward' ? `DNS now forwards to ${after.forwarders.join(', ')}` : 'DNS now resolves directly (recursive)');
  else if (after.mode === 'forward' && after.forwarders.join() !== before.forwarders.join()) parts.push(`DNS now forwards to ${after.forwarders.join(', ')}`);
  for (const [key, what] of switches) {
    if (after[key] !== before[key]) parts.push(`${after[key] ? 'Turned on' : 'Turned off'} ${what}`);
  }
  return parts.length ? parts.join('; ') : 'Updated DNS resolver settings';
}

// How often the page asks what the lease watcher found; it looks every 15 s.
const LEASE_POLL_MS = 15_000;

// The names DHCP devices have in DNS right now, and the ones refused,
// one card with a switch between them. The server keeps them up to
// date; this only shows them.
function DeviceNames() {
  const { applied } = useStore();
  const [data, setData] = useState<LeaseNamesResource | null>(null);
  const [failed, setFailed] = useState<string | null>(null);
  const [view, setView] = useState<'given' | 'refused'>('given');
  const now = useNow(5000);
  useEffect(() => {
    let live = true;
    const load = () =>
      backend.leaseNames().then(
        (d) => { if (live) { setData(d); setFailed(null); } },
        (e) => { if (live) setFailed(e instanceof Error ? e.message : String(e)); },
      );
    load();
    const t = setInterval(load, LEASE_POLL_MS);
    return () => { live = false; clearInterval(t); };
  }, []);

  const domain = applied.system.domain;
  if (!applied.dns.registerDynamicLeases && !data?.enabled) return null;
  const refused = data?.refused ?? [];
  const showing = refused.length ? view : 'given';
  return (
    <Card>
      <SectionTitle
        right={
          <Group gap="sm">
            {data?.checked && <Text size="xs" c="dimmed">Checked {formatAgo((now - Date.parse(data.checked)) / 1000)}</Text>}
            {refused.length > 0 && (
              <SegmentedControl size="xs" value={showing} onChange={(v) => setView(v as 'given' | 'refused')}
                data={[{ value: 'given', label: `Given ${data?.registered.length ?? 0}` }, { value: 'refused', label: `Refused ${refused.length}` }]} />
            )}
          </Group>
        }
      >
        Devices’ names
      </SectionTitle>
      <Stack gap="sm">
        {failed && <Alert color="red" variant="light" p="sm" icon={<IconAlertTriangle size={16} />}>Couldn’t ask OPF: {failed}</Alert>}
        {data?.error && <Alert color="yellow" variant="light" p="sm" icon={<IconAlertTriangle size={16} />}>{data.error}.</Alert>}
        {data && !data.enabled && <Text size="sm" c="dimmed">Starts once “Add other DHCP devices by name” is applied.</Text>}
        {data?.enabled && showing === 'given' && (
          <>
            <Text size="sm" c="dimmed">
              The names devices asked for, reachable as name.{domain}. They follow the leases, so they come and go with the devices.
            </Text>
            {data.registered.length ? (
              <Table.ScrollContainer minWidth={420}>
                <Table>
                  <Table.Thead>
                    <Table.Tr><Table.Th>Name</Table.Th><Table.Th>Address</Table.Th><Table.Th>Asked for</Table.Th></Table.Tr>
                  </Table.Thead>
                  <Table.Tbody>
                    {data.registered.map((r) => (
                      <Table.Tr key={r.name}>
                        <Table.Td style={{ whiteSpace: 'nowrap' }}><DeviceLink deviceKey={`ip:${r.ip}`}><Mono>{r.name}</Mono></DeviceLink></Table.Td>
                        <Table.Td style={{ whiteSpace: 'nowrap' }}><Mono>{r.ip}</Mono></Table.Td>
                        {/* Chosen by the device; shown as text, never markup. */}
                        <Table.Td><Text size="sm" c="dimmed">{r.from ? `“${r.from}”` : ''}</Text></Table.Td>
                      </Table.Tr>
                    ))}
                  </Table.Tbody>
                </Table>
              </Table.ScrollContainer>
            ) : (
              <Empty>No devices have names from their leases yet.</Empty>
            )}
          </>
        )}
        {data?.enabled && showing === 'refused' && (
          <>
            <Text size="sm" c="dimmed">Devices that asked for a name they didn’t get, and why.</Text>
            <Table.ScrollContainer minWidth={420}>
              <Table>
                <Table.Thead>
                  <Table.Tr><Table.Th>Asked for</Table.Th><Table.Th>Address</Table.Th><Table.Th>Why not</Table.Th></Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {refused.map((r) => (
                    <Table.Tr key={r.ip}>
                      {/* Chosen by the device; shown as text, never markup. */}
                      <Table.Td style={{ whiteSpace: 'nowrap' }}><DeviceLink deviceKey={`ip:${r.ip}`}><Mono>“{r.hostname}”</Mono></DeviceLink></Table.Td>
                      <Table.Td style={{ whiteSpace: 'nowrap' }}><Mono>{r.ip}</Mono></Table.Td>
                      <Table.Td><Text size="sm" c="dimmed">{r.reason}</Text></Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            </Table.ScrollContainer>
          </>
        )}
        {data?.truncated && <Text size="xs" c="dimmed">Showing the first 1000.</Text>}
      </Stack>
    </Card>
  );
}

// How names are looked up, and how devices get names: one form, saved
// together.
function DnsSettingsForm() {
  const { staged, edit } = useStore();
  const dns = staged.dns;
  const pick = (d: DnsSettings): Settings => ({ enabled: d.enabled, interfaces: d.interfaces ?? [], mode: d.mode, forwarders: d.forwarders, forwardTls: d.forwardTls, dnssec: d.dnssec, registerReservations: d.registerReservations, registerDynamicLeases: d.registerDynamicLeases, rewriteInvalidLeaseNames: d.rewriteInvalidLeaseNames });
  // Networks whose DHCP tells devices to ask OPF, which a narrower
  // "Answer on" would leave unable to look anything up.
  const strandedBy = (v: Settings) => !v.enabled || !v.interfaces?.length ? [] : staged.dhcp
    .filter((s) => s.enabled && s.dns === 'self' && !v.interfaces!.includes(s.iface))
    .map((s) => ({ id: s.iface, name: staged.interfaces.find((i) => i.id === s.iface)?.name ?? s.iface }));
  const form = useForm<Settings>({
    initialValues: pick(dns),
    validateInputOnChange: ['interfaces'],
    validate: {
      forwarders: (v, vals) => (vals.mode === 'recursive' || (v.length && v.every(isIPv4)) ? null : 'Enter one or more IPv4 addresses'),
      interfaces: (_, vals) => {
        const left = strandedBy(vals);
        if (!left.length) return null;
        const one = left.length === 1;
        // Each network's name takes you to its DHCP settings.
        const dhcpLinks = left.map((n, k) => (
          <span key={n.id}>
            {k > 0 && (k === left.length - 1 ? ' and ' : ', ')}
            <Anchor component={Link} to={`/services/dhcp?iface=${encodeURIComponent(n.id)}`} size="xs">{n.name}’s DHCP</Anchor>
          </span>
        ));
        return (
          <>
            {left.map((n) => n.name).join(' and ')}’s DHCP tells devices to ask OPF for names, so leaving {one ? 'it' : 'them'} out would leave those devices unable to look anything up.
            Add {one ? 'it' : 'them'} here, or first have {dhcpLinks} hand out other DNS servers.
          </>
        );
      },
    },
  });
  useEffect(() => {
    form.setValues(pick(dns));
    form.resetDirty();
  }, [dns]); // form is stable
  const domain = staged.system.domain;
  const insides = staged.interfaces.filter((i) => i.role !== 'wan' && !i.wireguard?.exit);
  const names = (ids: string[]) => ids.map((id) => staged.interfaces.find((i) => i.id === id)?.name ?? id).join(', ');
  return (
    <Card maw={760}>
      <form onSubmit={form.onSubmit((v) => edit('dns', describeSettings(pick(dns), v, names), (m) => {
        const next = { ...m.dns, ...v };
        if (!next.interfaces?.length) delete next.interfaces; // every one it can
        return { ...m, dns: next };
      }))}>
        <SectionTitle right={<Switch label="Enabled" {...form.getInputProps('enabled', { type: 'checkbox' })} />}>Resolver</SectionTitle>
        <Stack gap="lg">
          <Stack gap="md">
            <Stack gap={6}>
              <Text size="sm" fw={500}>How to look up names</Text>
              <SegmentedControl
                data={[{ value: 'recursive', label: 'Directly' }, { value: 'forward', label: 'Through a provider' }]}
                {...form.getInputProps('mode')}
              />
              <Text size="xs" c="dimmed">
                {form.values.mode === 'recursive'
                  ? 'OPF asks the internet’s authoritative servers itself. Nobody else sees your full lookup history.'
                  : 'OPF sends lookups to the servers below, such as Quad9 or your ISP.'}
              </Text>
            </Stack>
            {form.values.mode === 'forward' && (
              <>
                <TagsInput label="Upstream servers" placeholder="9.9.9.9" {...form.getInputProps('forwarders')} />
                <Switch label="Encrypt lookups (DNS over TLS)" {...form.getInputProps('forwardTls', { type: 'checkbox' })} />
              </>
            )}
            <Switch label="Verify answers with DNSSEC" description="Rejects answers that have been tampered with." {...form.getInputProps('dnssec', { type: 'checkbox' })} />
          </Stack>
          <Divider />
          <Stack gap="md">
            <Text size="sm" fw={600}>Who can ask</Text>
            <MultiSelect
              label="Answer on" placeholder={form.values.interfaces?.length ? undefined : 'Every inside network and tunnel'}
              description="Devices on other networks are refused, whatever the firewall’s rules allow. Those rules still apply on top: a network listed here can be blocked from port 53 too."
              inputWrapperOrder={['label', 'input', 'description', 'error']}
              data={insides.map((i) => ({
                value: i.id, disabled: !answerable(i),
                label: answerable(i) ? i.name : `${i.name} (${!i.enabled ? 'off' : 'gets its address by DHCP'})`,
              }))}
              {...form.getInputProps('interfaces')}
            />
          </Stack>
          <Divider />
          <Stack gap="md">
            <Text size="sm" fw={600}>Devices by name</Text>
            <Switch label="Add reserved devices by name" description={`Devices with a DHCP reservation can be reached as name.${domain}.`} {...form.getInputProps('registerReservations', { type: 'checkbox' })} />
            <Switch
              label="Add other DHCP devices by name"
              description={`Devices can be reached by the name they give themselves, as name.${domain}. Any device can pick any name, so names used by this configuration, and names claimed by two devices, are never added.`}
              {...form.getInputProps('registerDynamicLeases', { type: 'checkbox' })}
            />
            <Switch
              label="Fix names that aren’t valid"
              description={`A device calling itself “Priya’s iPad” becomes priyas-ipad.${domain}. Turned off, devices with names like that get none.`}
              disabled={!form.values.registerDynamicLeases}
              {...form.getInputProps('rewriteInvalidLeaseNames', { type: 'checkbox' })}
            />
          </Stack>
          <Group justify="space-between">
            <FileLink path="/var/unbound/etc/unbound.conf" />
            <Button type="submit" disabled={!form.isDirty()}>Save</Button>
          </Group>
        </Stack>
      </form>
    </Card>
  );
}

const tabs = ['overview', 'activity', 'names', 'settings', 'blocking', 'tools'] as const;
type Tab = (typeof tabs)[number];

export function Dns() {
  const { staged, applied } = useStore();
  const dns = staged.dns;
  const [params, setParams] = useSearchParams();
  const asked = params.get('tab');
  // The page used to have one "resolver" tab for all of these.
  const tab: Tab = tabs.includes(asked as Tab) ? (asked as Tab) : 'overview';
  const enabledLists = (dns.blocklists ?? []).filter((l) => l.enabled).length;
  const names = dns.overrides.length + (dns.records ?? []).length;

  return (
    <>
      <PageHeader title="DNS resolver" description="Answers name lookups for devices on your networks, and caches the results so browsing feels faster." />
      <Tabs value={tab} onChange={(v) => setParams(v && v !== 'overview' ? { tab: v } : {}, { replace: true })} keepMounted={false}>
        <Tabs.List mb="md">
          <Tabs.Tab value="overview">Overview</Tabs.Tab>
          <Tabs.Tab value="activity">Activity</Tabs.Tab>
          <Tabs.Tab value="names" rightSection={names ? <Badge size="xs" variant="light" circle>{names}</Badge> : undefined}>Local names</Tabs.Tab>
          <Tabs.Tab value="settings">Settings</Tabs.Tab>
          <Tabs.Tab value="blocking" rightSection={enabledLists ? <Badge size="xs" variant="light" circle>{enabledLists}</Badge> : undefined}>Blocking</Tabs.Tab>
          <Tabs.Tab value="tools">Tools</Tabs.Tab>
        </Tabs.List>
        <Tabs.Panel value="overview">
          {/* What's happening, then the names devices gave themselves, a
              list that grows on its own. */}
          <Stack gap="md">
            <DnsStatsCard />
            <DeviceNames />
          </Stack>
        </Tabs.Panel>
        <Tabs.Panel value="activity">
          <DnsActivityTab />
        </Tabs.Panel>
        <Tabs.Panel value="names">
          <Stack gap="md">
            <Card><LocalNames /></Card>
          </Stack>
        </Tabs.Panel>
        <Tabs.Panel value="settings">
          <Stack gap="md">
            <DnsSettingsForm />
            <DnsActivitySettingsCard />
          </Stack>
        </Tabs.Panel>
        <Tabs.Panel value="blocking">
          {/* The lists and your own names, then what they blocked, a list
              that changes by itself. */}
          <Stack gap="md">
            <Grid gutter="md">
              <Grid.Col span={{ base: 12, lg: 7 }}>
                <DnsBlocklists />
              </Grid.Col>
              <Grid.Col span={{ base: 12, lg: 5 }}>
                <DnsOwnNames />
              </Grid.Col>
            </Grid>
            <DnsBlockedNames />
          </Stack>
        </Tabs.Panel>
        <Tabs.Panel value="tools">
          {applied.dns.enabled ? <DnsTools /> : <Alert color="gray" variant="light">The resolver isn’t running, so there’s nothing to ask.</Alert>}
        </Tabs.Panel>
      </Tabs>
    </>
  );
}
