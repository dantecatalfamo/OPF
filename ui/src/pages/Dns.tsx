import { useEffect, useState } from 'react';
import { Accordion, ActionIcon, Alert, Button, Card, Grid, Group, Modal, SegmentedControl, Stack, Switch, Table, TagsInput, Text, TextInput } from '@mantine/core';
import { useForm } from '@mantine/form';
import { IconAlertTriangle, IconPlus, IconTrash } from '@tabler/icons-react';
import { backend, newId, useStore } from '../model/store';
import type { LeaseNamesResource } from '../lib/api';
import { formatAgo } from '../lib/format';
import { useNow } from '../lib/useNow';
import type { Dns as DnsSettings } from '../model/types';
import { isIPv4 } from '../lib/ip';
import { Empty, Mono, PageHeader, SectionTitle } from '../components/ui';
import { DnsBlocklists } from './DnsBlocklists';

type Settings = Omit<DnsSettings, 'overrides'>;

// What changed in the resolver settings, for review and history.
const switches: [keyof Settings, string][] = [
  ['enabled', 'the DNS resolver'],
  ['forwardTls', 'encrypted lookups'],
  ['dnssec', 'DNSSEC checking'],
  ['registerReservations', 'names for reserved devices'],
  ['registerDynamicLeases', 'names for other DHCP devices'],
  ['rewriteInvalidLeaseNames', 'fixing invalid device names'],
];

function describeSettings(before: Settings, after: Settings): string {
  const parts: string[] = [];
  if (after.mode !== before.mode) parts.push(after.mode === 'forward' ? `DNS now forwards to ${after.forwarders.join(', ')}` : 'DNS now resolves directly (recursive)');
  else if (after.mode === 'forward' && after.forwarders.join() !== before.forwarders.join()) parts.push(`DNS now forwards to ${after.forwarders.join(', ')}`);
  for (const [key, what] of switches) {
    if (after[key] !== before[key]) parts.push(`${after[key] ? 'Turned on' : 'Turned off'} ${what}`);
  }
  return parts.length ? parts.join('; ') : 'Updated DNS resolver settings';
}

// How often the page asks what the lease watcher found; it looks every 15 s.
const LEASE_POLL_MS = 15_000;

// The names DHCP devices have in DNS right now, and the ones that were
// refused. The server keeps them up to date; this only shows them.
function LeaseNames() {
  const { applied } = useStore();
  const [data, setData] = useState<LeaseNamesResource | null>(null);
  const [failed, setFailed] = useState<string | null>(null);
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
  return (
    <Card>
      <SectionTitle right={data?.checked && <Text size="xs" c="dimmed">Checked {formatAgo((now - Date.parse(data.checked)) / 1000)}</Text>}>
        DHCP devices by name
      </SectionTitle>
      <Stack gap="sm">
        {failed && <Alert color="red" variant="light" p="sm" icon={<IconAlertTriangle size={16} />}>Couldn’t ask OPF: {failed}</Alert>}
        {data?.error && <Alert color="yellow" variant="light" p="sm" icon={<IconAlertTriangle size={16} />}>{data.error}.</Alert>}
        {data && !data.enabled && <Text size="sm" c="dimmed">Starts once “Add other DHCP devices by name” is applied.</Text>}
        {data?.enabled && (
          <>
            <Text size="sm" c="dimmed">
              Names devices asked for, reachable as name.{domain}. They follow the leases, so they come and go with the devices.
            </Text>
            {data.registered.length ? (
              <Table.ScrollContainer minWidth={360}>
                <Table>
                  <Table.Tbody>
                    {data.registered.map((r) => (
                      <Table.Tr key={r.name}>
                        <Table.Td>
                          <Mono>{r.name}</Mono>
                          {/* Chosen by the device; shown as text, never markup. */}
                          {r.from && <Text size="xs" c="dimmed">from “{r.from}”</Text>}
                        </Table.Td>
                        <Table.Td><Mono>{r.ip}</Mono></Table.Td>
                      </Table.Tr>
                    ))}
                  </Table.Tbody>
                </Table>
              </Table.ScrollContainer>
            ) : (
              <Empty>No devices have names from their leases yet.</Empty>
            )}
            {data.refused.length > 0 && (
              <Accordion variant="contained" radius="md">
                <Accordion.Item value="refused">
                  <Accordion.Control>
                    <Text size="sm">{data.refused.length} device{data.refused.length === 1 ? '' : 's'} didn’t get the name {data.refused.length === 1 ? 'it' : 'they'} asked for</Text>
                  </Accordion.Control>
                  <Accordion.Panel>
                    <Table.ScrollContainer minWidth={420}>
                      <Table>
                        <Table.Tbody>
                          {data.refused.map((r) => (
                            <Table.Tr key={r.ip}>
                              {/* Chosen by the device; shown as text, never markup. */}
                              <Table.Td><Mono>“{r.hostname}”</Mono></Table.Td>
                              <Table.Td><Mono>{r.ip}</Mono></Table.Td>
                              <Table.Td><Text size="sm" c="dimmed">{r.reason}</Text></Table.Td>
                            </Table.Tr>
                          ))}
                        </Table.Tbody>
                      </Table>
                    </Table.ScrollContainer>
                  </Accordion.Panel>
                </Accordion.Item>
              </Accordion>
            )}
            {data.truncated && <Text size="xs" c="dimmed">Showing the first 1000 of each.</Text>}
          </>
        )}
      </Stack>
    </Card>
  );
}

function OverrideModal({ opened, onClose }: { opened: boolean; onClose: () => void }) {
  const { staged, edit } = useStore();
  const form = useForm({
    initialValues: { host: '', domain: staged.system.domain, ip: '', description: '' },
    validate: {
      host: (v) => (/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/i.test(v) ? null : 'Letters, digits and hyphens only'),
      domain: (v) => (/^[a-z0-9.-]+$/i.test(v) ? null : 'Enter a domain like office.arpa'),
      ip: (v) => (isIPv4(v) ? null : 'Enter an IPv4 address'),
    },
  });
  useEffect(() => {
    if (opened) form.setValues({ host: '', domain: staged.system.domain, ip: '', description: '' });
  }, [opened, staged.system.domain]); // form is stable
  return (
    <Modal opened={opened} onClose={onClose} title={<Text fw={600}>Add a host name</Text>}>
      <form
        onSubmit={form.onSubmit((v) => {
          edit('dns', `Added host name ${v.host}.${v.domain} → ${v.ip}`, (m) => ({ ...m, dns: { ...m.dns, overrides: [...m.dns.overrides, { id: newId('h'), ...v }] } }));
          onClose();
        })}
      >
        <Stack>
          <Text size="sm" c="dimmed">Devices using OPF for DNS will find this address by name.</Text>
          <Group grow align="flex-start">
            <TextInput label="Name" placeholder="nas" {...form.getInputProps('host')} />
            <TextInput label="Domain" {...form.getInputProps('domain')} />
          </Group>
          <TextInput label="Address" placeholder="192.168.1.20" {...form.getInputProps('ip')} />
          <TextInput label="Description" {...form.getInputProps('description')} />
          <Group justify="flex-end" mt="sm">
            <Button variant="default" onClick={onClose}>Cancel</Button>
            <Button type="submit">Add</Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}

export function Dns() {
  const { staged, edit } = useStore();
  const dns = staged.dns;
  const [modal, setModal] = useState(false);
  const pick = (d: DnsSettings): Settings => ({ enabled: d.enabled, mode: d.mode, forwarders: d.forwarders, forwardTls: d.forwardTls, dnssec: d.dnssec, registerReservations: d.registerReservations, registerDynamicLeases: d.registerDynamicLeases, rewriteInvalidLeaseNames: d.rewriteInvalidLeaseNames });
  const form = useForm<Settings>({
    initialValues: pick(dns),
    validate: { forwarders: (v, vals) => (vals.mode === 'recursive' || (v.length && v.every(isIPv4)) ? null : 'Enter one or more IPv4 addresses') },
  });
  useEffect(() => {
    form.setValues(pick(dns));
    form.resetDirty();
  }, [dns]); // form is stable

  return (
    <>
      <PageHeader title="DNS resolver" description="Answers name lookups for devices on your networks, and caches the results so browsing feels faster." />
      <Grid gutter="md">
        <Grid.Col span={{ base: 12, lg: 5 }}>
          <Card>
            <form
              onSubmit={form.onSubmit((v) => edit('dns', describeSettings(dns, v), (m) => ({ ...m, dns: { ...m.dns, ...v } })))}
            >
              <SectionTitle right={<Switch label="Enabled" {...form.getInputProps('enabled', { type: 'checkbox' })} />}>Settings</SectionTitle>
              <Stack>
                <Stack gap={6}>
                  <Text size="sm" fw={500}>How to look up names</Text>
                  <SegmentedControl
                    fullWidth
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
                <Switch label="Add reserved devices by name" description={`Devices with a DHCP reservation can be reached as name.${staged.system.domain}.`} {...form.getInputProps('registerReservations', { type: 'checkbox' })} />
                <Switch
                  label="Add other DHCP devices by name"
                  description={`Devices can be reached by the name they give themselves, as name.${staged.system.domain}. Any device can pick any name, so names used by this configuration, and names claimed by two devices, are never added.`}
                  {...form.getInputProps('registerDynamicLeases', { type: 'checkbox' })}
                />
                <Switch
                  label="Fix names that aren’t valid"
                  description={`A device calling itself “Priya’s iPad” becomes priyas-ipad.${staged.system.domain}. Turned off, devices with names like that get none.`}
                  disabled={!form.values.registerDynamicLeases}
                  {...form.getInputProps('rewriteInvalidLeaseNames', { type: 'checkbox' })}
                />
                <Group justify="flex-end">
                  <Button type="submit" disabled={!form.isDirty()}>Save</Button>
                </Group>
              </Stack>
            </form>
          </Card>
        </Grid.Col>
        <Grid.Col span={{ base: 12, lg: 7 }}>
          <Stack gap="md">
            <Card>
              <SectionTitle right={<Button size="xs" variant="light" leftSection={<IconPlus size={14} />} onClick={() => setModal(true)}>Add host name</Button>}>
                Local host names
              </SectionTitle>
              {dns.overrides.length ? (
                <Table.ScrollContainer minWidth={420}>
                  <Table>
                    <Table.Tbody>
                      {dns.overrides.map((o) => (
                        <Table.Tr key={o.id}>
                          <Table.Td>
                            <Mono>{o.host}.{o.domain}</Mono>
                            <Text size="xs" c="dimmed">{o.description}</Text>
                          </Table.Td>
                          <Table.Td><Mono>{o.ip}</Mono></Table.Td>
                          <Table.Td w={40}>
                            <ActionIcon variant="subtle" color="gray" aria-label="Remove" onClick={() => edit('dns', `Removed host name ${o.host}.${o.domain}`, (m) => ({ ...m, dns: { ...m.dns, overrides: m.dns.overrides.filter((x) => x.id !== o.id) } }))}>
                              <IconTrash size={16} />
                            </ActionIcon>
                          </Table.Td>
                        </Table.Tr>
                      ))}
                    </Table.Tbody>
                  </Table>
                </Table.ScrollContainer>
              ) : (
                <Empty>No local host names.</Empty>
              )}
            </Card>
            <DnsBlocklists />
            <LeaseNames />
          </Stack>
        </Grid.Col>
      </Grid>
      <OverrideModal opened={modal} onClose={() => setModal(false)} />
    </>
  );
}
