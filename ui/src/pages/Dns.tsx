import { useEffect, useState } from 'react';
import { ActionIcon, Button, Card, Grid, Group, Modal, SegmentedControl, Stack, Switch, Table, TagsInput, Text, TextInput } from '@mantine/core';
import { useForm } from '@mantine/form';
import { IconPlus, IconTrash } from '@tabler/icons-react';
import { newId, useStore } from '../model/store';
import type { Dns as DnsSettings } from '../model/types';
import { isIPv4 } from '../lib/ip';
import { Empty, Mono, PageHeader, SectionTitle } from '../components/ui';

type Settings = Omit<DnsSettings, 'overrides'>;

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
  const pick = (d: DnsSettings): Settings => ({ enabled: d.enabled, mode: d.mode, forwarders: d.forwarders, forwardTls: d.forwardTls, dnssec: d.dnssec, registerReservations: d.registerReservations, registerDynamicLeases: d.registerDynamicLeases });
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
              onSubmit={form.onSubmit((v) =>
                edit('dns', v.mode !== dns.mode ? (v.mode === 'forward' ? `DNS now forwards to ${v.forwarders.join(', ')}` : 'DNS now resolves directly (recursive)') : 'Updated DNS resolver settings', (m) => ({ ...m, dns: { ...m.dns, ...v } })),
              )}
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
                <Group justify="flex-end">
                  <Button type="submit" disabled={!form.isDirty()}>Save</Button>
                </Group>
              </Stack>
            </form>
          </Card>
        </Grid.Col>
        <Grid.Col span={{ base: 12, lg: 7 }}>
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
        </Grid.Col>
      </Grid>
      <OverrideModal opened={modal} onClose={() => setModal(false)} />
    </>
  );
}
