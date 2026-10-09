// System › General: ntpd, which keeps the firewall's clock (and, when
// asked, other devices' clocks) right: /etc/ntpd.conf, ntpd.conf(5).
import { useEffect, type ReactNode } from 'react';
import { Link } from 'react-router';
import { Accordion, ActionIcon, Alert, Anchor, Badge, Button, Card, Checkbox, Fieldset, Group, MultiSelect, NumberInput, Select, Stack, Table, TagsInput, Text, TextInput, Tooltip } from '@mantine/core';
import { useForm } from '@mantine/form';
import { IconAlertTriangle, IconPlus, IconTrash } from '@tabler/icons-react';
import { useStore } from '../model/store';
import { useRole } from '../lib/session';
import { useLive } from '../lib/live';
import { servable } from '../lib/labels';
import type { NtpConstraint, NtpListen, NtpSensor, NtpServer, NtpSettings, SystemSettings } from '../model/types';
import { SectionTitle } from '../components/ui';
import { FileLink } from './ConfigFiles';
import { HandConfigured, handConfigured } from '../components/HandConfigured';

interface Values {
  ntpServers: string[];
  servers: NtpServer[];
  sensors: NtpSensor[];
  constraints: NtpConstraint[];
  serveOn: string[];
  listen: NtpListen[];
  query4: string;
  query6: string;
}

const isV4 = (s: string) => /^\d{1,3}(\.\d{1,3}){3}$/.test(s) && s.split('.').every((o) => Number(o) <= 255);
const isV6 = (s: string) => /^[0-9a-f:.]+$/i.test(s) && s.includes(':');
const isIP = (s: string) => isV4(s) || isV6(s);
const isHost = (s: string) => isIP(s) || /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/i.test(s);

// Rows as the form holds them: every field there, so no input starts
// uncontrolled.
const blank = {
  server: (s?: NtpServer): NtpServer => ({ address: '', one: false, trusted: false, weight: undefined, ...s }),
  sensor: (s?: NtpSensor): NtpSensor => ({ device: '', correction: undefined, refid: '', stratum: undefined, trusted: false, weight: undefined, ...s }),
  constraint: (c?: NtpConstraint): NtpConstraint => ({ url: '', every: false, addresses: [], ...c }),
  listen: (l?: NtpListen): NtpListen => ({ address: '', rtable: undefined, ...l }),
};

function pick(s: SystemSettings): Values {
  const n = s.ntp ?? {};
  const q = n.queryFrom ?? [];
  return {
    ntpServers: s.ntpServers,
    servers: (n.servers ?? []).map(blank.server),
    sensors: (n.sensors ?? []).map(blank.sensor),
    constraints: (n.constraints ?? []).map(blank.constraint),
    serveOn: n.serveOn ?? [],
    listen: (n.listen ?? []).map(blank.listen),
    query4: q.find(isV4) ?? '',
    query6: q.find((a) => !isV4(a)) ?? '',
  };
}

// What's saved: unset numbers and false flags left out, as the server
// writes them, so an unchanged form compares equal.
function settings(v: Values): NtpSettings | undefined {
  const num = (n: number | string | undefined) => (typeof n === 'number' && n !== 0 ? n : undefined);
  const clean = <T extends object>(o: T): T => Object.fromEntries(Object.entries(o).filter(([, x]) => x !== undefined && x !== false && x !== '' && !(Array.isArray(x) && !x.length))) as T;
  const n: NtpSettings = clean({
    servers: v.servers.map((s) => clean({ address: s.address.trim(), one: s.one, trusted: s.trusted, weight: num(s.weight) })),
    sensors: v.sensors.map((s) => clean({ device: s.device.trim(), correction: num(s.correction), refid: s.refid?.trim(), stratum: num(s.stratum), trusted: s.trusted, weight: num(s.weight) })),
    constraints: v.constraints.map((c) => clean({ url: c.url.trim(), every: c.every, addresses: c.every ? undefined : c.addresses })),
    serveOn: v.serveOn,
    listen: v.listen.map((l) => clean({ address: l.address.trim(), rtable: num(l.rtable) })),
    queryFrom: [v.query4.trim(), v.query6.trim()].filter(Boolean),
  });
  return Object.keys(n).length ? n : undefined;
}

/** A group of rows in the accordion, with its count. */
function Part({ value, title, count, children }: { value: string; title: string; count: number; children: ReactNode }) {
  return (
    <Accordion.Item value={value}>
      <Accordion.Control>
        <Group gap="xs"><Text size="sm" fw={500}>{title}</Text>{count > 0 && <Badge size="sm" variant="light">{count}</Badge>}</Group>
      </Accordion.Control>
      <Accordion.Panel><Stack gap="sm">{children}</Stack></Accordion.Panel>
    </Accordion.Item>
  );
}

function Remove({ onClick, what }: { onClick: () => void; what: string }) {
  return (
    <Tooltip label={`Remove this ${what}`}>
      <ActionIcon variant="subtle" color="gray" aria-label={`Remove this ${what}`} onClick={onClick}><IconTrash size={16} /></ActionIcon>
    </Tooltip>
  );
}

function Add({ onClick, children }: { onClick: () => void; children: ReactNode }) {
  return <Group><Button size="xs" variant="light" leftSection={<IconPlus size={14} />} onClick={onClick}>{children}</Button></Group>;
}

export function TimeSettings() {
  const { staged, edit } = useStore();
  const { canEdit } = useRole();
  const { data: live } = useLive('system');
  const sys = staged.system;
  const insides = staged.interfaces.filter((i) => i.role !== 'wan' && !i.wireguard?.exit);
  const hand = handConfigured(staged, 'ntp');
  const form = useForm<Values>({
    initialValues: pick(sys),
    validate: {
      ntpServers: (v, vals) => {
        if (!v.length && !vals.servers.length && !vals.sensors.length) return 'Add at least one time server';
        const bad = v.find((s) => !isHost(s));
        return bad ? `${bad} isn’t a host name or IP address` : null;
      },
      servers: { address: (v) => (isHost(v.trim()) ? null : 'A host name or IP address') },
      sensors: {
        device: (v) => (/^(\*|[a-z]{1,12}[0-9]{1,3})$/.test(v.trim()) ? null : 'A device such as nmea0, or *'),
        refid: (v) => (!v || /^[A-Za-z0-9]{1,4}$/.test(v.trim()) ? null : '1 to 4 letters or digits'),
      },
      constraints: {
        url: (v) => (/^(https:\/\/)?[^\s"'\\]+$/.test(v.trim()) ? null : 'A URL like https://www.example.com/, or a host name or address'),
        addresses: (v) => (v?.find((a) => !isIP(a)) ? 'IP addresses only' : null),
      },
      listen: { address: (v) => (v.trim() === '*' || isIP(v.trim()) ? null : 'An IP address, or *') },
      query4: (v) => (!v.trim() || isV4(v.trim()) ? null : 'An IPv4 address'),
      query6: (v) => (!v.trim() || isV6(v.trim()) ? null : 'An IPv6 address'),
    },
  });
  useEffect(() => {
    form.setValues(pick(sys));
    form.resetDirty();
  }, [sys.ntpServers, sys.ntp]); // form is stable

  const v = form.values;
  const save = form.onSubmit((v) => {
    const ntp = settings(v);
    // What changed, each part by what it holds now.
    const was = sys.ntp ?? {};
    const now = ntp ?? {};
    const parts: string[] = [];
    const part = (what: string, before: unknown, after: unknown, list: string[]) => {
      if (JSON.stringify(before ?? []) !== JSON.stringify(after ?? [])) parts.push(`${what} ${list.join(', ') || 'none'}`);
    };
    part('servers', sys.ntpServers, v.ntpServers, v.ntpServers);
    part('servers with options', was.servers, now.servers, (now.servers ?? []).map((s) => s.address));
    part('sensors', was.sensors, now.sensors, (now.sensors ?? []).map((s) => s.device));
    part('constraints', was.constraints, now.constraints, (now.constraints ?? []).map((c) => c.url));
    part('served to', was.serveOn, now.serveOn, (now.serveOn ?? []).map((id) => staged.interfaces.find((i) => i.id === id)?.name ?? id));
    part('also served on', was.listen, now.listen, (now.listen ?? []).map((l) => l.address));
    part('asked from', was.queryFrom, now.queryFrom, now.queryFrom ?? []);
    edit('system', parts.length ? `Time: ${parts.join('; ')}` : 'Updated the time settings', (m) => {
      const system = { ...m.system, ntpServers: v.ntpServers };
      if (ntp) system.ntp = ntp;
      else delete system.ntp;
      return { ...m, system };
    });
  });

  const trusted = v.servers.some((s) => s.trusted) || v.sensors.some((s) => s.trusted);

  return (
    <Card id="time">
      <form onSubmit={save}>
        <SectionTitle>Time</SectionTitle>
        <HandConfigured area="ntp" compact />
        {live && (
          <Text size="sm" mb="sm" c={live.time?.synced ? undefined : 'dimmed'}>
            {!live.time ? 'ntpd isn’t running.'
              : live.time.synced ? `The clock is synced${live.time.source ? ` to ${live.time.source}` : ''}${live.time.offsetMs !== undefined ? `, ${Math.abs(live.time.offsetMs) < 10 ? (Math.round(live.time.offsetMs * 10) / 10 || 0).toFixed(1) : Math.round(live.time.offsetMs)} ms off` : ''}.`
                : 'ntpd hasn’t synced the clock yet.'}
          </Text>
        )}
        <Fieldset variant="unstyled" disabled={hand || !canEdit}>
          <Stack gap="md">
            <TagsInput
              label="Time servers"
              description="ntpd syncs to every address each name has, such as a pool’s"
              placeholder="pool.ntp.org"
              {...form.getInputProps('ntpServers')}
            />
            <Accordion variant="contained" radius="md" multiple>
              <Part value="servers" title="Servers with options" count={v.servers.length}>
                <Text size="xs" c="dimmed">
                  A server with a weight counts for more against the others (1 to 10; unset is 1). A trusted server’s time skips the constraints: for setting the clock at boot where no constraint can be reached.
                </Text>
                {v.servers.length > 0 && (
                  <Table verticalSpacing={4}>
                    <Table.Thead><Table.Tr><Table.Th>Server</Table.Th><Table.Th>Addresses</Table.Th><Table.Th>Weight</Table.Th><Table.Th>Trusted</Table.Th><Table.Th /></Table.Tr></Table.Thead>
                    <Table.Tbody>
                      {v.servers.map((_, i) => (
                        <Table.Tr key={i}>
                          <Table.Td><TextInput size="xs" miw={140} placeholder="ntp.example.org" aria-label="Server" {...form.getInputProps(`servers.${i}.address`)} /></Table.Td>
                          <Table.Td>
                            <Select size="xs" w={130} allowDeselect={false} aria-label="Addresses" data={[{ value: 'every', label: 'Every one' }, { value: 'one', label: 'First to answer' }]}
                              value={v.servers[i].one ? 'one' : 'every'} onChange={(x) => form.setFieldValue(`servers.${i}.one`, x === 'one')} />
                          </Table.Td>
                          <Table.Td><NumberInput size="xs" w={64} min={1} max={10} placeholder="1" aria-label="Weight" {...form.getInputProps(`servers.${i}.weight`)} /></Table.Td>
                          <Table.Td><Checkbox aria-label="Trusted" {...form.getInputProps(`servers.${i}.trusted`, { type: 'checkbox' })} /></Table.Td>
                          <Table.Td><Remove what="server" onClick={() => form.removeListItem('servers', i)} /></Table.Td>
                        </Table.Tr>
                      ))}
                    </Table.Tbody>
                  </Table>
                )}
                <Add onClick={() => form.insertListItem('servers', blank.server())}>Add a server</Add>
              </Part>

              <Part value="sensors" title="Sensors" count={v.sensors.length}>
                <Text size="xs" c="dimmed">
                  A timedelta sensor, such as a GPS (nmea0) or radio clock (udcf0), or * for every one the kernel finds; one that isn’t there is ignored. The correction, in microseconds, makes up for a receiver that lags; the reference ID (such as GPS) and stratum are what clients are told.
                </Text>
                {v.sensors.map((_, i) => (
                  <Stack key={i} gap={6} pb="xs" style={{ borderBottom: '1px solid var(--mantine-color-default-border)' }}>
                    <Group gap="xs" align="flex-start" wrap="wrap">
                      <TextInput size="xs" w={90} label="Device" placeholder="nmea0" {...form.getInputProps(`sensors.${i}.device`)} />
                      <NumberInput size="xs" w={130} label="Correction (µs)" min={-127000000} max={127000000} placeholder="0" {...form.getInputProps(`sensors.${i}.correction`)} />
                      <TextInput size="xs" w={80} label="Reference" placeholder="GPS" {...form.getInputProps(`sensors.${i}.refid`)} />
                      <NumberInput size="xs" w={70} label="Stratum" min={1} max={15} placeholder="1" {...form.getInputProps(`sensors.${i}.stratum`)} />
                      <NumberInput size="xs" w={70} label="Weight" min={1} max={10} placeholder="1" {...form.getInputProps(`sensors.${i}.weight`)} />
                    </Group>
                    <Group justify="space-between">
                      <Checkbox size="xs" label="Trusted" {...form.getInputProps(`sensors.${i}.trusted`, { type: 'checkbox' })} />
                      <Remove what="sensor" onClick={() => form.removeListItem('sensors', i)} />
                    </Group>
                  </Stack>
                ))}
                <Add onClick={() => form.insertListItem('sensors', blank.sensor())}>Add a sensor</Add>
              </Part>

              <Part value="constraints" title="Constraints" count={v.constraints.length}>
                <Text size="xs" c="dimmed">
                  ntpd asks these HTTPS servers for the date, over TLS, and ignores a time server whose answer is far from it, so a forged NTP reply can’t move the clock far. Without any, it believes the time servers.
                </Text>
                {v.constraints.map((c, i) => (
                  <Group key={i} gap="xs" align="flex-start" wrap="wrap">
                    <TextInput size="xs" style={{ flex: 1, minWidth: 200 }} label="URL" placeholder="https://www.example.com/" {...form.getInputProps(`constraints.${i}.url`)} />
                    <Select size="xs" w={150} label="Asks" allowDeselect={false} data={[{ value: 'one', label: 'First to answer' }, { value: 'every', label: 'Every address' }]}
                      value={c.every ? 'every' : 'one'} onChange={(x) => form.setFieldValue(`constraints.${i}.every`, x === 'every')} />
                    {!c.every && (
                      <TagsInput size="xs" w={200} label="Or these addresses" placeholder="9.9.9.9" {...form.getInputProps(`constraints.${i}.addresses`)} />
                    )}
                    <Group mt={22}><Remove what="constraint" onClick={() => form.removeListItem('constraints', i)} /></Group>
                  </Group>
                ))}
                <Add onClick={() => form.insertListItem('constraints', blank.constraint())}>Add a constraint</Add>
                {trusted && v.constraints.length > 0 && (
                  <Text size="xs" c="dimmed">The trusted servers and sensors skip these.</Text>
                )}
              </Part>

              <Part value="serve" title="Serving time" count={v.serveOn.length + v.listen.length}>
                <MultiSelect
                  label="Serve time to"
                  placeholder={v.serveOn.length ? undefined : 'No network'}
                  description="ntpd answers on each network’s address, the firewall lets that network’s devices ask it, and the DHCP server tells them to use it. A rule of yours that blocks those devices still blocks them. Until ntpd has synced, its answers say so, and devices don’t take the time from it."
                  inputWrapperOrder={['label', 'input', 'description', 'error']}
                  data={insides.map((i) => ({
                    value: i.id, disabled: !servable(i),
                    label: servable(i) ? i.name : `${i.name} (${!i.enabled ? 'off' : 'gets its address by DHCP'})`,
                  }))}
                  {...form.getInputProps('serveOn')}
                />
                <Text size="sm" fw={500} mt="xs">Other addresses</Text>
                <Text size="xs" c="dimmed">
                  More addresses ntpd answers on, or * for every one. For these, a <Anchor component={Link} to="/firewall/rules" size="xs">firewall rule</Anchor> has to pass UDP port 123 to it.
                </Text>
                {v.listen.map((_, i) => (
                  <Group key={i} gap="xs" align="flex-start">
                    <TextInput size="xs" w={200} label="Address" placeholder="192.168.1.1" {...form.getInputProps(`listen.${i}.address`)} />
                    <NumberInput size="xs" w={110} label="Routing table" min={0} max={255} placeholder="0" {...form.getInputProps(`listen.${i}.rtable`)} />
                    <Group mt={22}><Remove what="address" onClick={() => form.removeListItem('listen', i)} /></Group>
                  </Group>
                ))}
                <Add onClick={() => form.insertListItem('listen', blank.listen())}>Add an address</Add>
                {v.listen.some((l) => l.address.trim() === '*') && (
                  <Alert color="yellow" variant="light" p="sm" icon={<IconAlertTriangle size={16} />}>
                    <Text size="sm">On every address, the WAN’s too: only your firewall rules keep the internet from asking it.</Text>
                  </Alert>
                )}
              </Part>

              <Part value="source" title="Source address" count={(v.query4 ? 1 : 0) + (v.query6 ? 1 : 0)}>
                <Text size="xs" c="dimmed">
                  The address ntpd asks the time servers from, for a firewall with more than one way out; empty, the outgoing interface’s.
                </Text>
                <Group grow align="flex-start">
                  <TextInput size="xs" label="IPv4" placeholder="192.0.2.1" {...form.getInputProps('query4')} />
                  <TextInput size="xs" label="IPv6" placeholder="2001:db8::1" {...form.getInputProps('query6')} />
                </Group>
              </Part>
            </Accordion>
          </Stack>
        </Fieldset>
        <Group justify="space-between" mt="md">
          <FileLink path="/etc/ntpd.conf" />
          <Button type="submit" disabled={!form.isDirty() || hand || !canEdit}>Save</Button>
        </Group>
      </form>
    </Card>
  );
}
