// DNS activity: what the resolver answered over days, for the network
// and each device, when the admin has turned it on (dns.activity). The
// setting, on the Settings tab, and the Activity tab that shows it.
import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router';
import { BarChart } from '@mantine/charts';
import {
  Alert, Anchor, Button, Card, Drawer, Grid, Group, Modal, SegmentedControl, Select, SimpleGrid, Stack, Switch, Table, Text, UnstyledButton,
} from '@mantine/core';
import { useForm } from '@mantine/form';
import { IconAlertTriangle, IconLock } from '@tabler/icons-react';
import { backend, useStore } from '../model/store';
import type { ActivityCounts, ActivityDeviceInfo, ActivityHour, ActivityItem, DnsActivityResource, DnsDeviceActivityResource } from '../lib/api';
import { MAX_ACTIVITY_DAYS, type Model } from '../model/types';
import { useRole } from '../lib/session';
import { formatCount, formatLogTime } from '../lib/format';
import { Empty, Mono, SectionTitle } from '../components/ui';

const listName = (m: Model, id?: string) => (!id ? 'your own names' : (m.dns.blocklists ?? []).find((l) => l.id === id)?.name ?? id);
const pct = (n: number, of: number) => (of ? `${((n / of) * 100).toFixed(n / of < 0.1 ? 1 : 0)}%` : '—');
const errorText = (e: unknown) => (e instanceof Error ? e.message : String(e));

interface ActivityValues {
  enabled: boolean;
  devices: boolean;
  days: string;
}

/** The setting: whether to keep DNS activity, per device, and for how long. */
export function DnsActivitySettingsCard() {
  const { staged, applied, edit } = useStore();
  const { canEdit } = useRole();
  const a = staged.dns.activity;
  const pick = (): ActivityValues => ({ enabled: !!a?.enabled, devices: !!a?.devices, days: String(a?.days || 7) });
  const form = useForm<ActivityValues>({ initialValues: pick() });
  useEffect(() => {
    form.setValues(pick());
    form.resetDirty();
  }, [a]); // form is stable
  const [forgetting, setForgetting] = useState(false);
  const [forgetError, setForgetError] = useState<string>();
  const v = form.values;
  const keeping = !!applied.dns.activity?.enabled && applied.dns.enabled;
  const turningOff = keeping && !v.enabled;
  const droppingDevices = keeping && !!applied.dns.activity?.devices && v.enabled && !v.devices;

  const save = form.onSubmit((v) => {
    const next = v.enabled ? { enabled: true, devices: v.devices, days: Number(v.days) } : undefined;
    const summary = !v.enabled
      ? 'Stopped keeping DNS activity'
      : !a?.enabled
        ? `Keep DNS activity for ${v.days} days${v.devices ? ', for each device too' : ''}`
        : `DNS activity: ${v.devices ? 'for each device too' : 'for the network only'}, ${v.days} days`;
    edit('dns', summary, (m) => {
      const dns = { ...m.dns };
      if (next) dns.activity = next;
      else delete dns.activity;
      return { ...m, dns };
    });
  });

  return (
    <Card maw={760}>
      <form onSubmit={save}>
        <SectionTitle right={<Switch label="Keep" disabled={!canEdit} {...form.getInputProps('enabled', { type: 'checkbox' })} />}>Activity</SectionTitle>
        <Stack gap="md">
          <Text size="sm" c="dimmed">
            Keeps how many names were looked up, blocked and not found, by hour, and the names looked up, blocked and not found most each day, shown under Activity.
            OPF counts; it never keeps the queries themselves.
          </Text>
          <Alert color="gray" variant="light" p="sm" icon={<IconLock size={16} />}>
            <Text size="sm">
              The names a network looks up say a lot about the people on it: what they read, who they bank with, what their devices are.
              Only admins can see what’s kept, and nothing of it goes to webhooks. Turn this on where the people using the network know.
            </Text>
          </Alert>
          <Switch
            label="For each device too"
            description="Which device asked, by its MAC address, VPN device or address: each device’s counts and the names it looked up, had blocked and asked for that don’t exist most."
            disabled={!v.enabled || !canEdit}
            {...form.getInputProps('devices', { type: 'checkbox' })}
          />
          <Select
            label="Keep it for" w={200} allowDeselect={false} disabled={!v.enabled || !canEdit}
            data={[{ value: '1', label: 'Today only' }, { value: '7', label: 'A week' }, { value: '14', label: 'Two weeks' }, { value: String(MAX_ACTIVITY_DAYS), label: 'A month' }]}
            {...form.getInputProps('days')}
          />
          {v.enabled && (
            <Text size="xs" c="dimmed">
              While it’s on, the resolver logs every answer to its own file for OPF to count, instead of to the system log; its warnings still reach the system log, through OPF’s.
            </Text>
          )}
          {(turningOff || droppingDevices) && (
            <Alert color="yellow" variant="light" p="sm" icon={<IconAlertTriangle size={16} />}>
              {turningOff ? 'Once applied, everything kept is deleted.' : 'Once applied, every device’s activity is deleted; the network’s stays.'}
            </Alert>
          )}
          <Group justify="space-between">
            {keeping && canEdit ? (
              <Button variant="subtle" color="red" size="compact-sm" onClick={() => setForgetting(true)}>Delete what’s kept</Button>
            ) : <span />}
            <Button type="submit" disabled={!form.isDirty() || !canEdit}>Save</Button>
          </Group>
        </Stack>
      </form>
      <Modal opened={forgetting} onClose={() => setForgetting(false)} title="Delete the DNS activity kept?" size="md">
        <Stack gap="md">
          <Text size="sm">Every count and name kept so far, for the network and every device, is deleted now. Keeping goes on from here.</Text>
          {forgetError && <Alert color="red" variant="light" p="sm">{forgetError}</Alert>}
          <Group justify="flex-end">
            <Button variant="default" onClick={() => setForgetting(false)}>Cancel</Button>
            <Button color="red" onClick={() => backend.forgetDnsActivity().then(() => { setForgetting(false); setForgetError(undefined); }, (e) => setForgetError(errorText(e)))}>Delete</Button>
          </Group>
        </Stack>
      </Modal>
    </Card>
  );
}

function Stat({ label, value, detail }: { label: string; value: string; detail?: string }) {
  return (
    <Stack gap={0}>
      <Text size="xs" c="dimmed" tt="uppercase" fw={600} lts={0.6}>{label}</Text>
      <Text fw={600} size="lg" className="num">{value}</Text>
      {detail && <Text size="xs" c="dimmed">{detail}</Text>}
    </Stack>
  );
}

function CountStats({ total, narrow }: { total: ActivityCounts; narrow?: boolean }) {
  const q = total.queries;
  return (
    <SimpleGrid cols={narrow ? { base: 2, sm: 3 } : { base: 2, sm: 3, lg: 5 }} spacing="md">
      <Stat label="Queries" value={formatCount(q)} />
      <Stat label="Blocked" value={formatCount(total.blocked)} detail={`${pct(total.blocked, q)} of queries`} />
      <Stat label="No such name" value={formatCount(total.nxdomain ?? 0)} detail={`${pct(total.nxdomain ?? 0, q)}; many can mean malware`} />
      <Stat label="Failed" value={formatCount(total.servfail ?? 0)} detail={`${pct(total.servfail ?? 0, q)} the resolver couldn’t answer`} />
      <Stat label="From the cache" value={pct(total.cached ?? 0, q)} detail="answered without asking" />
    </SimpleGrid>
  );
}

function HoursChart({ hours, days }: { hours: ActivityHour[]; days: number }) {
  if (!hours.length) return null;
  const data = hours.map((h) => {
    const t = new Date(h.start);
    return {
      hour: days > 1 ? t.toLocaleString(undefined, { weekday: 'short', hour: 'numeric' }) : t.toLocaleTimeString(undefined, { hour: 'numeric' }),
      Answered: h.queries - h.blocked,
      Blocked: h.blocked,
    };
  });
  return (
    <BarChart
      h={160} data={data} dataKey="hour" type="stacked" withLegend={false} gridAxis="y" tickLine="none"
      series={[{ name: 'Answered', color: 'harbor.6' }, { name: 'Blocked', color: 'red.6' }]}
      xAxisProps={{ interval: 'preserveStartEnd', minTickGap: 40 }}
      yAxisProps={{ scale: 'linear', domain: [0, 'auto'], allowDecimals: false, width: 40 }}
      barProps={{ isAnimationActive: false }}
    />
  );
}

function NameList({ title, items, blocked, model, empty }: { title: string; items: ActivityItem[]; blocked?: boolean; model: Model; empty: string }) {
  const [all, setAll] = useState(false);
  const shown = all ? items : items.slice(0, 10);
  return (
    <Card h="100%">
      <SectionTitle>{title}</SectionTitle>
      {items.length ? (
        <>
          <Table verticalSpacing={5}>
            <Table.Tbody>
              {shown.map((n) => (
                <Table.Tr key={n.name}>
                  <Table.Td>
                    {/* Asked for by devices on the network: text, never markup. */}
                    <Text size="sm" className="mono" style={{ wordBreak: 'break-all' }}>{n.name}</Text>
                    {blocked && <Text size="xs" c="dimmed">by {listName(model, n.list)}{n.entry && n.entry !== n.name ? `, as ${n.entry}` : ''}</Text>}
                  </Table.Td>
                  <Table.Td ta="right" style={{ verticalAlign: 'top', whiteSpace: 'nowrap' }}>
                    <Text size="sm" className="num" title={n.err ? `Up to ${n.err.toLocaleString()} of these may be other names’: the list keeps only the names seen most` : undefined}>
                      {n.err ? '≈' : ''}{n.count.toLocaleString()}
                    </Text>
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
          {items.length > 10 && (
            <Group justify="center" mt="xs">
              <Button size="compact-xs" variant="subtle" color="gray" onClick={() => setAll(!all)}>{all ? 'Show fewer' : `Show ${items.length - 10} more`}</Button>
            </Group>
          )}
        </>
      ) : <Empty>{empty}</Empty>}
    </Card>
  );
}

const deviceLabel = (key: string, info?: ActivityDeviceInfo) => info?.name || info?.mac || key.replace(/^(ip|mac|vpn):/, '');
const kindWords: Record<ActivityDeviceInfo['kind'], string> = { device: 'Device', vpn: 'VPN device', firewall: 'OPF itself', address: 'Address only', other: 'Past the day’s 128 devices' };

function DeviceDrawer({ device, info, days, onClose, onForgot }: { device?: string; info?: ActivityDeviceInfo; days: number; onClose: () => void; onForgot: () => void }) {
  const { applied } = useStore();
  const [data, setData] = useState<DnsDeviceActivityResource>();
  const [error, setError] = useState<string>();
  const [confirm, setConfirm] = useState(false);
  useEffect(() => {
    if (!device) return;
    let live = true;
    setData(undefined);
    setError(undefined);
    backend.dnsDeviceActivity(device, days).then((d) => live && setData(d), (e) => live && setError(errorText(e)));
    return () => { live = false; };
  }, [device, days]);
  return (
    <Drawer opened={!!device} onClose={onClose} position="right" size="lg" title={device && <Text fw={600}>{deviceLabel(device, info)}</Text>}>
      {error && <Alert color="red" variant="light">{error}</Alert>}
      {!data && !error && <Text size="sm" c="dimmed">Reading…</Text>}
      {data && (
        <Stack gap="md">
          <Text size="sm" c="dimmed">
            {kindWords[data.kind]}{data.mac ? <> · <Mono>{data.mac}</Mono></> : ''}{data.address ? <> · last from <Mono>{data.address}</Mono></> : ''} · last asked {formatLogTime(data.last)}
          </Text>
          <CountStats total={data.total} narrow />
          <HoursChart hours={data.hours} days={days} />
          <Grid gutter="md">
            <Grid.Col span={{ base: 12, sm: 6 }}><NameList title="Looked up most" items={data.names} model={applied} empty="Nothing looked up." /></Grid.Col>
            <Grid.Col span={{ base: 12, sm: 6 }}><NameList title="Blocked most" items={data.blocked} blocked model={applied} empty="Nothing blocked." /></Grid.Col>
            {data.missing.length > 0 && (
              <Grid.Col span={12}><NameList title="Not found most" items={data.missing} model={applied} empty="" /></Grid.Col>
            )}
          </Grid>
          <Group justify="flex-end">
            {confirm ? (
              <>
                <Text size="sm">Delete everything kept about this device?</Text>
                <Button variant="default" size="compact-sm" onClick={() => setConfirm(false)}>Cancel</Button>
                <Button color="red" size="compact-sm" onClick={() => backend.forgetDnsActivity(device).then(onForgot, (e) => setError(errorText(e)))}>Delete</Button>
              </>
            ) : (
              <Button variant="subtle" color="red" size="compact-sm" onClick={() => setConfirm(true)}>Forget this device</Button>
            )}
          </Group>
        </Stack>
      )}
    </Drawer>
  );
}

/** The Activity tab: the network's DNS activity over the days chosen, and each device's. */
export function DnsActivityTab() {
  const { applied } = useStore();
  const { canEdit } = useRole();
  const settings = applied.dns.enabled ? applied.dns.activity : undefined;
  const kept = settings?.enabled ? settings.days : 0;
  const [days, setDays] = useState('1');
  const [data, setData] = useState<DnsActivityResource>();
  const [error, setError] = useState<string>();
  const [device, setDevice] = useState<string>();
  const n = Math.min(Number(days), kept || 1);
  const load = useCallback(() => backend.dnsActivity(n).then((d) => { setData(d); setError(undefined); }, (e) => setError(errorText(e))), [n]);
  useEffect(() => {
    if (!kept) return;
    load();
    const t = setInterval(load, 60_000);
    return () => clearInterval(t);
  }, [load, kept]);

  if (!canEdit) {
    return <Alert color="gray" variant="light" icon={<IconLock size={18} />}>DNS activity says what people on the network look up, so only admins can see it.</Alert>;
  }
  if (!kept) {
    return (
      <Card>
        <Empty>
          OPF doesn’t keep a history of lookups. It can, for the network and each device: turn it on under{' '}
          <Anchor component={Link} to="/services/dns?tab=settings" size="sm">Settings › Activity</Anchor>.
        </Empty>
      </Card>
    );
  }
  const ranges = [{ value: '1', label: 'Today' }, ...[7, 14, MAX_ACTIVITY_DAYS].filter((d) => d <= kept).map((d) => ({ value: String(d), label: d === MAX_ACTIVITY_DAYS ? 'Month' : `${d} days` }))];
  const total = data?.total;
  const by = Object.entries(data?.byList ?? {}).sort((a, b) => b[1] - a[1]).map(([id, c]) => `${c.toLocaleString()} by ${listName(applied, id)}`);
  return (
    <Stack gap="md">
      <Card>
        <SectionTitle right={ranges.length > 1 && <SegmentedControl size="xs" data={ranges} value={days} onChange={setDays} />}>
          {n === 1 ? 'Today' : `The last ${n} days`}
        </SectionTitle>
        <Stack gap="sm">
          {error && <Alert color="red" variant="light" p="sm" icon={<IconAlertTriangle size={16} />}>Couldn’t ask OPF: {error}</Alert>}
          {total && (total.queries ? (
            <>
              <CountStats total={total} />
              <HoursChart hours={data?.hours ?? []} days={n} />
              {by.length > 0 && <Text size="xs" c="dimmed">Blocked: {by.join(', ')}{total.allowed ? `. Your never-block names let ${total.allowed.toLocaleString()} through` : ''}.</Text>}
            </>
          ) : <Empty>Nothing yet: the resolver’s answers are counted as they come, every few seconds.</Empty>)}
        </Stack>
      </Card>
      {data?.names && (
        <Grid gutter="md">
          <Grid.Col span={{ base: 12, md: 6, xl: 4 }}><NameList title="Looked up most" items={data.names} model={applied} empty="Nothing looked up yet." /></Grid.Col>
          <Grid.Col span={{ base: 12, md: 6, xl: 4 }}><NameList title="Blocked most" items={data.blocked ?? []} blocked model={applied} empty="Nothing blocked yet." /></Grid.Col>
          {/* Names that don't exist: a device asking for many, often
              random-looking ones, may be infected. */}
          <Grid.Col span={{ base: 12, xl: 4 }}><NameList title="Not found most" items={data.missing ?? []} model={applied} empty="Every name asked for existed." /></Grid.Col>
        </Grid>
      )}
      {data?.perDevice ? (
        <Card>
          <SectionTitle>Devices</SectionTitle>
          {data.devices?.length ? (
            <Table.ScrollContainer minWidth={560}>
              <Table verticalSpacing={6} highlightOnHover>
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>Device</Table.Th>
                    <Table.Th ta="right">Queries</Table.Th>
                    <Table.Th ta="right">Blocked</Table.Th>
                    <Table.Th ta="right">No such name</Table.Th>
                    <Table.Th ta="right">Failed</Table.Th>
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {data.devices.map((d) => {
                    const info = data.deviceInfo?.[d.key];
                    return (
                      <Table.Tr key={d.key} onClick={() => setDevice(d.key)} style={{ cursor: 'pointer' }}>
                        <Table.Td>
                          <UnstyledButton onClick={() => setDevice(d.key)}>
                            <Text size="sm" fw={500}>{deviceLabel(d.key, info)}</Text>
                            <Text size="xs" c="dimmed">
                              {info ? kindWords[info.kind] : ''}{d.address ? <> · <Mono>{d.address}</Mono></> : ''}
                            </Text>
                          </UnstyledButton>
                        </Table.Td>
                        <Table.Td ta="right" className="num">{d.queries.toLocaleString()}</Table.Td>
                        <Table.Td ta="right" className="num">{d.blocked.toLocaleString()}</Table.Td>
                        {/* A device most of whose lookups fail stands out. */}
                        <Table.Td ta="right" className="num" c={(d.nxdomain ?? 0) > d.queries / 4 && d.queries > 50 ? 'yellow' : undefined}>{(d.nxdomain ?? 0).toLocaleString()}</Table.Td>
                        <Table.Td ta="right" className="num">{(d.servfail ?? 0).toLocaleString()}</Table.Td>
                      </Table.Tr>
                    );
                  })}
                </Table.Tbody>
              </Table>
            </Table.ScrollContainer>
          ) : <Empty>No device has asked anything yet.</Empty>}
        </Card>
      ) : data?.enabled && (
        <Text size="xs" c="dimmed">
          Only the network’s activity is kept. Each device’s can be too, under <Anchor component={Link} to="/services/dns?tab=settings" size="xs">Settings › Activity</Anchor>.
        </Text>
      )}
      <DeviceDrawer device={device} info={device ? data?.deviceInfo?.[device] : undefined} days={n} onClose={() => setDevice(undefined)} onForgot={() => { setDevice(undefined); load(); }} />
    </Stack>
  );
}
