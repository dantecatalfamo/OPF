// Traffic per device (firewall.traffic): the setting, on Firewall ›
// Settings, and Devices › Traffic, which shows what each device
// sent and received.
import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router';
import { BarChart } from '@mantine/charts';
import { Alert, Anchor, Button, Card, Drawer, Group, Modal, NumberInput, SegmentedControl, Select, SimpleGrid, Stack, Switch, Table, Text, UnstyledButton } from '@mantine/core';
import { useForm } from '@mantine/form';
import { IconAlertTriangle, IconLock } from '@tabler/icons-react';
import { backend, useStore } from '../model/store';
import type { ActivityDeviceInfo, TrafficBytes, TrafficDeviceResource, TrafficResource } from '../lib/api';
import { DEFAULT_TRAFFIC_DEVICES, MAX_ACTIVITY_DAYS, MAX_DEVICE_CAP } from '../model/types';
import { useRole } from '../lib/session';
import { useLive } from '../lib/live';
import { formatBytes } from '../lib/format';
import { DeviceLink } from '../components/DeviceLink';
import { Empty, Mono, PageHeader, SectionTitle } from '../components/ui';

// An hour at most, saved (activity.WorstTraffic): a little for the hour
// and about 140 bytes a device.
const WORST_HOUR_BASE = 256;
const WORST_DEVICE_HOUR = 140;
const errorText = (e: unknown) => (e instanceof Error ? e.message : String(e));
const dayChoices = [1, 7, 14, MAX_ACTIVITY_DAYS];
const dayLabel = (d: number) => (d === 1 ? 'Today only' : d === 7 ? 'A week' : d === 14 ? 'Two weeks' : 'A month');

/** The setting: whether pf counts each device's traffic, and for how long OPF keeps it. */
export function TrafficSettingsCard() {
  const { staged, applied, edit } = useStore();
  const { canEdit } = useRole();
  const { data: sys } = useLive('system');
  const t = staged.firewall.traffic;
  const pick = () => ({ enabled: !!t?.enabled, days: String(t?.days || 7), maxDevices: (t?.maxDevices || DEFAULT_TRAFFIC_DEVICES) as number | string });
  const form = useForm({
    initialValues: pick(),
    validate: { maxDevices: (v) => (Number.isInteger(Number(v)) && Number(v) >= 1 && Number(v) <= MAX_DEVICE_CAP ? null : `1 to ${MAX_DEVICE_CAP.toLocaleString()}`) },
  });
  useEffect(() => {
    form.setValues(pick());
    form.resetDirty();
  }, [t]); // form is stable
  const [forgetting, setForgetting] = useState(false);
  const [error, setError] = useState<string>();
  const v = form.values;
  const keeping = !!applied.firewall.traffic?.enabled;
  const cap = Number(v.maxDevices) || DEFAULT_TRAFFIC_DEVICES;
  const worst = (WORST_HOUR_BASE + WORST_DEVICE_HOUR * cap) * 24 * Number(v.days);
  const ram = sys?.memory?.total;
  return (
    <Card id="traffic">
      <form onSubmit={form.onSubmit((v) => edit('firewall', v.enabled ? `Count each device’s traffic, kept ${dayLabel(Number(v.days)).toLowerCase()}` : 'Stopped counting each device’s traffic', (m) => {
        const firewall = { ...m.firewall };
        const maxDevices = Number(v.maxDevices);
        if (v.enabled) firewall.traffic = { enabled: true, days: Number(v.days), ...(maxDevices !== DEFAULT_TRAFFIC_DEVICES ? { maxDevices } : {}) };
        else delete firewall.traffic;
        return { ...m, firewall };
      }))}>
        <SectionTitle right={<Switch label="Count" disabled={!canEdit} {...form.getInputProps('enabled', { type: 'checkbox' })} />}>Traffic per device</SectionTitle>
        <Stack gap="md">
          <Text size="sm" c="dimmed">
            The firewall counts how much each device on your networks sends and receives, both through the firewall and to it. OPF keeps hourly totals and shows them under{' '}
            <Anchor component={Link} to="/devices/traffic" size="sm">Devices › Traffic</Anchor>. It records only how much, never what or where to.
          </Text>
          <Alert color="gray" variant="light" p="sm" icon={<IconLock size={16} />}>
            <Text size="sm">How much each device sends and receives, and when, can show when people are home and what they do. Only admins can see it, and none of it is sent to webhooks.</Text>
          </Alert>
          <Group align="flex-start" grow>
            <Select label="Keep it for" allowDeselect={false} disabled={!v.enabled || !canEdit}
              data={dayChoices.map((d) => ({ value: String(d), label: dayLabel(d) }))} {...form.getInputProps('days')} />
            <NumberInput
              label="Devices kept apart a day" min={1} max={MAX_DEVICE_CAP} allowDecimal={false} thousandSeparator="," disabled={!v.enabled || !canEdit}
              description={`How many devices get their own totals each day. Any more are counted together. The default is ${DEFAULT_TRAFFIC_DEVICES}.`}
              inputWrapperOrder={['label', 'input', 'description', 'error']}
              {...form.getInputProps('maxDevices')}
            />
          </Group>
          {v.enabled && (
            <Text size="sm">
              At most about <b>{formatBytes(worst)}</b> in memory, and as much on disk, if {cap.toLocaleString()} devices are active every hour.
              {ram && worst / ram > 0.03 ? ` That’s ${(worst / ram * 100).toFixed(1)}% of this machine’s memory.` : ''}
            </Text>
          )}
          {keeping && !v.enabled && (
            <Alert color="yellow" variant="light" p="sm" icon={<IconAlertTriangle size={16} />}>When you apply this, the traffic kept so far is deleted.</Alert>
          )}
          <Group justify="space-between">
            {keeping && canEdit ? <Button variant="subtle" color="red" size="compact-sm" onClick={() => setForgetting(true)}>Delete what’s kept</Button> : <span />}
            <Button type="submit" disabled={!form.isDirty() || !canEdit}>Save</Button>
          </Group>
        </Stack>
      </form>
      <Modal opened={forgetting} onClose={() => setForgetting(false)} title="Delete the traffic kept?" size="md">
        <Stack gap="md">
          <Text size="sm">This deletes the traffic kept so far for every device. Counting continues from now.</Text>
          {error && <Alert color="red" variant="light" p="sm">{error}</Alert>}
          <Group justify="flex-end">
            <Button variant="default" onClick={() => setForgetting(false)}>Cancel</Button>
            <Button color="red" onClick={() => backend.forgetTraffic().then(() => { setForgetting(false); setError(undefined); }, (e) => setError(errorText(e)))}>Delete</Button>
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

export function TrafficHoursChart({ hours, days }: { hours: (TrafficBytes & { start: string })[]; days: number }) {
  if (!hours.length) return null;
  const data = hours.map((h) => {
    const t = new Date(h.start);
    return {
      hour: days > 1 ? t.toLocaleString(undefined, { weekday: 'short', hour: 'numeric' }) : t.toLocaleTimeString(undefined, { hour: 'numeric' }),
      Received: h.received, Sent: h.sent,
    };
  });
  return (
    <BarChart
      h={170} data={data} dataKey="hour" type="stacked" withLegend legendProps={{ verticalAlign: 'top', height: 30 }} gridAxis="y" tickLine="none"
      series={[{ name: 'Received', color: 'harbor.6' }, { name: 'Sent', color: 'amber.6' }]}
      valueFormatter={(n) => formatBytes(n)}
      xAxisProps={{ interval: 'preserveStartEnd', minTickGap: 40 }}
      yAxisProps={{ scale: 'linear', domain: [0, 'auto'], width: 72, tickFormatter: (n: number) => formatBytes(n) }}
      barProps={{ isAnimationActive: false }}
    />
  );
}

const deviceLabel = (key: string, info?: ActivityDeviceInfo) => info?.name || info?.mac || key.replace(/^(ip|mac|vpn):/, '');
const kindWords: Record<ActivityDeviceInfo['kind'], string> = {
  device: 'Device', vpn: 'VPN device', address: 'Address only', other: 'Devices past the daily limit, counted together',
  firewall: 'Traffic the firewall starts itself, such as DNS lookups for your devices, updates, downloads and time',
};

function DeviceDrawer({ device, info, days, onClose, onForgot }: { device?: string; info?: ActivityDeviceInfo; days: number; onClose: () => void; onForgot: () => void }) {
  const [data, setData] = useState<TrafficDeviceResource>();
  const [error, setError] = useState<string>();
  const [confirm, setConfirm] = useState(false);
  useEffect(() => {
    if (!device) return;
    let live = true;
    setData(undefined);
    setError(undefined);
    setConfirm(false);
    backend.trafficDevice(device, days).then((d) => live && setData(d), (e) => live && setError(errorText(e)));
    return () => { live = false; };
  }, [device, days]);
  return (
    <Drawer opened={!!device} onClose={onClose} position="right" size="lg" title={device && <Text fw={600}>{deviceLabel(device, info)}</Text>}>
      {error && <Alert color="red" variant="light">{error}</Alert>}
      {!data && !error && <Text size="sm" c="dimmed">Reading…</Text>}
      {data && (
        <Stack gap="md">
          <Text size="sm" c="dimmed">{kindWords[data.kind]}{data.mac ? <> · <Mono>{data.mac}</Mono></> : ''}</Text>
          <SimpleGrid cols={2}>
            <Stat label="Received" value={formatBytes(data.total.received)} />
            <Stat label="Sent" value={formatBytes(data.total.sent)} />
          </SimpleGrid>
          <TrafficHoursChart hours={data.hours} days={days} />
          <Group justify="flex-end">
            {confirm ? (
              <>
                <Text size="sm">Delete everything kept about this device’s traffic?</Text>
                <Button variant="default" size="compact-sm" onClick={() => setConfirm(false)}>Cancel</Button>
                <Button color="red" size="compact-sm" onClick={() => backend.forgetTraffic(device).then(onForgot, (e) => setError(errorText(e)))}>Delete</Button>
              </>
            ) : (
              <>
                <DeviceLink deviceKey={device!}>Everything about this device</DeviceLink>
                <Button variant="subtle" color="red" size="compact-sm" onClick={() => setConfirm(true)}>Forget this device</Button>
              </>
            )}
          </Group>
        </Stack>
      )}
    </Drawer>
  );
}

/** Devices › Traffic: what each device sent and received over the days chosen. */
export function Traffic() {
  const { applied } = useStore();
  const { isAdmin: canEdit } = useRole();
  const kept = applied.firewall.traffic?.enabled ? applied.firewall.traffic.days : 0;
  const [days, setDays] = useState('1');
  const [data, setData] = useState<TrafficResource>();
  const [error, setError] = useState<string>();
  const [device, setDevice] = useState<string>();
  const n = Math.min(Number(days), kept || 1);
  const load = useCallback(() => backend.traffic(n).then((d) => { setData(d); setError(undefined); }, (e) => setError(errorText(e))), [n]);
  useEffect(() => {
    if (!kept || !canEdit) return;
    load();
    const t = setInterval(load, 30_000);
    return () => clearInterval(t);
  }, [load, kept, canEdit]);

  const header = <PageHeader title="Traffic" description="What each device on your networks sent and received, through the firewall or to it." />;
  if (!canEdit) {
    return <>{header}<Alert color="gray" variant="light" icon={<IconLock size={18} />}>Each device’s traffic can show when people are home and what they do. Only admins can see it.</Alert></>;
  }
  if (!kept) {
    return (
      <>
        {header}
        <Card><Empty>OPF isn’t counting each device’s traffic. You can turn it on under <Anchor component={Link} to="/firewall/settings#traffic" size="sm">Firewall › Settings › Traffic per device</Anchor>.</Empty></Card>
      </>
    );
  }
  const ranges = [{ value: '1', label: 'Today' }, ...[7, 14, MAX_ACTIVITY_DAYS].filter((d) => d <= kept).map((d) => ({ value: String(d), label: d === MAX_ACTIVITY_DAYS ? 'Month' : `${d} days` }))];
  const total = data?.total;
  const most = data?.devices?.[0] ? data.devices[0].sent + data.devices[0].received : 0;
  return (
    <>
      {header}
      <Stack gap="md">
        <Card>
          <SectionTitle right={ranges.length > 1 && <SegmentedControl size="xs" data={ranges} value={days} onChange={setDays} />}>
            {n === 1 ? 'Today' : `The last ${n} days`}
          </SectionTitle>
          <Stack gap="sm">
            {error && <Alert color="red" variant="light" p="sm" icon={<IconAlertTriangle size={16} />}>Couldn’t ask OPF: {error}</Alert>}
            {total && (total.sent + total.received ? (
              <>
                <SimpleGrid cols={{ base: 2, sm: 4 }} spacing="md">
                  <Stat label="Received" value={formatBytes(total.received)} detail="by your devices" />
                  <Stat label="Sent" value={formatBytes(total.sent)} detail="by your devices" />
                  <Stat label="This firewall" value={formatBytes((data?.firewall?.received ?? 0) + (data?.firewall?.sent ?? 0))} detail="traffic it starts itself, sent and received" />
                  <Stat label="Not attributed" value={formatBytes(data?.unknown ?? 0)} detail="from addresses OPF hadn’t seen yet" />
                </SimpleGrid>
                <TrafficHoursChart hours={data?.hours ?? []} days={n} />
              </>
            ) : <Empty>Nothing yet. Counting starts once the change that turned this on is applied, and the totals update every few seconds.</Empty>)}
          </Stack>
        </Card>
        {data?.devices && (
          <Card>
            <SectionTitle>Devices</SectionTitle>
            {data.devices.length ? (
              <Table.ScrollContainer minWidth={560}>
                <Table verticalSpacing={6} highlightOnHover>
                  <Table.Thead>
                    <Table.Tr>
                      <Table.Th>Device</Table.Th>
                      <Table.Th ta="right">Received</Table.Th>
                      <Table.Th ta="right">Sent</Table.Th>
                      <Table.Th w={160} />
                    </Table.Tr>
                  </Table.Thead>
                  <Table.Tbody>
                    {data.devices.map((d) => {
                      const info = data.deviceInfo?.[d.key];
                      const share = most ? (d.sent + d.received) / most : 0;
                      return (
                        <Table.Tr key={d.key} onClick={() => setDevice(d.key)} style={{ cursor: 'pointer' }}>
                          <Table.Td>
                            <UnstyledButton onClick={() => setDevice(d.key)}>
                              <Text size="sm" fw={500}>{deviceLabel(d.key, info)}</Text>
                              <Text size="xs" c="dimmed">{info ? kindWords[info.kind] : ''}</Text>
                            </UnstyledButton>
                          </Table.Td>
                          <Table.Td ta="right" className="num">{formatBytes(d.received)}</Table.Td>
                          <Table.Td ta="right" className="num">{formatBytes(d.sent)}</Table.Td>
                          <Table.Td>
                            <div style={{ height: 6, borderRadius: 3, background: 'var(--mantine-color-default-border)' }}>
                              <div style={{ width: `${Math.max(1, share * 100)}%`, height: 6, borderRadius: 3, background: 'var(--mantine-color-harbor-6)' }} />
                            </div>
                          </Table.Td>
                        </Table.Tr>
                      );
                    })}
                  </Table.Tbody>
                </Table>
              </Table.ScrollContainer>
            ) : <Empty>No device has sent or received anything yet.</Empty>}
          </Card>
        )}
        <Text size="xs" c="dimmed">
          Only traffic that passes through the firewall is counted. Traffic between two devices on the same network never reaches the firewall, because a switch carries it. Totals are kept {dayLabel(kept).toLowerCase()}. You can change this under{' '}
          <Anchor component={Link} to="/firewall/settings#traffic" size="xs">Firewall › Settings › Traffic per device</Anchor>.
        </Text>
        <DeviceDrawer device={device} info={device ? data?.deviceInfo?.[device] : undefined} days={n} onClose={() => setDevice(undefined)} onForgot={() => { setDevice(undefined); load(); }} />
      </Stack>
    </>
  );
}
