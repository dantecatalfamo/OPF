// Traffic per device (firewall.traffic): the setting, on Firewall ›
// Settings, and Diagnostics › Traffic, which shows what each device
// sent and received.
import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router';
import { BarChart } from '@mantine/charts';
import { Alert, Anchor, Button, Card, Drawer, Group, Modal, SegmentedControl, Select, SimpleGrid, Stack, Switch, Table, Text, UnstyledButton } from '@mantine/core';
import { useForm } from '@mantine/form';
import { IconAlertTriangle, IconLock } from '@tabler/icons-react';
import { backend, useStore } from '../model/store';
import type { ActivityDeviceInfo, TrafficBytes, TrafficDeviceResource, TrafficResource } from '../lib/api';
import { MAX_ACTIVITY_DAYS } from '../model/types';
import { useRole } from '../lib/session';
import { useLive } from '../lib/live';
import { formatBytes } from '../lib/format';
import { Empty, Mono, PageHeader, SectionTitle } from '../components/ui';

// An hour at most, saved, with 128 devices (activity.WorstTrafficHour).
const WORST_HOUR = 18 * 1024;
const errorText = (e: unknown) => (e instanceof Error ? e.message : String(e));
const dayChoices = [1, 7, 14, MAX_ACTIVITY_DAYS];
const dayLabel = (d: number) => (d === 1 ? 'Today only' : d === 7 ? 'A week' : d === 14 ? 'Two weeks' : 'A month');

/** The setting: whether pf counts each device's traffic, and for how long OPF keeps it. */
export function TrafficSettingsCard() {
  const { staged, applied, edit } = useStore();
  const { canEdit } = useRole();
  const { data: sys } = useLive('system');
  const t = staged.firewall.traffic;
  const pick = () => ({ enabled: !!t?.enabled, days: String(t?.days || 7) });
  const form = useForm({ initialValues: pick() });
  useEffect(() => {
    form.setValues(pick());
    form.resetDirty();
  }, [t]); // form is stable
  const [forgetting, setForgetting] = useState(false);
  const [error, setError] = useState<string>();
  const v = form.values;
  const keeping = !!applied.firewall.traffic?.enabled;
  const worst = WORST_HOUR * 24 * Number(v.days);
  const ram = sys?.memory?.total;
  return (
    <Card id="traffic">
      <form onSubmit={form.onSubmit((v) => edit('firewall', v.enabled ? `Count each device’s traffic, kept ${dayLabel(Number(v.days)).toLowerCase()}` : 'Stopped counting each device’s traffic', (m) => {
        const firewall = { ...m.firewall };
        if (v.enabled) firewall.traffic = { enabled: true, days: Number(v.days) };
        else delete firewall.traffic;
        return { ...m, firewall };
      }))}>
        <SectionTitle right={<Switch label="Count" disabled={!canEdit} {...form.getInputProps('enabled', { type: 'checkbox' })} />}>Traffic per device</SectionTitle>
        <Stack gap="md">
          <Text size="sm" c="dimmed">
            pf counts every packet each device on your networks sends and receives, through the firewall or to it, and OPF keeps the totals by hour, shown under{' '}
            <Anchor component={Link} to="/diagnostics/traffic" size="sm">Diagnostics › Traffic</Anchor>. Only how much, never what or where to.
          </Text>
          <Alert color="gray" variant="light" p="sm" icon={<IconLock size={16} />}>
            <Text size="sm">How much each device moves, and when, says when people are home and what they do. Only admins can see it, and nothing of it goes to webhooks.</Text>
          </Alert>
          <Select label="Keep it for" w={220} allowDeselect={false} disabled={!v.enabled || !canEdit}
            data={dayChoices.map((d) => ({ value: String(d), label: dayLabel(d) }))} {...form.getInputProps('days')} />
          {v.enabled && (
            <Text size="sm">
              At most about <b>{formatBytes(worst)}</b> in memory, and as much on disk, with 128 devices every hour.
              {ram && worst / ram > 0.03 ? ` That’s ${(worst / ram * 100).toFixed(1)}% of this machine’s memory.` : ''}
            </Text>
          )}
          {keeping && !v.enabled && (
            <Alert color="yellow" variant="light" p="sm" icon={<IconAlertTriangle size={16} />}>Once applied, the traffic kept is deleted.</Alert>
          )}
          <Group justify="space-between">
            {keeping && canEdit ? <Button variant="subtle" color="red" size="compact-sm" onClick={() => setForgetting(true)}>Delete what’s kept</Button> : <span />}
            <Button type="submit" disabled={!form.isDirty() || !canEdit}>Save</Button>
          </Group>
        </Stack>
      </form>
      <Modal opened={forgetting} onClose={() => setForgetting(false)} title="Delete the traffic kept?" size="md">
        <Stack gap="md">
          <Text size="sm">Every device’s traffic kept so far is deleted now. Counting goes on from here.</Text>
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

function HoursChart({ hours, days }: { hours: (TrafficBytes & { start: string })[]; days: number }) {
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
const kindWords: Record<ActivityDeviceInfo['kind'], string> = { device: 'Device', vpn: 'VPN device', firewall: 'OPF itself', address: 'Address only', other: 'Past the day’s 128 devices' };

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
          <HoursChart hours={data.hours} days={days} />
          <Group justify="flex-end">
            {confirm ? (
              <>
                <Text size="sm">Delete everything kept about this device’s traffic?</Text>
                <Button variant="default" size="compact-sm" onClick={() => setConfirm(false)}>Cancel</Button>
                <Button color="red" size="compact-sm" onClick={() => backend.forgetTraffic(device).then(onForgot, (e) => setError(errorText(e)))}>Delete</Button>
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

/** Diagnostics › Traffic: what each device sent and received over the days chosen. */
export function Traffic() {
  const { applied } = useStore();
  const { canEdit } = useRole();
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
    return <>{header}<Alert color="gray" variant="light" icon={<IconLock size={18} />}>Each device’s traffic says when people are home and what they do, so only admins can see it.</Alert></>;
  }
  if (!kept) {
    return (
      <>
        {header}
        <Card><Empty>OPF doesn’t count each device’s traffic. It can: turn it on under <Anchor component={Link} to="/firewall/settings#traffic" size="sm">Firewall › Settings › Traffic per device</Anchor>.</Empty></Card>
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
                <SimpleGrid cols={{ base: 2, sm: 3 }} spacing="md">
                  <Stat label="Received" value={formatBytes(total.received)} detail="by your devices" />
                  <Stat label="Sent" value={formatBytes(total.sent)} detail="by your devices" />
                  <Stat label="Not attributed" value={formatBytes(data?.unknown ?? 0)} detail="from addresses OPF hadn’t seen yet" />
                </SimpleGrid>
                <HoursChart hours={data?.hours ?? []} days={n} />
              </>
            ) : <Empty>Nothing yet: pf’s counters are read every few seconds, once the change that turned this on is applied.</Empty>)}
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
            ) : <Empty>No device has moved anything yet.</Empty>}
          </Card>
        )}
        <Text size="xs" c="dimmed">
          Counted by pf as packets pass the firewall: traffic between two devices on the same network, through a switch, never reaches it. Kept {dayLabel(kept).toLowerCase()}; set under{' '}
          <Anchor component={Link} to="/firewall/settings#traffic" size="xs">Firewall › Settings › Traffic per device</Anchor>.
        </Text>
        <DeviceDrawer device={device} info={device ? data?.deviceInfo?.[device] : undefined} days={n} onClose={() => setDevice(undefined)} onForgot={() => { setDevice(undefined); load(); }} />
      </Stack>
    </>
  );
}
