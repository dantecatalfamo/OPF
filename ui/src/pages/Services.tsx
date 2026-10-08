// Services › All services: every service the base system has (rcctl),
// what it is, whether it starts at boot and whether it's running now.
// Starting, stopping and restarting are done at once (operators); boot
// settings are changes like any other, reviewed and applied (admins),
// and written into rc.conf.local by OPF.
import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router';
import {
  ActionIcon, Alert, Anchor, Badge, Button, Card, Code, Drawer, Group, Menu, Modal, NumberInput, SegmentedControl, Stack, Switch, Table, Text, TextInput, Tooltip,
} from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { IconAlertTriangle, IconDots, IconPlayerPlay, IconPlayerStop, IconRefresh, IconRotateClockwise, IconSearch, IconSettings } from '@tabler/icons-react';
import { backend, useStore } from '../model/store';
import type { ServiceSetting } from '../model/types';
import type { LogLine, ServiceDetailResource, ServicesResource, ServiceStatus } from '../lib/api';
import { useRole } from '../lib/session';
import { Empty, Mono, PageHeader, SectionTitle } from '../components/ui';

const POLL_MS = 30_000; // rcctl takes seconds to say
const categories = ['Network', 'Firewall and VPN', 'Routing', 'Name and time', 'Web and mail', 'Monitoring and logging', 'System', 'File sharing', 'Rarely needed', 'Packages and others'];
const flagsRE = /^[A-Za-z0-9 ._,:/=@%+-]*$/;
type Action = 'start' | 'stop' | 'restart' | 'reload';
const errorText = (e: unknown) => (e instanceof Error ? e.message : String(e));

// What may be done to a service now, as the server allows it.
function actionsFor(s: ServiceStatus): Action[] {
  if (s.kind === 'boot' || s.name === 'opf') return [];
  if (s.managedAt) return s.running ? ['restart', 'reload'] : [];
  return s.running ? ['restart', 'reload', 'stop'] : ['start'];
}
const actionLabel: Record<Action, string> = { start: 'Start', stop: 'Stop', restart: 'Restart', reload: 'Reload its configuration' };
const actionIcon: Record<Action, typeof IconPlayerPlay> = { start: IconPlayerPlay, stop: IconPlayerStop, restart: IconRotateClockwise, reload: IconRefresh };
const pastTense: Record<Action, string> = { start: 'Started', stop: 'Stopped', restart: 'Restarted', reload: 'Reloaded' };

function State({ s }: { s: ServiceStatus }) {
  if (s.kind === 'boot') return <Badge color={s.enabled ? 'teal' : 'gray'} variant="light">{s.enabled ? 'On at boot' : 'Off'}</Badge>;
  if (s.failed) return <Tooltip label="It starts at boot, but isn’t running"><Badge color="red" variant="light">Not running</Badge></Tooltip>;
  if (s.running) return <Badge color="teal" variant="light">Running</Badge>;
  return <Badge color="gray" variant="light">Stopped</Badge>;
}

function Boot({ s }: { s: ServiceStatus }) {
  return (
    <Group gap={6} wrap="nowrap">
      <Text size="sm" c={s.enabled ? undefined : 'dimmed'}>{s.enabled ? 'Yes' : 'No'}</Text>
      {s.setting && <Tooltip label="OPF’s setting, in rc.conf.local"><Badge size="xs" variant="outline" color="gray">set here</Badge></Tooltip>}
      {s.kind === 'daemon' && s.running && !s.enabled && <Tooltip label="Running now, but won’t start at the next boot"><IconAlertTriangle size={14} color="var(--mantine-color-yellow-6)" /></Tooltip>}
    </Group>
  );
}

function BootModal({ s, onClose }: { s?: ServiceStatus; onClose: () => void }) {
  const { staged, edit } = useStore();
  const current = s ? staged.system.services?.find((x) => x.name === s.name) : undefined;
  const [v, setV] = useState<ServiceSetting>({ name: '', enabled: false });
  const [flags, setFlags] = useState('');
  useEffect(() => {
    if (!s) return;
    setV(current ?? { name: s.name, enabled: s.enabled });
    setFlags(current?.flags ?? '');
  }, [s?.name]); // eslint-disable-line react-hooks/exhaustive-deps
  if (!s) return null;
  const daemon = s.kind === 'daemon';
  const flagsError = !flagsRE.test(flags) ? 'Letters, digits, spaces and . _ , : / = @ % + - only' : flags.length > 256 ? 'At most 256 characters' : null;
  const set = (summary: string, next?: ServiceSetting) =>
    edit('system', summary, (m) => {
      const rest = (m.system.services ?? []).filter((x) => x.name !== s.name);
      const services = next ? [...rest, next] : rest;
      return { ...m, system: { ...m.system, services: services.length ? services : undefined } };
    });
  const save = () => {
    const next: ServiceSetting = { name: s.name, enabled: v.enabled };
    if (daemon && v.enabled && flags.trim()) next.flags = flags.trim();
    if (daemon && v.rtable !== undefined) next.rtable = v.rtable;
    if (daemon && v.timeout !== undefined) next.timeout = v.timeout;
    set(`${s.name}: ${v.enabled ? 'starts at boot' : 'doesn’t start at boot'}${next.flags ? ` with ${next.flags}` : ''}`, next);
    onClose();
  };
  return (
    <Modal opened onClose={onClose} title={<Text fw={600}>{s.name} at boot</Text>}>
      <Stack>
        <Text size="sm" c="dimmed">{s.description}</Text>
        <Switch label={daemon ? 'Start it at boot' : 'On at boot'} checked={v.enabled} onChange={(e) => setV({ ...v, enabled: e.currentTarget.checked })} />
        {s.name === 'sshd' && !v.enabled && (
          <Alert color="yellow" variant="light" icon={<IconAlertTriangle size={16} />}>
            After the next restart there’ll be no SSH: no remote shell and no sign-in access. This interface stays.
          </Alert>
        )}
        {daemon && (
          <>
            <TextInput
              label="Flags"
              description="Empty: rc.d’s defaults."
              placeholder="Its defaults"
              disabled={!v.enabled}
              value={flags}
              onChange={(e) => setFlags(e.currentTarget.value)}
              error={flagsError}
              styles={{ input: { fontFamily: 'var(--mantine-font-family-monospace)' } }}
            />
            <Group grow>
              <NumberInput label="Routing table" description="Empty: 0" min={0} max={255} allowDecimal={false} value={v.rtable ?? ''} onChange={(n) => setV({ ...v, rtable: typeof n === 'number' ? n : undefined })} />
              <NumberInput label="Stop timeout" description="Seconds; empty: 30" min={1} max={3600} allowDecimal={false} value={v.timeout ?? ''} onChange={(n) => setV({ ...v, timeout: typeof n === 'number' ? n : undefined })} />
            </Group>
          </>
        )}
        <Text size="xs" c="dimmed">
          Applied with your other changes, into <Mono>/etc/rc.conf.local</Mono>; it takes effect at the next boot. Start or stop it now from its menu.
        </Text>
        <Group justify="space-between">
          {current ? <Button variant="subtle" color="gray" onClick={() => { set(`${s.name}: back to the system’s boot setting`); onClose(); }}>Back to the system’s setting</Button> : <span />}
          <Group gap="sm">
            <Button variant="default" onClick={onClose}>Cancel</Button>
            <Button onClick={save} disabled={!!flagsError}>Save</Button>
          </Group>
        </Group>
      </Stack>
    </Modal>
  );
}

const dayLabel = (t: Date, now = new Date()) => {
  const day = (x: Date) => new Date(x.getFullYear(), x.getMonth(), x.getDate()).getTime();
  const diff = Math.round((day(now) - day(t)) / 86_400_000);
  if (diff === 0) return 'Today';
  if (diff === 1) return 'Yesterday';
  return t.toLocaleDateString([], { weekday: 'long', month: 'long', day: 'numeric', ...(t.getFullYear() !== now.getFullYear() ? { year: 'numeric' } : {}) });
};

// A service's log lines, newest first, under a heading for each day so
// a line needs only its time.
function RecentLog({ lines }: { lines: LogLine[] }) {
  const groups: { day: string; lines: LogLine[] }[] = [];
  for (const l of lines) {
    const day = l.time ? dayLabel(new Date(l.time)) : '';
    if (groups.at(-1)?.day !== day) groups.push({ day, lines: [] });
    groups.at(-1)!.lines.push(l);
  }
  return (
    <Stack gap="sm">
      {groups.map((g) => (
        <div key={g.day}>
          {g.day && <Text size="xs" fw={600} c="dimmed" tt="uppercase" lts={0.5} mb={4}>{g.day}</Text>}
          <Card withBorder padding={0} radius="sm">
            {g.lines.map((l, i) => (
              <Group key={i} gap="sm" wrap="nowrap" align="baseline" px="sm" py={6} style={i ? { borderTop: '1px solid var(--mantine-color-default-border)' } : undefined}>
                <Text size="xs" c="dimmed" className="num" w={64} style={{ flexShrink: 0, whiteSpace: 'nowrap' }} title={l.time ? new Date(l.time).toLocaleString() : undefined}>
                  {l.time ? new Date(l.time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }) : ''}
                </Text>
                {/* Written by the service, and by whoever it logs about: text, never markup. */}
                <Text size="xs" className="mono" style={{ wordBreak: 'break-word', lineHeight: 1.5 }}>{l.message}</Text>
              </Group>
            ))}
          </Card>
        </div>
      ))}
    </Stack>
  );
}

function DetailDrawer({ name, onClose, onAction }: { name?: string; onClose: () => void; onAction: (s: ServiceStatus, a: Action) => void }) {
  const [d, setD] = useState<ServiceDetailResource>();
  const [error, setError] = useState<string>();
  const { canOperate } = useRole();
  useEffect(() => {
    if (!name) return;
    let live = true;
    setD(undefined);
    setError(undefined);
    backend.service(name).then((x) => live && setD(x), (e) => live && setError(errorText(e)));
    return () => { live = false; };
  }, [name]);
  return (
    <Drawer opened={!!name} onClose={onClose} position="right" size="lg" title={name && <Text fw={600} className="mono">{name}</Text>}>
      {error && <Alert color="red" variant="light">{error}</Alert>}
      {!d && !error && <Text size="sm" c="dimmed">Reading…</Text>}
      {d && (
        <Stack gap="md">
          <Group gap="sm"><State s={d} />{d.description && <Text size="sm" c="dimmed">{d.description}</Text>}</Group>
          {d.managedAt && <Text size="sm">Set up on <Anchor component={Link} to={d.managedAt}>its own page</Anchor>.</Text>}
          {canOperate && actionsFor(d).length > 0 && (
            <Group gap="xs">
              {actionsFor(d).map((a) => {
                const Icon = actionIcon[a];
                return <Button key={a} size="compact-sm" variant="light" color={a === 'stop' ? 'red' : undefined} leftSection={<Icon size={14} />} onClick={() => onAction(d, a)}>{actionLabel[a]}</Button>;
              })}
            </Group>
          )}
          <div>
            <SectionTitle>rc.d settings</SectionTitle>
            <Table verticalSpacing={4}>
              <Table.Tbody>
                {Object.entries(d.vars).map(([k, v]) => (
                  <Table.Tr key={k}><Table.Td w={120}><Text size="sm" c="dimmed">{k}</Text></Table.Td><Table.Td><Mono>{v || '—'}</Mono></Table.Td></Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
            <Text size="xs" c="dimmed" mt={4}>As rcctl get has them: rc.conf’s defaults, then rc.conf.local.</Text>
          </div>
          <div>
            <SectionTitle right={<Anchor component={Link} to={`/system/logs?log=${d.logName}`} size="xs">Open {d.logName}</Anchor>}>Its recent log</SectionTitle>
            {d.log.length ? <RecentLog lines={d.log.slice(0, 20)} /> : null}
            {d.log.length ? null : (              <Empty>Nothing from it in {d.logName} lately.</Empty>
            )}
          </div>
        </Stack>
      )}
    </Drawer>
  );
}

export function ServicesPage() {
  const { canEdit, canOperate } = useRole();
  const [data, setData] = useState<ServicesResource>();
  const [error, setError] = useState<string>();
  const [tick, setTick] = useState(0);
  const [q, setQ] = useState('');
  const [show, setShow] = useState('all');
  const [detail, setDetail] = useState<string>();
  const [boot, setBoot] = useState<ServiceStatus>();
  const [confirm, setConfirm] = useState<{ s: ServiceStatus; a: Action }>();
  const [busy, setBusy] = useState<string>();
  useEffect(() => {
    let live = true;
    const load = () => !document.hidden && backend.services().then((d) => { if (live) { setData(d); setError(undefined); } }, (e) => live && setError(errorText(e)));
    load();
    const t = setInterval(load, POLL_MS);
    return () => { live = false; clearInterval(t); };
  }, [tick]);

  const run = async (s: ServiceStatus, a: Action) => {
    setConfirm(undefined);
    setBusy(s.name);
    try {
      const r = await backend.serviceAction(s.name, a);
      notifications.show(r.ok ? { color: 'teal', message: `${pastTense[a]} ${s.name}` } : { color: 'red', title: `Couldn’t ${a} ${s.name}`, message: r.output || 'rcctl failed' });
    } catch (e) {
      notifications.show({ color: 'red', title: `Couldn’t ${a} ${s.name}`, message: errorText(e) });
    } finally {
      setBusy(undefined);
      setTick((n) => n + 1);
    }
  };
  // Stopping anything is asked first; stopping sshd, with why.
  const act = (s: ServiceStatus, a: Action) => (a === 'stop' ? setConfirm({ s, a }) : run(s, a));

  const shown = useMemo(() => {
    const t = q.trim().toLowerCase();
    return (data?.services ?? []).filter((s) => {
      if (t && !`${s.name} ${s.description}`.toLowerCase().includes(t)) return false;
      switch (show) {
        case 'running': return s.running;
        case 'boot': return s.enabled;
        case 'failed': return s.failed;
        case 'stopped': return s.kind === 'daemon' && !s.running;
      }
      return true;
    });
  }, [data, q, show]);
  const failed = data?.services.filter((s) => s.failed).length ?? 0;

  return (
    <>
      <PageHeader
        title="Services"
        description="The base system’s services: what each is, whether it starts at boot, and whether it’s running. Starting and stopping happen at once; whether one starts at boot is a change you review and apply, written into rc.conf.local."
      />
      {error && <Alert color="red" variant="light" mb="md">{error}</Alert>}
      {data?.errors.map((e) => <Alert key={e} color="yellow" variant="light" mb="md">{e}</Alert>)}
      {failed > 0 && show !== 'failed' && (
        <Alert color="red" variant="light" mb="md" icon={<IconAlertTriangle size={16} />}>
          {failed} {failed === 1 ? 'service starts' : 'services start'} at boot but {failed === 1 ? 'isn’t' : 'aren’t'} running. <Anchor component="button" type="button" size="sm" onClick={() => setShow('failed')}>Show {failed === 1 ? 'it' : 'them'}</Anchor>
        </Alert>
      )}
      <Group mb="md" gap="sm">
        <TextInput placeholder="Search services" leftSection={<IconSearch size={16} />} value={q} onChange={(e) => setQ(e.currentTarget.value)} style={{ flex: '1 1 240px' }} />
        <SegmentedControl value={show} onChange={setShow} data={[{ value: 'all', label: 'All' }, { value: 'running', label: 'Running' }, { value: 'boot', label: 'Start at boot' }, { value: 'failed', label: 'Not running' }, { value: 'stopped', label: 'Stopped' }]} />
      </Group>
      {!data && !error && <Text size="sm" c="dimmed">Reading rcctl…</Text>}
      {data && shown.length === 0 && <Card><Empty>No services match.</Empty></Card>}
      <Stack gap="md">
        {categories.map((c) => {
          const rows = shown.filter((s) => s.category === c);
          if (!rows.length) return null;
          return (
            <Card key={c} padding={0}>
              <Text fw={600} px="md" pt="sm" pb={4}>{c}</Text>
              <Table.ScrollContainer minWidth={640}>
                <Table highlightOnHover verticalSpacing={6}>
                  <Table.Thead>
                    <Table.Tr>
                      <Table.Th>Service</Table.Th>
                      <Table.Th w={130}>Now</Table.Th>
                      <Table.Th w={140}>Starts at boot</Table.Th>
                      <Table.Th w={44} />
                    </Table.Tr>
                  </Table.Thead>
                  <Table.Tbody>
                    {rows.map((s) => {
                      const acts = canOperate ? actionsFor(s) : [];
                      const bootable = canEdit && s.known && !s.managedAt;
                      return (
                        <Table.Tr key={s.name}>
                          <Table.Td>
                            <Anchor component="button" type="button" className="mono" size="sm" onClick={() => setDetail(s.name)}>{s.name}</Anchor>
                            <Text size="xs" c="dimmed">
                              {s.description || 'Not one of the base system’s'}
                              {s.managedAt && <> · <Anchor component={Link} to={s.managedAt} size="xs">set up on its page</Anchor></>}
                            </Text>
                          </Table.Td>
                          <Table.Td><State s={s} /></Table.Td>
                          <Table.Td><Boot s={s} /></Table.Td>
                          <Table.Td>
                            {(acts.length > 0 || bootable) && (
                              <Menu position="bottom-end">
                                <Menu.Target><ActionIcon variant="subtle" color="gray" loading={busy === s.name} aria-label={`Actions for ${s.name}`}><IconDots size={16} /></ActionIcon></Menu.Target>
                                <Menu.Dropdown>
                                  {acts.map((a) => {
                                    const Icon = actionIcon[a];
                                    return <Menu.Item key={a} color={a === 'stop' ? 'red' : undefined} leftSection={<Icon size={16} />} onClick={() => act(s, a)}>{actionLabel[a]}</Menu.Item>;
                                  })}
                                  {bootable && <Menu.Item leftSection={<IconSettings size={16} />} onClick={() => setBoot(s)}>At boot…</Menu.Item>}
                                </Menu.Dropdown>
                              </Menu>
                            )}
                          </Table.Td>
                        </Table.Tr>
                      );
                    })}
                  </Table.Tbody>
                </Table>
              </Table.ScrollContainer>
            </Card>
          );
        })}
      </Stack>
      <Text size="xs" c="dimmed" mt="sm">
        OPF itself and pf aren’t stopped from here, and services set up on their own pages start and stop with their settings there. Every start, stop and restart is
        in <Anchor component={Link} to="/monitoring/events" size="xs">the events</Anchor>, with who did it.
      </Text>
      <DetailDrawer name={detail} onClose={() => setDetail(undefined)} onAction={act} />
      {boot && <BootModal s={boot} onClose={() => setBoot(undefined)} />}
      <Modal opened={!!confirm} onClose={() => setConfirm(undefined)} title={<Text fw={600}>Stop {confirm?.s.name}?</Text>}>
        {confirm && (
          <Stack>
            {confirm.s.name === 'sshd' ? (
              <Alert color="yellow" variant="light" icon={<IconAlertTriangle size={16} />}>
                No new SSH connections until it’s started again: no remote shell, and no one can sign in for sign-in access. Connections open now stay.
              </Alert>
            ) : (
              <Text size="sm">{confirm.s.description}. It stays stopped until it’s started again{confirm.s.enabled ? ', or the next boot' : ''}.</Text>
            )}
            <Code>rcctl stop {confirm.s.name}</Code>
            <Group justify="flex-end">
              <Button variant="default" onClick={() => setConfirm(undefined)}>Cancel</Button>
              <Button color="red" onClick={() => run(confirm.s, confirm.a)}>Stop</Button>
            </Group>
          </Stack>
        )}
      </Modal>
    </>
  );
}
