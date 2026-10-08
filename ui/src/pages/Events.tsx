// Diagnostics › Events: what happened, newest first. Links going down,
// the WAN address changing, gateways not answering, new devices, VPN
// devices roaming, daemons stopping, list downloads failing, patches,
// and every change applied. Filter by kind, search, and read further
// back a page at a time.
import { useEffect, useRef, useState } from 'react';
import { Link } from 'react-router';
import { Alert, Anchor, Button, Card, Chip, Group, Stack, Text, TextInput, ThemeIcon } from '@mantine/core';
import {
  IconDeviceLaptop, IconGitCommit, IconLogin, IconList, IconPlugConnected, IconPower, IconRoute, IconSearch, IconServer, IconShieldCheck, IconShieldLock, IconWorldWww,
} from '@tabler/icons-react';
import { backend, useStore } from '../model/store';
import { tunnels, type Model } from '../model/types';
import type { EventKind, OpfEvent } from '../lib/api';
import { PageHeader } from '../components/ui';

const kinds: { value: EventKind; label: string; icon: typeof IconPower }[] = [
  { value: 'link', label: 'Links', icon: IconPlugConnected },
  { value: 'address', label: 'Addresses', icon: IconWorldWww },
  { value: 'gateway', label: 'Gateways', icon: IconRoute },
  { value: 'device', label: 'New devices', icon: IconDeviceLaptop },
  { value: 'vpn', label: 'VPN', icon: IconShieldLock },
  { value: 'service', label: 'Services', icon: IconServer },
  { value: 'list', label: 'Lists', icon: IconList },
  { value: 'updates', label: 'Updates', icon: IconShieldCheck },
  { value: 'commit', label: 'Changes', icon: IconGitCommit },
  { value: 'login', label: 'Sign-ins', icon: IconLogin },
  { value: 'opf', label: 'OPF', icon: IconPower },
];
const iconOf = Object.fromEntries(kinds.map((k) => [k.value, k.icon])) as Record<EventKind, typeof IconPower>;

// Where an event's subject is set up or shown, if anywhere.
function linkOf(m: Model, e: OpfEvent): string | undefined {
  const s = e.subject ?? '';
  switch (e.kind) {
    case 'link':
    case 'address':
      return m.interfaces.some((i) => i.id === s) ? `/interfaces/${s}` : undefined;
    case 'gateway':
      return '/network/routing';
    case 'vpn':
      // A VPN device's own page; it links to its tunnel.
      return tunnels(m).some((x) => x.wireguard.peers.some((p) => p.id === s)) ? `/diagnostics/devices/${encodeURIComponent(`vpn:${s}`)}` : undefined;
    case 'device':
      // Its subject is its MAC address.
      return /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(s) ? `/diagnostics/devices/${encodeURIComponent(`mac:${s.toLowerCase()}`)}` : '/diagnostics/arp';
    case 'service':
      return { dhcpd: '/services/dhcp', unbound: '/services/dns', ntpd: '/system/general' }[s];
    case 'list':
      return (m.dns.blocklists ?? []).some((l) => l.id === s) ? '/services/dns?tab=blocking' : '/firewall/aliases';
    case 'updates':
      return '/system/general';
    case 'commit':
      return '/system/history';
  }
  return undefined;
}

const dayOf = (iso: string) => new Date(iso).toDateString();
const dayFormat = new Intl.DateTimeFormat([], { weekday: 'long', month: 'long', day: 'numeric' });
const timeFormat = new Intl.DateTimeFormat([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });

function dayLabel(iso: string): string {
  const d = new Date(iso);
  const today = new Date();
  const yesterday = new Date(Date.now() - 86400_000);
  if (d.toDateString() === today.toDateString()) return 'Today';
  if (d.toDateString() === yesterday.toDateString()) return 'Yesterday';
  return dayFormat.format(d);
}

export function Events() {
  const { applied } = useStore();
  const [selected, setSelected] = useState<string[]>([]);
  const [q, setQ] = useState('');
  const [query, setQuery] = useState('');
  const [events, setEvents] = useState<OpfEvent[]>();
  const [more, setMore] = useState(false);
  const [error, setError] = useState<string>();
  const [loadingOlder, setLoadingOlder] = useState(false);
  useEffect(() => {
    const t = setTimeout(() => setQuery(q.trim()), 300);
    return () => clearTimeout(t);
  }, [q]);

  const req = { kinds: selected as EventKind[], query: query || undefined };
  // The newest page, again every 30 seconds, adding what's new at the
  // top; older pages stay as loaded.
  const loaded = useRef(false);
  useEffect(() => {
    let live = true;
    loaded.current = false;
    setEvents(undefined);
    const load = () => {
      if (document.hidden) return;
      backend.events(req).then(
        (r) => {
          if (!live) return;
          if (!loaded.current) {
            loaded.current = true;
            setEvents(r.events);
            setMore(!!r.more);
          } else {
            setEvents((prev) => {
              const newest = prev?.[0]?.time;
              return [...r.events.filter((e) => !newest || e.time > newest), ...(prev ?? [])];
            });
          }
          setError(undefined);
        },
        (e) => live && setError(e instanceof Error ? e.message : String(e)),
      );
    };
    load();
    const t = setInterval(load, 30_000);
    return () => { live = false; clearInterval(t); };
  }, [selected.join(), query]); // req is made of these

  const older = async () => {
    if (!events?.length) return;
    setLoadingOlder(true);
    try {
      const r = await backend.events({ ...req, before: events[events.length - 1].time });
      setEvents([...events, ...r.events]);
      setMore(!!r.more);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoadingOlder(false);
    }
  };

  // By day, newest first.
  const days: { day: string; events: OpfEvent[] }[] = [];
  for (const e of events ?? []) {
    const d = dayOf(e.time);
    if (days[days.length - 1]?.day !== d) days.push({ day: d, events: [] });
    days[days.length - 1].events.push(e);
  }

  return (
    <>
      <PageHeader
        title="Events"
        description="What happened: links and gateways going down and coming back, new devices, VPN devices connecting from somewhere new, services stopping, downloads failing, patches, and every change applied. Kept for 90 days."
      />
      <Stack gap="sm" mb="md">
        <TextInput placeholder="Search" leftSection={<IconSearch size={16} />} value={q} onChange={(e) => setQ(e.currentTarget.value)} maw={420} />
        <Chip.Group multiple value={selected} onChange={setSelected}>
          <Group gap={6}>
            {kinds.map((k) => (
              <Chip key={k.value} value={k.value} size="xs" variant="outline">{k.label}</Chip>
            ))}
          </Group>
        </Chip.Group>
      </Stack>
      {error && <Alert color="red" variant="light" mb="md">Couldn’t ask OPF: {error}</Alert>}
      {events && events.length === 0 && (
        <Text c="dimmed" size="sm">{query || selected.length ? 'No events match.' : 'Nothing has happened yet. OPF starts noticing when it starts.'}</Text>
      )}
      <Stack gap="md">
        {days.map(({ day, events: list }) => (
          <Card key={day} padding="md">
            <Text fw={600} size="sm" mb="xs">{dayLabel(list[0].time)}</Text>
            <Stack gap={10}>
              {list.map((e, i) => {
                const Icon = iconOf[e.kind] ?? IconPower;
                const to = linkOf(applied, e);
                return (
                  <Group key={`${e.time}-${i}`} gap="sm" wrap="nowrap" align="flex-start">
                    <ThemeIcon size={26} radius="xl" variant="light" color={e.warning ? 'red' : 'gray'}>
                      <Icon size={15} />
                    </ThemeIcon>
                    <Text size="xs" c="dimmed" className="num" w={72} pt={4} style={{ flexShrink: 0 }}>{timeFormat.format(new Date(e.time))}</Text>
                    {/* Messages can quote what devices call themselves: text, never markup. */}
                    <Text size="sm" pt={2} style={{ minWidth: 0, overflowWrap: 'anywhere' }}>
                      {e.message}
                      {to && <> <Anchor component={Link} to={to} size="xs">Open</Anchor></>}
                    </Text>
                  </Group>
                );
              })}
            </Stack>
          </Card>
        ))}
      </Stack>
      {more && (
        <Group justify="center" mt="md">
          <Button variant="default" size="xs" loading={loadingOlder} onClick={older}>Show older</Button>
        </Group>
      )}
    </>
  );
}
