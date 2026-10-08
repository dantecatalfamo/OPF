// The command palette (Ctrl-K or ⌘K): every page by its name and
// section, and the things the configuration names (interfaces, tunnels,
// VPN devices, rules, aliases...) and the network's devices, each
// opening the page that has it.
import { useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate } from 'react-router';
import { Group, Kbd, Modal, ScrollArea, Stack, Text, TextInput, UnstyledButton } from '@mantine/core';
import { IconSearch } from '@tabler/icons-react';
import { backend, useStore } from '../model/store';
import { tunnels, type Model } from '../model/types';
import { useRole } from '../lib/session';
import { nav, places } from '../lib/nav';
import type { DeviceInfo } from '../lib/api';

interface Entry {
  label: string;
  /** Where it is, or what it is: "Firewall", "Interface", "VPN device". */
  kind: string;
  to: string;
  /** More it's found by: an address, a MAC, a device name. */
  also?: string;
  /** Pages before things, at the same match. */
  page?: boolean;
  /** A tab or card within a page: not listed until something's typed. */
  place?: boolean;
}

const enc = encodeURIComponent;

// The pages, then the tabs and cards within them (places), found by
// their names, their sections and their keywords.
function pages(canEdit: boolean): Entry[] {
  return [
    ...nav.flatMap((g) =>
      g.to
        ? [{ label: g.label, kind: 'Page', to: g.to, page: true }]
        : g.items!.filter((i) => !i.admin || canEdit).map((i) => ({ label: i.label, kind: g.label, to: i.to, also: `${g.label} ${i.keywords ?? ''}`, page: true })),
    ),
    ...places.filter((p) => !p.admin || canEdit).map((p) => ({ label: p.label, kind: p.page, to: p.to, also: p.keywords, page: true, place: true })),
  ];
}

// known: the MACs of the devices listed, whose reservations they stand for.
function things(m: Model, known: Set<string>): Entry[] {
  const out: Entry[] = [];
  for (const i of m.interfaces) {
    out.push({ label: i.name, kind: 'Interface', to: `/interfaces/${enc(i.id)}`, also: `${i.device} ${i.ipv4.address ?? ''}` });
  }
  for (const t of tunnels(m)) {
    out.push({ label: t.name, kind: 'WireGuard tunnel', to: `/services/wireguard/${enc(t.id)}`, also: t.device });
    for (const p of t.wireguard.peers) {
      out.push({ label: p.name, kind: `VPN device on ${t.name}`, to: `/devices/${enc(`vpn:${p.id}`)}`, also: p.address });
    }
  }
  const ifaceName = (id: string) => m.interfaces.find((i) => i.id === id)?.name ?? id;
  for (const r of m.firewall.rules) {
    if (!r.description) continue;
    const tab = r.interfaces.length === 1 && !(r.groups ?? []).length ? r.interfaces[0] : 'floating';
    out.push({ label: r.description, kind: `Rule on ${tab === 'floating' ? 'floating' : ifaceName(tab)}`, to: `/firewall/rules/${enc(tab)}` });
  }
  for (const f of m.firewall.forwards) {
    if (f.description) out.push({ label: f.description, kind: 'Port forward', to: '/firewall/nat' });
  }
  for (const r of m.firewall.outboundNat.rules) {
    if (r.description) out.push({ label: r.description, kind: 'Outbound NAT', to: '/firewall/nat/outbound' });
  }
  for (const a of m.firewall.aliases) {
    out.push({ label: a.name, kind: 'Alias', to: '/firewall/aliases', also: a.description });
  }
  for (const g of m.routing.gateways) {
    out.push({ label: g.name, kind: 'Gateway', to: '/network/routing/gateways', also: `${g.address} ${g.description}` });
  }
  for (const s of m.dhcp) {
    for (const r of s.reservations) {
      if (known.has(r.mac.toLowerCase())) continue;
      out.push({ label: r.hostname, kind: `Reservation on ${ifaceName(s.iface)}`, to: `/services/dhcp?iface=${enc(s.iface)}`, also: `${r.ip} ${r.mac}` });
    }
  }
  return out;
}

function devices(list: DeviceInfo[]): Entry[] {
  // VPN devices are among the configuration's things already.
  return list.filter((d) => d.kind !== 'vpn').map((d) => ({
    label: d.name || d.mac || d.addresses[0] || d.key,
    kind: d.networks.length ? `Device on ${d.networks.map((n) => n.name).join(', ')}` : 'Device',
    to: `/devices/${enc(d.key)}`,
    also: [d.mac, ...d.addresses].filter(Boolean).join(' '),
  }));
}

// How well an entry matches: every word of the query must be in it;
// then its name starting with the query, a word of its name starting
// with it, anywhere in its name, and last only in what else it's found by.
function score(e: Entry, words: string[], q: string): number {
  const label = e.label.toLowerCase();
  const all = `${label} ${e.kind.toLowerCase()} ${(e.also ?? '').toLowerCase()}`;
  if (!words.every((w) => all.includes(w))) return 0;
  const page = e.page ? 0.5 : 0;
  if (label.startsWith(q)) return 4 + page;
  if (label.split(/[\s\-_.:/]+/).some((w) => w.startsWith(words[0]))) return 3 + page;
  if (label.includes(words[0])) return 2 + page;
  return 1 + page;
}

const looksLikeHost = (q: string) => /^[0-9a-f:.]+$/i.test(q) && /[.:]/.test(q) || /^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(q);

export function CommandPalette({ opened, onClose }: { opened: boolean; onClose: () => void }) {
  const navigate = useNavigate();
  const { staged } = useStore();
  const { canEdit } = useRole();
  const [q, setQ] = useState('');
  const [sel, setSel] = useState(0);
  const [found, setFound] = useState<DeviceInfo[]>([]);
  const list = useRef<HTMLDivElement>(null);

  // The network's devices, read each time it opens; without them it
  // still finds the rest.
  useEffect(() => {
    if (!opened) return;
    setQ('');
    setSel(0);
    let live = true;
    backend.devices().then((r) => live && setFound(r.devices), () => {});
    return () => { live = false; };
  }, [opened]);

  const entries = useMemo(() => {
    const known = new Set(found.flatMap((d) => (d.mac ? [d.mac.toLowerCase()] : [])));
    return [...pages(canEdit), ...things(staged, known), ...devices(found)];
  }, [canEdit, staged, found]);
  const results = useMemo(() => {
    const query = q.trim().toLowerCase();
    const words = query.split(/\s+/).filter(Boolean);
    let out: Entry[];
    if (!words.length) {
      out = entries.filter((e) => e.page && !e.place);
    } else {
      out = entries
        .map((e) => ({ e, s: score(e, words, query) }))
        .filter((x) => x.s > 0)
        .sort((a, b) => b.s - a.s || a.e.label.localeCompare(b.e.label))
        .map((x) => x.e)
        .slice(0, 50);
    }
    // An address or a host name: the tools, for it.
    if (looksLikeHost(q.trim())) {
      const h = enc(q.trim());
      out = [
        ...out,
        { label: `Ping ${q.trim()}`, kind: 'Tools', to: `/monitoring/tools?tool=ping&host=${h}` },
        { label: `Trace the route to ${q.trim()}`, kind: 'Tools', to: `/monitoring/tools?tool=traceroute&host=${h}` },
        { label: `Look up ${q.trim()} in DNS`, kind: 'Tools', to: `/monitoring/tools?tool=dns&host=${h}` },
      ];
    }
    return out;
  }, [q, entries]);

  useEffect(() => setSel(0), [q]);
  useEffect(() => {
    list.current?.querySelector(`[data-index="${sel}"]`)?.scrollIntoView({ block: 'nearest' });
  }, [sel]);

  const go = (e?: Entry) => {
    if (!e) return;
    onClose();
    navigate(e.to);
  };

  return (
    <Modal opened={opened} onClose={onClose} withCloseButton={false} centered={false} size="lg" padding={0} yOffset="12vh" radius="md" aria-label="Go to">
      <TextInput
        data-autofocus
        size="md"
        variant="unstyled"
        px="md"
        py={6}
        leftSection={<IconSearch size={18} />}
        placeholder="Go to a page, an interface, a device, a rule…"
        value={q}
        onChange={(e) => setQ(e.currentTarget.value)}
        onKeyDown={(e) => {
          if (e.key === 'ArrowDown') { e.preventDefault(); setSel((s) => Math.min(s + 1, results.length - 1)); }
          else if (e.key === 'ArrowUp') { e.preventDefault(); setSel((s) => Math.max(s - 1, 0)); }
          else if (e.key === 'Enter') { e.preventDefault(); go(results[sel]); }
        }}
        style={{ borderBottom: '1px solid var(--mantine-color-default-border)' }}
        aria-controls="opf-palette-results"
        aria-activedescendant={results.length ? `opf-palette-${sel}` : undefined}
      />
      <ScrollArea.Autosize mah="55vh" viewportRef={list}>
        <Stack gap={0} p={6} id="opf-palette-results" role="listbox">
          {results.length ? results.map((e, i) => (
            <UnstyledButton
              key={`${e.to} ${e.label} ${e.kind}`}
              id={`opf-palette-${i}`}
              data-index={i}
              role="option"
              aria-selected={i === sel}
              onMouseMove={() => i !== sel && setSel(i)}
              onClick={() => go(e)}
              px="sm"
              py={7}
              style={{ borderRadius: 6, background: i === sel ? 'var(--mantine-color-default-hover)' : undefined }}
            >
              <Group justify="space-between" wrap="nowrap" gap="md">
                {/* Names come from the configuration and from devices: text, never markup. */}
                <Text size="sm" truncate>{e.label}</Text>
                <Text size="xs" c="dimmed" style={{ flexShrink: 0 }}>{e.kind}</Text>
              </Group>
            </UnstyledButton>
          )) : <Text size="sm" c="dimmed" ta="center" py="md">Nothing by that name.</Text>}
        </Stack>
      </ScrollArea.Autosize>
      <Group gap="md" px="md" py={8} style={{ borderTop: '1px solid var(--mantine-color-default-border)' }}>
        <Text size="xs" c="dimmed"><Kbd size="xs">↑</Kbd> <Kbd size="xs">↓</Kbd> to choose</Text>
        <Text size="xs" c="dimmed"><Kbd size="xs">Enter</Kbd> to go</Text>
        <Text size="xs" c="dimmed"><Kbd size="xs">Esc</Kbd> to close</Text>
      </Group>
    </Modal>
  );
}
