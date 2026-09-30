// DNS blocklists on the DNS resolver page: lists of names the resolver
// blocks (ads, trackers), your own blocked and allowed names, and how a
// blocked name is answered.
import { useEffect, useState } from 'react';
import { ActionIcon, Anchor, Button, Card, Group, Menu, Modal, NumberInput, SegmentedControl, Stack, Switch, Table, TagsInput, Text, TextInput, Tooltip } from '@mantine/core';
import { useForm } from '@mantine/form';
import { notifications } from '@mantine/notifications';
import { IconDots, IconDownload, IconPencil, IconPlus, IconTrash } from '@tabler/icons-react';
import { backend, useStore } from '../model/store';
import type { DnsListStatus } from '../lib/api';
import type { DnsBlocklist, Model } from '../model/types';
import { ListState } from '../components/ListState';
import { Empty, SectionTitle } from '../components/ui';
import { formatBytes } from '../lib/format';
import { estimateBytes } from '../lib/dnsCost';
import { BlocklistMemory } from './DnsActivity';

// Lists people use, in formats OPF reads, fetched to check them.
const wellKnown: Omit<DnsBlocklist, 'id' | 'enabled'>[] = [
  // Hagezi's RPZ, which lists each name and what's under it; its
  // "onlydomains" file means the same but reads as exact names.
  { name: 'Hagezi Pro', url: 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/rpz/pro.txt' },
  { name: 'OISD small', url: 'https://small.oisd.nl/rpz' },
  { name: 'AdGuard DNS filter', url: 'https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt' },
  { name: 'Steven Black hosts', url: 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts' },
];

// A name, or *. and a name (pf.IsBlockName).
const blockNameRE = /^(\*\.)?(?=.{1,253}\.?$)([A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.)*[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.?$/;

// A new list's id: lowercase letters, digits and hyphens, unique.
function listId(name: string, m: Model): string {
  const base = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 24) || 'list';
  const taken = new Set((m.dns.blocklists ?? []).map((l) => l.id));
  let id = base;
  for (let n = 2; taken.has(id); n++) id = `${base}-${n}`;
  return id;
}

function ListModal({ list, onClose, onSave }: { list: DnsBlocklist | Omit<DnsBlocklist, 'id'> | null; onClose: () => void; onSave: (l: Omit<DnsBlocklist, 'id'>) => void }) {
  const form = useForm({
    initialValues: { name: '', url: '', refreshHours: '' as number | string },
    validate: {
      name: (v) => (!v.trim() ? 'Name the list' : /["\\]/.test(v) ? 'Leave out quotes and backslashes' : v.length > 60 ? 'Up to 60 characters' : null),
      url: (v) => (/^https:\/\/\S+$/.test(v.trim()) ? null : 'Enter an https:// URL'),
    },
  });
  useEffect(() => {
    if (list) form.setValues({ name: list.name, url: list.url, refreshHours: list.refreshHours ?? '' });
  }, [list]); // form is stable
  return (
    <Modal opened={!!list} onClose={onClose} title={<Text fw={600}>{list && 'id' in list ? `Edit ${list.name}` : 'Add a DNS blocklist'}</Text>}>
      <form onSubmit={form.onSubmit((v) => {
        onSave({ name: v.name.trim(), url: v.url.trim(), enabled: list?.enabled ?? true, refreshHours: typeof v.refreshHours === 'number' ? v.refreshHours : undefined });
        onClose();
      })}>
        <Stack>
          <TextInput label="Name" placeholder="Hagezi Pro" {...form.getInputProps('name')} />
          <TextInput
            label="List URL"
            description="A hosts file, a list of names, an adblock list or an RPZ zone; OPF reads each and says what it couldn’t use."
            inputWrapperOrder={['label', 'input', 'description', 'error']}
            placeholder="https://example.org/blocklist.txt"
            {...form.getInputProps('url')}
          />
          <NumberInput label="Download it again every" suffix=" hours" min={1} max={8760} placeholder="24" {...form.getInputProps('refreshHours')} />
          <Group justify="flex-end" mt="sm">
            <Button variant="default" onClick={onClose}>Cancel</Button>
            <Button type="submit">Save</Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}

// The lines a list had that OPF couldn't use, by why.
function Skipped({ skipped }: { skipped: Record<string, number> }) {
  const total = Object.values(skipped).reduce((a, b) => a + b, 0);
  if (!total) return null;
  return (
    <Tooltip multiline w={340} label={Object.entries(skipped).map(([why, n]) => `${n.toLocaleString()}: ${why}`).join('\n')} style={{ whiteSpace: 'pre-line' }}>
      <Text size="xs" c="dimmed" td="underline" style={{ textDecorationStyle: 'dotted', cursor: 'help' }}>
        {total.toLocaleString()} {total === 1 ? 'line' : 'lines'} left out
      </Text>
    </Tooltip>
  );
}

export function DnsBlocklists() {
  const { staged, applied, edit } = useStore();
  const lists = staged.dns.blocklists ?? [];
  const [status, setStatus] = useState<DnsListStatus[]>();
  const [refreshing, setRefreshing] = useState<string>();
  const [modal, setModal] = useState<DnsBlocklist | Omit<DnsBlocklist, 'id'> | null>(null);
  const load = () => backend.dnsLists().then(setStatus, () => setStatus([]));
  useEffect(() => { load(); }, [applied]); // a commit may have downloaded one

  const setDns = (summary: string, fn: (d: Model['dns']) => Model['dns']) => edit('dns', summary, (m) => ({ ...m, dns: fn(m.dns) }));
  const setLists = (summary: string, fn: (l: DnsBlocklist[]) => DnsBlocklist[]) => setDns(summary, (d) => ({ ...d, blocklists: fn(d.blocklists ?? []) }));

  const refresh = async (l: DnsBlocklist) => {
    setRefreshing(l.id);
    try {
      const s = await backend.refreshDnsList(l.id);
      notifications.show({ color: s.warning ? 'yellow' : 'teal', title: `Downloaded ${l.name}`, message: s.warning ?? `${s.blocked.toLocaleString()} names, loaded into the resolver.` });
    } catch (e) {
      notifications.show({ color: 'red', title: `Couldn’t download ${l.name}`, message: e instanceof Error ? e.message : String(e) });
    } finally {
      setRefreshing(undefined);
      load();
    }
  };

  const answer = staged.dns.blockAnswer ?? '';
  return (
    <Card>
      <SectionTitle
        right={
          <Menu position="bottom-end">
            <Menu.Target>
              <Button size="xs" variant="light" leftSection={<IconPlus size={14} />}>Add list</Button>
            </Menu.Target>
            <Menu.Dropdown>
              <Menu.Item onClick={() => setModal({ name: '', url: '', enabled: true })}>A list by URL…</Menu.Item>
              <Menu.Label>Well-known lists</Menu.Label>
              {wellKnown.filter((w) => !lists.some((l) => l.url === w.url)).map((w) => (
                <Menu.Item key={w.url} onClick={() => setLists(`Added DNS blocklist ${w.name}`, (all) => [...all, { ...w, id: listId(w.name, staged), enabled: true }])}>{w.name}</Menu.Item>
              ))}
            </Menu.Dropdown>
          </Menu>
        }
      >
        Blocklists
      </SectionTitle>
      <Stack gap="md">
        <Text size="sm" c="dimmed">
          Names on these lists, such as ad and tracker servers, don’t resolve for devices using this resolver. Lists are downloaded when you apply them and again on a schedule. Every list a Pi-hole takes works here. Browser lists like EasyList only partly apply: DNS sees names, not pages, so OPF uses their rules for whole names and says how many it left out.
        </Text>
        <Group gap="sm" align="center">
          <Text size="sm" fw={500}>Answer blocked names with</Text>
          <SegmentedControl
            size="xs"
            value={answer}
            onChange={(v) => setDns(v ? 'Blocked names answer “no such name”' : 'Blocked names answer 0.0.0.0', (d) => ({ ...d, blockAnswer: v as '' | 'nxdomain' }))}
            data={[{ value: '', label: '0.0.0.0, like Pi-hole' }, { value: 'nxdomain', label: 'No such name' }]}
          />
        </Group>
        <BlocklistMemory status={status} />
        {lists.length ? (
          <Table.ScrollContainer minWidth={460}>
            <Table verticalSpacing="xs">
              <Table.Tbody>
                {lists.map((l) => {
                  const s = status?.find((x) => x.id === l.id);
                  const live = (applied.dns.blocklists ?? []).some((x) => x.id === l.id && x.enabled);
                  return (
                    <Table.Tr key={l.id}>
                      <Table.Td w={52}>
                        <Switch size="xs" checked={l.enabled} aria-label={l.enabled ? 'Turn off' : 'Turn on'}
                          onChange={() => setLists(`${l.enabled ? 'Turned off' : 'Turned on'} DNS blocklist ${l.name}`, (all) => all.map((x) => (x.id === l.id ? { ...x, enabled: !x.enabled } : x)))} />
                      </Table.Td>
                      <Table.Td>
                        <Text size="sm" fw={500} c={l.enabled ? undefined : 'dimmed'}>{l.name}</Text>
                        <Anchor href={l.url} target="_blank" rel="noreferrer" size="xs" c="dimmed" className="mono" style={{ wordBreak: 'break-all' }}>{l.url}</Anchor>
                        {l.enabled && (status
                          ? <ListState applied={live} fetched={s?.fetched} count={s && `${s.blocked.toLocaleString()} names${s.allowed ? ` (${s.allowed.toLocaleString()} let through)` : ''}, about ${formatBytes(estimateBytes(s.blocked + s.allowed))} of memory`} refresh={s?.refresh} />
                          : <Text size="xs" c="dimmed">…</Text>)}
                        {s && live && <Skipped skipped={s.skipped} />}
                      </Table.Td>
                      <Table.Td w={44}>
                        <Menu position="bottom-end">
                          <Menu.Target><ActionIcon variant="subtle" color="gray" aria-label="Actions"><IconDots size={16} /></ActionIcon></Menu.Target>
                          <Menu.Dropdown>
                            <Menu.Item leftSection={<IconPencil size={16} />} onClick={() => setModal(l)}>Edit</Menu.Item>
                            {live && (
                              <Menu.Item leftSection={<IconDownload size={16} />} disabled={refreshing === l.id} onClick={() => refresh(l)}>
                                {refreshing === l.id ? 'Downloading…' : 'Download again now'}
                              </Menu.Item>
                            )}
                            <Menu.Item leftSection={<IconTrash size={16} />} color="red" onClick={() => setLists(`Removed DNS blocklist ${l.name}`, (all) => all.filter((x) => x.id !== l.id))}>Remove</Menu.Item>
                          </Menu.Dropdown>
                        </Menu>
                      </Table.Td>
                    </Table.Tr>
                  );
                })}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        ) : (
          <Empty>No blocklists. Add one of the well-known lists to start.</Empty>
        )}
      </Stack>
      <ListModal
        list={modal}
        onClose={() => setModal(null)}
        onSave={(v) => {
          if (modal && 'id' in modal) setLists(`Edited DNS blocklist ${v.name}`, (all) => all.map((x) => (x.id === modal.id ? { ...v, id: x.id } : x)));
          else setLists(`Added DNS blocklist ${v.name}`, (all) => [...all, { ...v, id: listId(v.name, staged) }]);
        }}
      />
    </Card>
  );
}

// Your own names, blocked or allowed whatever the lists say.
export function DnsOwnNames() {
  const { staged, edit } = useStore();
  const setDns = (summary: string, fn: (d: Model['dns']) => Model['dns']) => edit('dns', summary, (m) => ({ ...m, dns: fn(m.dns) }));
  const own = useForm({
    initialValues: { blocked: staged.dns.blocked ?? [], allowed: staged.dns.allowed ?? [] },
    validate: {
      blocked: (v) => v.find((n) => !blockNameRE.test(n)) ? `“${v.find((n) => !blockNameRE.test(n))}” isn’t a name` : null,
      allowed: (v, all) => {
        const bad = v.find((n) => !blockNameRE.test(n));
        if (bad) return `“${bad}” isn’t a name`;
        const both = v.find((n) => all.blocked.some((b) => b.toLowerCase() === n.toLowerCase()));
        return both ? `${both} is blocked too` : null;
      },
    },
  });
  useEffect(() => {
    own.setValues({ blocked: staged.dns.blocked ?? [], allowed: staged.dns.allowed ?? [] });
    own.resetDirty();
  }, [staged.dns.blocked, staged.dns.allowed]); // form is stable

  return (
    <Card>
      <SectionTitle>Your own names</SectionTitle>
        <form onSubmit={own.onSubmit((v) => setDns('Changed your own blocked and allowed names', (d) => ({ ...d, blocked: v.blocked, allowed: v.allowed })))}>
        <Stack gap="sm">
          <TagsInput label="Always block" placeholder="ads.example.com or *.example.com" {...own.getInputProps('blocked')} />
          <TagsInput label="Never block" description="Wins over every list: for a name a list blocks that you need." inputWrapperOrder={['label', 'input', 'description', 'error']} placeholder="cdn.example.com" {...own.getInputProps('allowed')} />
          <Text size="xs" c="dimmed">
            A name blocks just that name; *.example.com blocks example.com and everything under it. Patterns (regular expressions) aren’t possible: OpenBSD’s resolver only matches names and wildcards.
          </Text>
          <Group justify="flex-end">
            <Button type="submit" size="xs" disabled={!own.isDirty()}>Save names</Button>
          </Group>
        </Stack>
      </form>
    </Card>
  );
}
