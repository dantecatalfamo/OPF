import { useEffect, useState } from 'react';
import { ActionIcon, Badge, Button, Card, Group, Menu, Modal, NumberInput, Select, Stack, Table, TagsInput, Text, TextInput, Tooltip } from '@mantine/core';
import { ListState } from '../components/ListState';
import { notifications } from '@mantine/notifications';
import { useForm } from '@mantine/form';
import { IconDots, IconDownload, IconPencil, IconPlus, IconTrash } from '@tabler/icons-react';
import { backend, newId, useStore } from '../model/store';
import type { TableStatus } from '../lib/api';
import type { Alias, Model } from '../model/types';
import { isCIDR, isIPv4, isPortSpec } from '../lib/ip';
import { PageHeader } from '../components/ui';
import { minutesText } from '../lib/format';

type Values = Omit<Alias, 'id'>;

const typeLabel: Record<Alias['type'], string> = {
  hosts: 'Addresses',
  networks: 'Networks',
  ports: 'Ports',
  table: 'Dynamic table',
  url: 'Downloaded list',
};

const typeHelp: Record<Alias['type'], string> = {
  hosts: 'A fixed list of addresses.',
  networks: 'A fixed list of networks in CIDR form.',
  ports: 'A fixed list of ports, for the port field of rules.',
  table: 'Starts empty (or with the entries below) and is filled at runtime, for example by a rule’s connection limits. Entries survive rule reloads, and stay until they expire (below), the table is flushed or the firewall restarts.',
  url: 'A list of addresses or networks downloaded from a URL into a pf table, such as a blocklist. It’s downloaded when you first apply it, again on the schedule below, and from its menu whenever you want the latest.',
};

function usedBy(m: Model, name: string): number {
  return m.firewall.rules.filter((r) => {
    if (r.kind === 'raw') return r.text.includes(`<${name}>`);
    return (r.source.type === 'alias' && r.source.alias === name) || (r.destination.type === 'alias' && r.destination.alias === name) || r.port === `alias:${name}` || r.sourcePort === `alias:${name}` || r.state?.overload === name;
  }).length;
}

const blank: Values = { name: '', type: 'hosts', entries: [], description: '' };

const units = [{ value: '1', label: 'minutes' }, { value: '60', label: 'hours' }, { value: '1440', label: 'days' }];
const MAX_MINUTES = 525600; // a year, as the server allows

// How long a table keeps each address: a number and a unit, or nothing
// for until it's flushed.
function ExpiryInput({ value, onChange }: { value?: number; onChange: (n: number | undefined) => void }) {
  const fit = (n: number) => (n % 1440 === 0 ? '1440' : n % 60 === 0 ? '60' : '1');
  const [unit, setUnit] = useState(() => (value ? fit(value) : '60'));
  const amount = value ? value / Number(unit) : '';
  const set = (a: number | string, u = unit) => onChange(typeof a === 'number' && a > 0 ? Math.min(MAX_MINUTES, Math.round(a * Number(u))) : undefined);
  return (
    <Group grow align="flex-start" gap="xs">
      <NumberInput
        label="Take each address out after"
        description={value ? `OPF removes it ${minutesText(value)} after it was added` : 'Empty: it stays until the table is flushed or the firewall restarts'}
        inputWrapperOrder={['label', 'input', 'description']}
        placeholder="Never"
        min={1}
        allowDecimal={false}
        value={amount}
        onChange={(a) => set(a)}
      />
      <Select label="&nbsp;" data={units} value={unit} allowDeselect={false} onChange={(u) => { if (u) { setUnit(u); if (typeof amount === 'number') set(amount, u); } }} />
    </Group>
  );
}

function AliasModal({ opened, onClose, alias, onSave }: { opened: boolean; onClose: () => void; alias: Alias | null; onSave: (v: Values) => void }) {
  const { staged } = useStore();
  const form = useForm<Values>({
    initialValues: blank,
    validate: {
      name: (v) => {
        if (!/^[a-z][a-z0-9_]{0,30}$/.test(v)) return 'Use lowercase letters, digits and _, starting with a letter';
        return staged.firewall.aliases.some((a) => a.name === v && a.id !== alias?.id) ? 'That name is taken' : null;
      },
      entries: (v, vals) => {
        if (vals.type === 'url') return null;
        if (!v.length && vals.type !== 'table') return 'Add at least one entry';
        const check = vals.type === 'hosts' ? isIPv4 : vals.type === 'ports' ? isPortSpec : (s: string) => isCIDR(s) || isIPv4(s);
        const bad = v.find((e) => !check(e));
        return bad ? `“${bad}” isn’t a valid ${vals.type === 'ports' ? 'port' : 'address'}` : null;
      },
      url: (v, vals) => (vals.type !== 'url' || /^https:\/\/\S+$/.test(v ?? '') ? null : 'Enter an https:// URL'),
    },
  });
  useEffect(() => {
    if (opened) form.setValues(alias ? { ...alias } : blank);
  }, [opened, alias]); // form is stable

  const t = form.values.type;
  const placeholder = t === 'hosts' ? '192.168.1.20' : t === 'ports' ? '8080' : '198.51.100.0/24';

  return (
    <Modal opened={opened} onClose={onClose} title={<Text fw={600}>{alias ? `Edit ${alias.name}` : 'Add alias'}</Text>} size="md">
      <form onSubmit={form.onSubmit((v) => {
        // An emptied number field is ''; unset is every 24 hours.
        const hours = v.refreshHours as number | string | undefined;
        onSave({ ...v, refreshHours: v.type === 'url' && typeof hours === 'number' ? hours : undefined, expireMinutes: v.type === 'table' ? v.expireMinutes : undefined });
        onClose();
      })}>
        <Stack>
          <TextInput label="Name" description={t === 'ports' ? undefined : `Used in pf as <${form.values.name || 'name'}>`} placeholder="cameras" {...form.getInputProps('name')} />
          <Select label="Type" data={Object.entries(typeLabel).map(([value, label]) => ({ value, label }))} allowDeselect={false} {...form.getInputProps('type')} />
          <Text size="xs" c="dimmed" mt={-8}>{typeHelp[t]}</Text>
          {t === 'url' ? (
            <>
              <TextInput label="List URL" description="One address or network a line; comments after # or ; are fine" inputWrapperOrder={['label', 'input', 'description', 'error']} placeholder="https://example.org/blocklist.txt" {...form.getInputProps('url')} />
              <NumberInput label="Download it again every" suffix=" hours" min={1} max={8760} placeholder="24" {...form.getInputProps('refreshHours')} />
            </>
          ) : (
            <TagsInput label={t === 'table' ? 'Initial entries' : 'Entries'} description="Press Enter after each one" placeholder={placeholder} {...form.getInputProps('entries')} />
          )}
          {t === 'table' && <ExpiryInput value={form.values.expireMinutes} onChange={(n) => form.setFieldValue('expireMinutes', n)} />}
          <TextInput label="Description" {...form.getInputProps('description')} />
          <Group justify="flex-end" mt="sm">
            <Button variant="default" onClick={onClose}>Cancel</Button>
            <Button type="submit">{alias ? 'Save' : 'Add alias'}</Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}

// The downloaded lists of the applied configuration's URL aliases,
// read again after a refresh.
function useTables(applied: Model) {
  const [tables, setTables] = useState<TableStatus[]>();
  const [refreshing, setRefreshing] = useState<string>();
  const load = () => backend.tables().then(setTables, () => setTables([]));
  useEffect(() => { load(); }, [applied]); // a commit may have downloaded one
  const refresh = async (name: string) => {
    setRefreshing(name);
    try {
      const t = await backend.refreshAlias(name);
      notifications.show({ color: t.warning ? 'yellow' : 'teal', title: `Downloaded ${name}`, message: t.warning ?? `${t.entries.toLocaleString()} entries, loaded into pf.` });
    } catch (e) {
      notifications.show({ color: 'red', title: `Couldn’t download ${name}`, message: e instanceof Error ? e.message : String(e) });
    } finally {
      setRefreshing(undefined);
      load();
    }
  };
  return { tables, refreshing, refresh };
}

export function Aliases() {
  const { staged, applied, edit } = useStore();
  const { tables, refreshing, refresh } = useTables(applied);
  const [modal, setModal] = useState<{ open: boolean; alias: Alias | null }>({ open: false, alias: null });
  const set = (summary: string, fn: (a: Alias[]) => Alias[]) => edit('firewall', summary, (m) => ({ ...m, firewall: { ...m.firewall, aliases: fn(m.firewall.aliases) } }));

  return (
    <>
      <PageHeader
        title="Aliases"
        description="Named groups of addresses, networks or ports. Each address alias becomes a pf table, so large lists stay fast and can change without reloading rules."
        actions={<Button leftSection={<IconPlus size={16} />} onClick={() => setModal({ open: true, alias: null })}>Add alias</Button>}
      />
      <Card padding={0}>
        <Table.ScrollContainer minWidth={680}>
          <Table highlightOnHover>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Name</Table.Th>
                <Table.Th>Type</Table.Th>
                <Table.Th>Contents</Table.Th>
                <Table.Th>Used by</Table.Th>
                <Table.Th />
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {staged.firewall.aliases.map((a) => {
                const n = usedBy(staged, a.name);
                return (
                  <Table.Tr key={a.id}>
                    <Table.Td>
                      <Text size="sm" fw={500} className="mono">{a.type === 'ports' ? a.name : `<${a.name}>`}</Text>
                      <Text size="xs" c="dimmed">{a.description}</Text>
                    </Table.Td>
                    <Table.Td><Badge color={a.type === 'table' || a.type === 'url' ? 'harbor' : 'gray'}>{typeLabel[a.type]}</Badge></Table.Td>
                    <Table.Td>
                      {a.type === 'url' ? (
                        <Stack gap={2}>
                          <Text size="xs" className="mono" c="dimmed" truncate="end" maw={320}>{a.url}</Text>
                          {(() => {
                            const t = tables?.find((x) => x.name === a.name);
                            const live = applied.firewall.aliases.some((x) => x.name === a.name && x.type === 'url');
                            return tables ? <ListState applied={live} fetched={t?.fetched} count={t && `${t.entries.toLocaleString()} entries`} refresh={t?.refresh} /> : <Text size="xs" c="dimmed">…</Text>;
                          })()}
                        </Stack>
                      ) : a.type === 'table' && !a.entries.length ? (
                        <Text size="xs" c="dimmed">Filled at runtime · {a.expireMinutes ? `each address kept ${minutesText(a.expireMinutes)}` : 'addresses kept until a flush or restart'}</Text>
                      ) : (
                        <Group gap={4}>
                          {a.entries.slice(0, 4).map((e) => <Badge key={e} variant="outline" color="gray" tt="none" className="mono">{e}</Badge>)}
                          {a.entries.length > 4 && <Text size="xs" c="dimmed">+{a.entries.length - 4} more</Text>}
                        </Group>
                      )}
                    </Table.Td>
                    <Table.Td><Text size="sm" c="dimmed">{n ? `${n} rule${n === 1 ? '' : 's'}` : 'Unused'}</Text></Table.Td>
                    <Table.Td w={44}>
                      <Menu position="bottom-end">
                        <Menu.Target><ActionIcon variant="subtle" color="gray" aria-label="Actions"><IconDots size={16} /></ActionIcon></Menu.Target>
                        <Menu.Dropdown>
                          <Menu.Item leftSection={<IconPencil size={16} />} onClick={() => setModal({ open: true, alias: a })}>Edit</Menu.Item>
                          {a.type === 'url' && tables?.some((t) => t.name === a.name) && (
                            <Menu.Item leftSection={<IconDownload size={16} />} disabled={refreshing === a.name} onClick={() => refresh(a.name)}>
                              {refreshing === a.name ? 'Downloading…' : 'Download again now'}
                            </Menu.Item>
                          )}
                          <Tooltip label="Remove it from rules first" disabled={n === 0} position="left">
                            <Menu.Item leftSection={<IconTrash size={16} />} color="red" disabled={n > 0} onClick={() => set(`Deleted alias ${a.name}`, (all) => all.filter((x) => x.id !== a.id))}>Delete</Menu.Item>
                          </Tooltip>
                        </Menu.Dropdown>
                      </Menu>
                    </Table.Td>
                  </Table.Tr>
                );
              })}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      </Card>
      <AliasModal
        opened={modal.open}
        onClose={() => setModal((m) => ({ ...m, open: false }))}
        alias={modal.alias}
        onSave={(v) =>
          modal.alias
            ? set(`Edited alias ${v.name}`, (all) => all.map((x) => (x.id === modal.alias!.id ? { ...v, id: x.id } : x)))
            : set(`Added ${typeLabel[v.type].toLowerCase()} alias ${v.name}`, (all) => [...all, { ...v, id: newId('a') }])
        }
      />
    </>
  );
}
