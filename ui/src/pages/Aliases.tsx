import { useEffect, useState } from 'react';
import { ActionIcon, Badge, Button, Card, Group, Menu, Modal, SegmentedControl, Stack, Table, TagsInput, Text, TextInput, Tooltip } from '@mantine/core';
import { useForm } from '@mantine/form';
import { IconDots, IconPencil, IconPlus, IconTrash } from '@tabler/icons-react';
import { newId, useStore } from '../model/store';
import type { Alias, Model } from '../model/types';
import { isCIDR, isIPv4, isPortSpec } from '../lib/ip';
import { PageHeader } from '../components/ui';

type Values = Omit<Alias, 'id'>;

const typeLabel: Record<Alias['type'], string> = { hosts: 'Addresses', networks: 'Networks', ports: 'Ports' };

function usedBy(m: Model, name: string): number {
  return m.firewall.rules.filter(
    (r) => (r.source.type === 'alias' && r.source.alias === name) || (r.destination.type === 'alias' && r.destination.alias === name) || r.port === `alias:${name}`,
  ).length;
}

function AliasModal({ opened, onClose, alias, onSave }: { opened: boolean; onClose: () => void; alias: Alias | null; onSave: (v: Values) => void }) {
  const { staged } = useStore();
  const form = useForm<Values>({
    initialValues: { name: '', type: 'hosts', entries: [], description: '' },
    validate: {
      name: (v) => {
        if (!/^[a-z][a-z0-9_]{0,30}$/.test(v)) return 'Use lowercase letters, digits and _, starting with a letter';
        return staged.firewall.aliases.some((a) => a.name === v && a.id !== alias?.id) ? 'That name is taken' : null;
      },
      entries: (v, vals) => {
        if (!v.length) return 'Add at least one entry';
        const check = vals.type === 'hosts' ? isIPv4 : vals.type === 'networks' ? (s: string) => isCIDR(s) || isIPv4(s) : isPortSpec;
        const bad = v.find((e) => !check(e));
        return bad ? `“${bad}” isn’t a valid ${vals.type === 'ports' ? 'port' : 'address'}` : null;
      },
    },
  });
  useEffect(() => {
    if (opened) form.setValues(alias ? { ...alias } : { name: '', type: 'hosts', entries: [], description: '' });
  }, [opened, alias]); // form is stable

  const placeholder = form.values.type === 'hosts' ? '192.168.1.20' : form.values.type === 'networks' ? '198.51.100.0/24' : '8080';

  return (
    <Modal opened={opened} onClose={onClose} title={<Text fw={600}>{alias ? `Edit ${alias.name}` : 'Add alias'}</Text>} size="md">
      <form onSubmit={form.onSubmit((v) => { onSave(v); onClose(); })}>
        <Stack>
          <Text size="sm" c="dimmed">
            Name a group of addresses or ports once, then use it in any rule. Updating the alias updates every rule that uses it.
          </Text>
          <TextInput label="Name" placeholder="cameras" {...form.getInputProps('name')} />
          <SegmentedControl data={Object.entries(typeLabel).map(([value, label]) => ({ value, label }))} {...form.getInputProps('type')} />
          <TagsInput label="Entries" description="Press Enter after each one" placeholder={placeholder} {...form.getInputProps('entries')} />
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

export function Aliases() {
  const { staged, edit } = useStore();
  const [modal, setModal] = useState<{ open: boolean; alias: Alias | null }>({ open: false, alias: null });
  const set = (summary: string, fn: (a: Alias[]) => Alias[]) =>
    edit('firewall', summary, (m) => ({ ...m, firewall: { ...m.firewall, aliases: fn(m.firewall.aliases) } }));

  return (
    <>
      <PageHeader
        title="Aliases"
        description="Reusable groups of addresses, networks or ports for firewall rules."
        actions={<Button leftSection={<IconPlus size={16} />} onClick={() => setModal({ open: true, alias: null })}>Add alias</Button>}
      />
      <Card padding={0}>
        <Table.ScrollContainer minWidth={640}>
          <Table highlightOnHover>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Name</Table.Th>
                <Table.Th>Type</Table.Th>
                <Table.Th>Entries</Table.Th>
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
                      <Text size="sm" fw={500} className="mono">{a.name}</Text>
                      <Text size="xs" c="dimmed">{a.description}</Text>
                    </Table.Td>
                    <Table.Td><Badge color="gray">{typeLabel[a.type]}</Badge></Table.Td>
                    <Table.Td>
                      <Group gap={4}>
                        {a.entries.slice(0, 4).map((e) => <Badge key={e} variant="outline" color="gray" tt="none" className="mono">{e}</Badge>)}
                        {a.entries.length > 4 && <Text size="xs" c="dimmed">+{a.entries.length - 4} more</Text>}
                      </Group>
                    </Table.Td>
                    <Table.Td><Text size="sm" c="dimmed">{n ? `${n} rule${n === 1 ? '' : 's'}` : 'Unused'}</Text></Table.Td>
                    <Table.Td w={44}>
                      <Menu position="bottom-end">
                        <Menu.Target>
                          <ActionIcon variant="subtle" color="gray" aria-label="Actions"><IconDots size={16} /></ActionIcon>
                        </Menu.Target>
                        <Menu.Dropdown>
                          <Menu.Item leftSection={<IconPencil size={16} />} onClick={() => setModal({ open: true, alias: a })}>Edit</Menu.Item>
                          <Tooltip label="Remove it from rules first" disabled={n === 0} position="left">
                            <Menu.Item leftSection={<IconTrash size={16} />} color="red" disabled={n > 0} onClick={() => set(`Deleted alias ${a.name}`, (all) => all.filter((x) => x.id !== a.id))}>
                              Delete
                            </Menu.Item>
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
            : set(`Added alias ${v.name} (${v.entries.length} ${typeLabel[v.type].toLowerCase()})`, (all) => [...all, { ...v, id: newId('a') }])
        }
      />
    </>
  );
}
