import { useState } from 'react';
import { useNavigate, useParams } from 'react-router';
import { ActionIcon, Badge, Button, Card, Group, Menu, Switch, Table, Tabs, Text, Tooltip } from '@mantine/core';
import { IconCopy, IconDots, IconGripVertical, IconLock, IconNotes, IconPencil, IconPlus, IconTrash } from '@tabler/icons-react';
import { DndContext, KeyboardSensor, PointerSensor, closestCenter, useSensor, useSensors, type DragEndEvent } from '@dnd-kit/core';
import { SortableContext, arrayMove, sortableKeyboardCoordinates, useSortable, verticalListSortingStrategy } from '@dnd-kit/sortable';
import { CSS } from '@dnd-kit/utilities';
import { newId, useStore } from '../model/store';
import { ruleCounters } from '../model/live';
import type { Model, Rule } from '../model/types';
import { endpointLabel, ifaceName, portLabel, protocolLabel } from '../lib/labels';
import { formatCount } from '../lib/format';
import { ActionBadge, PageHeader, Mono } from '../components/ui';
import { RuleDrawer } from './RuleDrawer';

function RuleRow({ rule, model, onEdit, onToggle, onDuplicate, onDelete }: {
  rule: Rule; model: Model; onEdit: () => void; onToggle: () => void; onDuplicate: () => void; onDelete: () => void;
}) {
  const { attributes, listeners, setNodeRef, transform, transition, isDragging } = useSortable({ id: rule.id });
  const c = ruleCounters[rule.id];
  const dim = rule.enabled ? undefined : 'dimmed';
  return (
    <Table.Tr
      ref={setNodeRef}
      className="drag-row"
      data-dragging={isDragging}
      style={{ transform: CSS.Translate.toString(transform), transition, opacity: rule.enabled ? 1 : 0.62 }}
    >
      <Table.Td w={36} pr={0}>
        <ActionIcon variant="subtle" color="gray" style={{ cursor: 'grab', touchAction: 'none' }} aria-label="Drag to reorder" {...attributes} {...listeners}>
          <IconGripVertical size={16} />
        </ActionIcon>
      </Table.Td>
      <Table.Td w={56}>
        <Switch size="xs" checked={rule.enabled} onChange={onToggle} aria-label={rule.enabled ? 'Disable rule' : 'Enable rule'} />
      </Table.Td>
      <Table.Td w={80}>
        <ActionBadge action={rule.action} muted={!rule.enabled} />
      </Table.Td>
      <Table.Td>
        <Text size="sm" fw={500} c={dim} style={{ cursor: 'pointer' }} onClick={onEdit}>
          {rule.description}
        </Text>
        <Group gap={6} mt={2}>
          {rule.log && (
            <Tooltip label="Matches are logged">
              <IconNotes size={14} color="var(--mantine-color-dimmed)" />
            </Tooltip>
          )}
          <Text size="xs" c="dimmed">
            {protocolLabel[rule.protocol]}
          </Text>
        </Group>
      </Table.Td>
      <Table.Td>
        <Text size="sm" c={dim}>{endpointLabel(rule.source, model)}</Text>
      </Table.Td>
      <Table.Td>
        <Text size="sm" c={dim}>{endpointLabel(rule.destination, model)}</Text>
      </Table.Td>
      <Table.Td>
        <Mono c={dim}>{portLabel(rule.port)}</Mono>
      </Table.Td>
      <Table.Td ta="right">
        {c ? (
          <Tooltip label={`${c.evaluations.toLocaleString()} checked · ${c.states} open connections`}>
            <Text size="sm" c="dimmed" className="num">{formatCount(c.evaluations)}</Text>
          </Tooltip>
        ) : (
          <Text size="sm" c="dimmed">New</Text>
        )}
      </Table.Td>
      <Table.Td w={44}>
        <Menu position="bottom-end" withinPortal>
          <Menu.Target>
            <ActionIcon variant="subtle" color="gray" aria-label="Rule actions">
              <IconDots size={16} />
            </ActionIcon>
          </Menu.Target>
          <Menu.Dropdown>
            <Menu.Item leftSection={<IconPencil size={16} />} onClick={onEdit}>Edit</Menu.Item>
            <Menu.Item leftSection={<IconCopy size={16} />} onClick={onDuplicate}>Duplicate</Menu.Item>
            <Menu.Divider />
            <Menu.Item leftSection={<IconTrash size={16} />} color="red" onClick={onDelete}>Delete</Menu.Item>
          </Menu.Dropdown>
        </Menu>
      </Table.Td>
    </Table.Tr>
  );
}

function SystemRow({ action, description, source, destination, port }: {
  action: 'pass' | 'block'; description: string; source: string; destination: string; port?: string;
}) {
  return (
    <Table.Tr style={{ background: 'var(--opf-bg)' }}>
      <Table.Td pr={0}>
        <Tooltip label="Built in. Change it under the interface’s settings.">
          <IconLock size={16} color="var(--mantine-color-dimmed)" style={{ marginLeft: 6 }} />
        </Tooltip>
      </Table.Td>
      <Table.Td />
      <Table.Td>
        <ActionBadge action={action} muted />
      </Table.Td>
      <Table.Td>
        <Text size="sm" c="dimmed">{description}</Text>
      </Table.Td>
      <Table.Td><Text size="sm" c="dimmed">{source}</Text></Table.Td>
      <Table.Td><Text size="sm" c="dimmed">{destination}</Text></Table.Td>
      <Table.Td><Mono c="dimmed">{port ?? 'Any'}</Mono></Table.Td>
      <Table.Td />
      <Table.Td />
    </Table.Tr>
  );
}

export function FirewallRules() {
  const { iface: param } = useParams();
  const navigate = useNavigate();
  const { staged, edit } = useStore();
  const ifaces = staged.interfaces;
  const current = ifaces.find((i) => i.id === param) ?? ifaces.find((i) => i.role === 'lan') ?? ifaces[0];
  const rules = staged.firewall.rules.filter((r) => r.iface === current.id);
  const [drawer, setDrawer] = useState<{ open: boolean; rule: Rule | null }>({ open: false, rule: null });
  const sensors = useSensors(useSensor(PointerSensor, { activationConstraint: { distance: 4 } }), useSensor(KeyboardSensor, { coordinateGetter: sortableKeyboardCoordinates }));

  const setRules = (summary: string, fn: (rules: Rule[]) => Rule[]) =>
    edit('firewall', summary, (m) => ({ ...m, firewall: { ...m.firewall, rules: fn(m.firewall.rules) } }));

  const onDragEnd = ({ active, over }: DragEndEvent) => {
    if (!over || active.id === over.id) return;
    const moved = rules.find((r) => r.id === active.id)!;
    setRules(`Moved rule “${moved.description}” on ${current.name}`, (all) => {
      const from = all.findIndex((r) => r.id === active.id);
      const to = all.findIndex((r) => r.id === over.id);
      return arrayMove(all, from, to);
    });
  };

  const save = (r: Omit<Rule, 'id'>) => {
    const existing = drawer.rule;
    if (existing) {
      setRules(`Edited rule “${r.description}” on ${ifaceName(staged, r.iface)}`, (all) => all.map((x) => (x.id === existing.id ? { ...r, id: x.id } : x)));
    } else {
      setRules(`Added rule “${r.description}” on ${ifaceName(staged, r.iface)}`, (all) => [...all, { ...r, id: newId('r') }]);
    }
    if (r.iface !== current.id) navigate(`/firewall/rules/${r.iface}`);
  };

  const isWan = current.role === 'wan';
  const isLan = current.role === 'lan';

  return (
    <>
      <PageHeader
        title="Firewall rules"
        description="Rules decide which new connections are allowed into each network. They’re checked from top to bottom and the first match wins. Drag rules to change their order."
        actions={
          <Button leftSection={<IconPlus size={16} />} onClick={() => setDrawer({ open: true, rule: null })}>
            Add rule
          </Button>
        }
      />
      <Tabs value={current.id} onChange={(v) => v && navigate(`/firewall/rules/${v}`)} mb="md">
        <Tabs.List>
          {ifaces.map((i) => {
            const n = staged.firewall.rules.filter((r) => r.iface === i.id).length;
            return (
              <Tabs.Tab key={i.id} value={i.id} rightSection={<Badge size="sm" color="gray" circle>{n}</Badge>}>
                {i.name}
              </Tabs.Tab>
            );
          })}
        </Tabs.List>
      </Tabs>

      <Card padding={0}>
        <Table.ScrollContainer minWidth={880}>
          <Table highlightOnHover>
            <Table.Thead>
              <Table.Tr>
                <Table.Th />
                <Table.Th>On</Table.Th>
                <Table.Th>Action</Table.Th>
                <Table.Th>Rule</Table.Th>
                <Table.Th>From</Table.Th>
                <Table.Th>To</Table.Th>
                <Table.Th>Port</Table.Th>
                <Table.Th ta="right">Matches</Table.Th>
                <Table.Th />
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {isLan && (
                <SystemRow action="pass" description="Anti-lockout: always allow this web interface" source={`${current.name} network`} destination="This firewall" port="443, 22" />
              )}
              {isWan && current.blockPrivate && <SystemRow action="block" description="Block private networks" source="Private addresses" destination="Any" />}
              {isWan && current.blockBogons && <SystemRow action="block" description="Block bogon networks" source="Bogon addresses" destination="Any" />}
              <DndContext sensors={sensors} collisionDetection={closestCenter} onDragEnd={onDragEnd}>
                <SortableContext items={rules.map((r) => r.id)} strategy={verticalListSortingStrategy}>
                  {rules.map((r) => (
                    <RuleRow
                      key={r.id}
                      rule={r}
                      model={staged}
                      onEdit={() => setDrawer({ open: true, rule: r })}
                      onToggle={() => setRules(`${r.enabled ? 'Disabled' : 'Enabled'} rule “${r.description}” on ${current.name}`, (all) => all.map((x) => (x.id === r.id ? { ...x, enabled: !x.enabled } : x)))}
                      onDuplicate={() => setRules(`Duplicated rule “${r.description}” on ${current.name}`, (all) => {
                        const i = all.findIndex((x) => x.id === r.id);
                        return [...all.slice(0, i + 1), { ...r, id: newId('r'), description: `${r.description} (copy)` }, ...all.slice(i + 1)];
                      })}
                      onDelete={() => setRules(`Deleted rule “${r.description}” on ${current.name}`, (all) => all.filter((x) => x.id !== r.id))}
                    />
                  ))}
                </SortableContext>
              </DndContext>
              {rules.length === 0 && (
                <Table.Tr>
                  <Table.Td colSpan={9}>
                    <Text size="sm" c="dimmed" ta="center" py="md">
                      No rules yet, so nothing new can come in on {current.name}.
                    </Text>
                  </Table.Td>
                </Table.Tr>
              )}
              <SystemRow
                action="block"
                description={`Default: block everything else arriving on ${current.name}`}
                source="Any"
                destination="Any"
              />
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      </Card>
      <Text size="xs" c="dimmed" mt="sm">
        Traffic this firewall sends, and replies to allowed connections, are always let through.
      </Text>

      <RuleDrawer
        opened={drawer.open}
        onClose={() => setDrawer({ open: false, rule: drawer.rule })}
        model={staged}
        rule={drawer.rule}
        iface={current.id}
        onSave={save}
      />
    </>
  );
}
