import { useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router';
import { ActionIcon, Anchor, Badge, Button, Card, Group, Menu, Switch, Table, Tabs, Text, Tooltip } from '@mantine/core';
import {
  IconArrowBarToRight, IconArrowsSplit2, IconCode, IconCopy, IconDots, IconGauge, IconGripVertical, IconLock, IconNotes, IconPencil, IconPlus, IconTag, IconTrash,
} from '@tabler/icons-react';
import { DndContext, KeyboardSensor, PointerSensor, closestCenter, useSensor, useSensors, type DragEndEvent } from '@dnd-kit/core';
import { SortableContext, arrayMove, sortableKeyboardCoordinates, useSortable, verticalListSortingStrategy } from '@dnd-kit/sortable';
import { CSS } from '@dnd-kit/utilities';
import { newId, useStore } from '../model/store';
import { ruleCounters } from '../model/live';
import { ruleText } from '../model/generate';
import type { Model, Rule, RuleInput } from '../model/types';
import { endpointLabel, ifaceName, portLabel, protocolLabel } from '../lib/labels';
import { formatCount } from '../lib/format';
import { rawAction } from '../lib/pfcheck';
import { isFloating } from '../lib/rules';
import { ActionBadge, PageHeader, Mono } from '../components/ui';
import { RuleDrawer } from './RuleDrawer';

const FLOATING = 'floating';

function usePref(key: string, initial: boolean): [boolean, (v: boolean) => void] {
  const [v, setV] = useState(() => {
    try {
      const s = localStorage.getItem(key);
      return s === null ? initial : s === '1';
    } catch {
      return initial;
    }
  });
  return [v, (nv) => {
    setV(nv);
    try {
      localStorage.setItem(key, nv ? '1' : '0');
    } catch {
      /* per-browser convenience only */
    }
  }];
}

function Markers({ rule, model }: { rule: Rule; model: Model }) {
  if (rule.kind === 'raw') {
    return <Badge size="xs" variant="outline" color="gray" leftSection={<IconCode size={10} />}>pf</Badge>;
  }
  const m: { icon: typeof IconNotes; label: string }[] = [];
  if (rule.log !== 'off') m.push({ icon: IconNotes, label: rule.log === 'all' ? 'Logs every packet' : 'Logs new connections' });
  if (!rule.quick) m.push({ icon: IconArrowBarToRight, label: 'Doesn’t stop here; later rules can override it' });
  if (rule.state && (rule.state.maxStates || rule.state.maxSrcConn || rule.state.maxSrcConnRate || rule.state.mode !== 'keep')) {
    m.push({ icon: IconGauge, label: `Connection limits or ${rule.state.mode} state` });
  }
  if (rule.gateway || rule.replyTo || rule.rtable !== undefined) {
    const g = model.routing.gateways.find((x) => x.id === rule.gateway);
    m.push({ icon: IconArrowsSplit2, label: g ? `Routed via ${g.name}` : 'Custom routing' });
  }
  if (rule.tag || rule.tagged || rule.prio !== undefined) m.push({ icon: IconTag, label: [rule.tag && `tags ${rule.tag}`, rule.tagged && `only tagged ${rule.tagged}`, rule.prio !== undefined && `priority ${rule.prio}`].filter(Boolean).join(', ') });
  return (
    <Group gap={6} wrap="nowrap">
      {rule.direction !== 'in' && <Badge size="xs" color="gray">{rule.direction === 'out' ? 'out' : 'in/out'}</Badge>}
      {m.map(({ icon: Icon, label }) => (
        <Tooltip key={label} label={label}>
          <Icon size={14} color="var(--mantine-color-dimmed)" />
        </Tooltip>
      ))}
    </Group>
  );
}

function RuleRow({ rule, model, showPf, floating, onEdit, onToggle, onDuplicate, onDelete }: {
  rule: Rule; model: Model; showPf: boolean; floating: boolean; onEdit: () => void; onToggle: () => void; onDuplicate: () => void; onDelete: () => void;
}) {
  const { attributes, listeners, setNodeRef, transform, transition, isDragging } = useSortable({ id: rule.id });
  const c = ruleCounters[rule.id];
  const dim = rule.enabled ? undefined : 'dimmed';
  const action = rule.kind === 'raw' ? rawAction(rule.text) : rule.action;
  const pf = showPf || rule.kind === 'raw';
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
      <Table.Td w={96}>
        {action === 'other' ? <Badge color="gray" w={80}>pf</Badge> : <ActionBadge action={action} muted={!rule.enabled} />}
      </Table.Td>
      <Table.Td>
        <Text size="sm" fw={500} c={dim} style={{ cursor: 'pointer' }} onClick={onEdit}>
          {rule.description}
        </Text>
        <Group gap={8} mt={2} wrap="nowrap">
          {rule.kind === 'form' && <Text size="xs" c="dimmed">{protocolLabel[rule.protocol]}{floating ? ` · ${[...rule.interfaces.map((i) => ifaceName(model, i)), ...(rule.groups ?? [])].join(', ') || 'any interface'}` : ''}</Text>}
          <Markers rule={rule} model={model} />
        </Group>
      </Table.Td>
      {pf ? (
        <Table.Td colSpan={3}>
          <Text className="mono" size="xs" c={dim} style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
            {ruleText(rule, model)}
          </Text>
        </Table.Td>
      ) : (
        rule.kind === 'form' && (
          <>
            <Table.Td><Text size="sm" c={dim}>{endpointLabel(rule.source, model)}{rule.sourcePort ? <Text span c="dimmed" size="xs"> :{rule.sourcePort}</Text> : null}</Text></Table.Td>
            <Table.Td><Text size="sm" c={dim}>{endpointLabel(rule.destination, model)}</Text></Table.Td>
            <Table.Td><Mono c={dim}>{portLabel(rule.port)}</Mono></Table.Td>
          </>
        )
      )}
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

function SystemRow({ action, description, source, destination, port, pf, showPf, to }: {
  action: 'pass' | 'block'; description: string; source: string; destination: string; port?: string; pf: string; showPf: boolean; to: string;
}) {
  return (
    <Table.Tr style={{ background: 'var(--opf-bg)' }}>
      <Table.Td pr={0}>
        <Tooltip label="Built in. Change it where it’s set.">
          <IconLock size={16} color="var(--mantine-color-dimmed)" style={{ marginLeft: 6 }} />
        </Tooltip>
      </Table.Td>
      <Table.Td />
      <Table.Td><ActionBadge action={action} muted /></Table.Td>
      <Table.Td>
        <Anchor component={Link} to={to} size="sm" c="dimmed" underline="hover">{description}</Anchor>
      </Table.Td>
      {showPf ? (
        <Table.Td colSpan={3}><Text className="mono" size="xs" c="dimmed">{pf}</Text></Table.Td>
      ) : (
        <>
          <Table.Td><Text size="sm" c="dimmed">{source}</Text></Table.Td>
          <Table.Td><Text size="sm" c="dimmed">{destination}</Text></Table.Td>
          <Table.Td style={{ whiteSpace: 'nowrap' }}><Mono c="dimmed">{port ?? 'Any'}</Mono></Table.Td>
        </>
      )}
      <Table.Td />
      <Table.Td />
    </Table.Tr>
  );
}

export function FirewallRules() {
  const { iface: param } = useParams();
  const navigate = useNavigate();
  const { staged, edit } = useStore();
  const [showPf, setShowPf] = usePref('opf.rules.showPf', false);
  const ifaces = staged.interfaces;
  const floating = param === FLOATING;
  const current = floating ? null : ifaces.find((i) => i.id === param) ?? ifaces.find((i) => i.role === 'lan') ?? ifaces[0];
  const tab = floating ? FLOATING : current!.id;
  const inTab = (r: Rule) => (floating ? isFloating(r) : !isFloating(r) && r.interfaces[0] === current!.id);
  const rules = staged.firewall.rules.filter(inTab);
  const tabName = floating ? 'floating' : current!.name;
  const [drawer, setDrawer] = useState<{ open: boolean; rule: Rule | null }>({ open: false, rule: null });
  const sensors = useSensors(useSensor(PointerSensor, { activationConstraint: { distance: 4 } }), useSensor(KeyboardSensor, { coordinateGetter: sortableKeyboardCoordinates }));

  const setRules = (summary: string, fn: (rules: Rule[]) => Rule[]) =>
    edit('firewall', summary, (m) => ({ ...m, firewall: { ...m.firewall, rules: fn(m.firewall.rules) } }));

  const onDragEnd = ({ active, over }: DragEndEvent) => {
    if (!over || active.id === over.id) return;
    const moved = rules.find((r) => r.id === active.id)!;
    setRules(`Moved rule “${moved.description}” (${tabName})`, (all) => arrayMove(all, all.findIndex((r) => r.id === active.id), all.findIndex((r) => r.id === over.id)));
  };

  const where = (r: RuleInput) => (isFloating(r) ? '(floating)' : `on ${ifaceName(staged, r.interfaces[0])}`);

  const save = (r: RuleInput) => {
    const existing = drawer.rule;
    if (existing) {
      setRules(`Edited rule “${r.description}” ${where(r)}`, (all) => all.map((x) => (x.id === existing.id ? ({ ...r, id: x.id } as Rule) : x)));
    } else {
      setRules(`Added ${r.kind === 'raw' ? 'pf ' : ''}rule “${r.description}” ${where(r)}`, (all) => [...all, { ...r, id: newId('r') } as Rule]);
    }
    const dest = isFloating(r) ? FLOATING : r.interfaces[0];
    if (dest !== tab) navigate(`/firewall/rules/${dest}`);
  };

  const wan = current?.role === 'wan' ? current : null;
  const lan = current?.role === 'lan' ? current : null;
  const opts = staged.firewall.options;

  return (
    <>
      <PageHeader
        title="Firewall rules"
        description="Rules are checked from top to bottom and, unless a rule says otherwise, the first match wins. Floating rules are checked before interface rules. Drag rules to reorder them."
        actions={
          <>
            <Switch label="Show as pf" checked={showPf} onChange={(e) => setShowPf(e.currentTarget.checked)} />
            <Button leftSection={<IconPlus size={16} />} onClick={() => setDrawer({ open: true, rule: null })}>Add rule</Button>
          </>
        }
      />
      <Tabs value={tab} onChange={(v) => v && navigate(`/firewall/rules/${v}`)} mb="md">
        <Tabs.List>
          <Tabs.Tab value={FLOATING} rightSection={<Badge size="sm" color="gray" circle>{staged.firewall.rules.filter(isFloating).length}</Badge>}>
            Floating
          </Tabs.Tab>
          {ifaces.map((i) => (
            <Tabs.Tab key={i.id} value={i.id} rightSection={<Badge size="sm" color="gray" circle>{staged.firewall.rules.filter((r) => !isFloating(r) && r.interfaces[0] === i.id).length}</Badge>}>
              {i.name}
            </Tabs.Tab>
          ))}
        </Tabs.List>
      </Tabs>

      {floating && (
        <Text size="sm" c="dimmed" mb="md">
          Floating rules apply to several interfaces, all of them, or outgoing traffic. They’re checked first, so they suit global blocks, priorities and tagging.
        </Text>
      )}

      <DndContext sensors={sensors} collisionDetection={closestCenter} onDragEnd={onDragEnd}>
        <Card padding={0}>
          <Table.ScrollContainer minWidth={920}>
            <Table highlightOnHover>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th />
                  <Table.Th>On</Table.Th>
                  <Table.Th>Action</Table.Th>
                  <Table.Th>Rule</Table.Th>
                  {showPf ? (
                    <Table.Th colSpan={3}>pf rule</Table.Th>
                  ) : (
                    <>
                      <Table.Th>From</Table.Th>
                      <Table.Th>To</Table.Th>
                      <Table.Th>Port</Table.Th>
                    </>
                  )}
                  <Table.Th ta="right">Matches</Table.Th>
                  <Table.Th />
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {lan && (
                  <SystemRow action="pass" description="Anti-lockout: always allow this web interface" source={`${lan.name} network`} destination={`${lan.name} address`} port="443, 22"
                    pf={`pass in quick on $${lan.id} proto tcp to ($${lan.id}) port { 443 22 }`} showPf={showPf} to={`/interfaces/${lan.id}`} />
                )}
                {wan?.blockPrivate && <SystemRow action="block" description="Block private networks" source="<private>" destination="Any" pf={`block in log quick on $${wan.id} from <private>`} showPf={showPf} to={`/interfaces/${wan.id}`} />}
                {wan?.blockBogons && <SystemRow action="block" description="Block bogon networks" source="<bogons>" destination="Any" pf={`block in log quick on $${wan.id} from <bogons>`} showPf={showPf} to={`/interfaces/${wan.id}`} />}
                {wan && staged.firewall.forwards.some((f) => f.enabled && f.iface === wan.id) && (
                  <SystemRow action="pass" description={`Port forwards (${staged.firewall.forwards.filter((f) => f.enabled && f.iface === wan.id).length})`} source="See NAT" destination="Forward targets" pf="pass in quick on $wan … rdr-to …" showPf={showPf} to="/firewall/nat" />
                )}
                  <SortableContext items={rules.map((r) => r.id)} strategy={verticalListSortingStrategy}>
                    {rules.map((r) => (
                      <RuleRow
                        key={r.id}
                        rule={r}
                        model={staged}
                        showPf={showPf}
                        floating={floating}
                        onEdit={() => setDrawer({ open: true, rule: r })}
                        onToggle={() => setRules(`${r.enabled ? 'Disabled' : 'Enabled'} rule “${r.description}” (${tabName})`, (all) => all.map((x) => (x.id === r.id ? { ...x, enabled: !x.enabled } : x)))}
                        onDuplicate={() => setRules(`Duplicated rule “${r.description}” (${tabName})`, (all) => {
                          const i = all.findIndex((x) => x.id === r.id);
                          return [...all.slice(0, i + 1), { ...r, id: newId('r'), description: `${r.description} (copy)` }, ...all.slice(i + 1)];
                        })}
                        onDelete={() => setRules(`Deleted rule “${r.description}” (${tabName})`, (all) => all.filter((x) => x.id !== r.id))}
                      />
                    ))}
                  </SortableContext>
                {rules.length === 0 && (
                  <Table.Tr>
                    <Table.Td colSpan={9}>
                      <Text size="sm" c="dimmed" ta="center" py="md">
                        {floating ? 'No floating rules.' : `No rules yet, so nothing new can come in on ${current!.name}.`}
                      </Text>
                    </Table.Td>
                  </Table.Tr>
                )}
                {!floating && (
                  <SystemRow action="block" description={`Default: block everything else${opts.logDefaultBlock ? ' (logged)' : ''}`} source="Any" destination="Any"
                    pf={opts.logDefaultBlock ? 'block log all' : 'block all'} showPf={showPf} to="/firewall/settings" />
                )}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        </Card>
      </DndContext>
      <Group justify="space-between" mt="sm">
        <Text size="xs" c="dimmed">Traffic this firewall sends, and replies to allowed connections, are always let through.</Text>
        <Anchor component={Link} to="/firewall/ruleset" size="xs">View the complete ruleset</Anchor>
      </Group>

      <RuleDrawer
        opened={drawer.open}
        onClose={() => setDrawer({ open: false, rule: drawer.rule })}
        model={staged}
        rule={drawer.rule}
        iface={floating ? null : current!.id}
        onSave={save}
      />
    </>
  );
}
