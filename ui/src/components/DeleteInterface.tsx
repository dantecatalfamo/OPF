import { Alert, Badge, Button, Group, List, Modal, Stack, Text } from '@mantine/core';
import { IconAlertTriangle } from '@tabler/icons-react';
import { useStore } from '../model/store';
import type { Iface } from '../model/types';
import { cannotDelete, interfaceDependents, withoutInterface, type Dependent } from '../lib/removeInterface';

const effectLabel: Record<Dependent['effect'], { label: string; color: string }> = {
  deleted: { label: 'deleted', color: 'red' },
  changed: { label: 'changed', color: 'amber' },
  edit: { label: 'needs editing', color: 'yellow' },
};

// Deleting a VLAN or a tunnel, and everything that refers to it, after
// showing what that is.
export function DeleteInterface({ iface, kind, opened, onClose, onDeleted }: {
  iface: Iface;
  kind: string; // "VLAN network", "WireGuard tunnel"
  opened: boolean;
  onClose: () => void;
  onDeleted: () => void;
}) {
  const { staged, edit } = useStore();
  const blocked = cannotDelete(staged, iface.id);
  const deps = interfaceDependents(staged, iface.id);
  const toEdit = deps.filter((d) => d.effect === 'edit');

  const remove = () => {
    const others = deps.filter((d) => d.effect !== 'edit').length;
    edit('interfaces', `Deleted ${kind} “${iface.name}” (${iface.device})${others ? `, and ${others} thing${others === 1 ? '' : 's'} that used it` : ''}`, (m) => withoutInterface(m, iface.id));
    onClose();
    onDeleted();
  };

  return (
    <Modal opened={opened} onClose={onClose} title={<Text fw={600}>Delete {iface.name}?</Text>} size="lg">
      <Stack>
        {blocked ? (
          <Alert color="red" variant="light" icon={<IconAlertTriangle size={18} />}>{blocked}</Alert>
        ) : (
          <>
            <Text size="sm">
              {iface.device} is removed from the system when you apply this, along with its settings.
              {deps.length === 0 && ' Nothing else uses it.'}
            </Text>
            {deps.length > 0 && (
              <>
                <Text size="sm" fw={500}>These use it and go or change with it:</Text>
                <List spacing={6} size="sm">
                  {deps.map((d, i) => (
                    <List.Item key={i}>
                      <Group gap={6} wrap="nowrap" align="flex-start">
                        <Badge size="xs" variant="light" color={effectLabel[d.effect].color}>{effectLabel[d.effect].label}</Badge>
                        <Text size="sm">{d.what}{d.detail && <Text span c="dimmed" size="sm">: {d.detail}</Text>}</Text>
                      </Group>
                    </List.Item>
                  ))}
                </List>
              </>
            )}
            {toEdit.length > 0 && (
              <Alert color="yellow" variant="light" p="sm" icon={<IconAlertTriangle size={16} />}>
                OPF can’t change pf text you wrote yourself. Edit {toEdit.length === 1 ? 'it' : 'them'} before applying, or the check
                of the new rules will refuse the change.
              </Alert>
            )}
            <Text size="xs" c="dimmed">Nothing changes until you review and apply, and a commit can be reverted from Change history.</Text>
          </>
        )}
        <Group justify="flex-end">
          <Button variant="default" onClick={onClose}>Cancel</Button>
          {!blocked && <Button color="red" onClick={remove}>Delete {iface.name}</Button>}
        </Group>
      </Stack>
    </Modal>
  );
}
