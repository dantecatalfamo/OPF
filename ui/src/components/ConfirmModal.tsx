import { Anchor, Button, Center, Group, Modal, RingProgress, Stack, Text, Title } from '@mantine/core';
import { useStore } from '../model/store';
import { useNow } from '../lib/useNow';

export function ConfirmModal({ opened, onClose }: { opened: boolean; onClose: () => void }) {
  const { confirming, keep, revert } = useStore();
  const now = useNow(200);
  if (!confirming) return null;
  const left = Math.max(0, (confirming.deadline - now) / 1000);
  const total = Math.max(1, (confirming.deadline - confirming.start) / 1000);

  return (
    <Modal opened={opened} onClose={onClose} closeOnClickOutside={false} size="md" withCloseButton={false}>
      <Stack align="center" gap="md" py="sm">
        <RingProgress
          size={132}
          thickness={9}
          roundCaps
          sections={[{ value: (left / total) * 100, color: left < 15 ? 'red' : 'amber' }]}
          label={
            <Center>
              <Stack gap={0} align="center">
                <Text fw={600} size="xl" className="num">
                  {Math.ceil(left)}
                </Text>
                <Text size="xs" c="dimmed">
                  seconds
                </Text>
              </Stack>
            </Center>
          }
        />
        {confirming.move ? (
          <>
            <Title order={3} ta="center">
              Keep them from the new address
            </Title>
            <Text ta="center" c="dimmed" size="sm" maw={380}>
              {confirming.move.url ? (
                <>
                  {confirming.move.name} has moved, so this page can’t reach OPF any more. Open{' '}
                  <Anchor href={confirming.move.url} target="_blank" className="mono">{confirming.move.url}</Anchor>,
                  sign in, and keep the changes there. If you can’t, do nothing: the previous settings come back when
                  the timer runs out, and this page with them.
                </>
              ) : (
                <>
                  {confirming.move.name} {confirming.move.dhcp ? 'now gets its address by DHCP' : 'has no address now'}, so this page can’t reach OPF any more. Keep the
                  changes from wherever you can reach it, or do nothing: the previous settings come back when the
                  timer runs out, and this page with them.
                </>
              )}
            </Text>
            {confirming.move.url && (
              <Button component="a" href={confirming.move.url} target="_blank" fullWidth mt="xs">
                Open {confirming.move.url}
              </Button>
            )}
          </>
        ) : (
          <>
            <Title order={3} ta="center">
              Can you still reach OPF?
            </Title>
            <Text ta="center" c="dimmed" size="sm" maw={360}>
              The new settings are active. If this page is still working, keep them. Otherwise do nothing and the
              previous settings come back when the timer runs out.
            </Text>
            <Group grow w="100%" mt="xs">
              <Button variant="default" onClick={revert}>
                Revert now
              </Button>
              <Button onClick={keep}>Keep changes</Button>
            </Group>
          </>
        )}
        <Button variant="subtle" size="xs" color="gray" onClick={onClose}>
          Decide later
        </Button>
      </Stack>
    </Modal>
  );
}
