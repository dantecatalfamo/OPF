import type { ReactNode } from 'react';
import { Stack, Text, Tooltip } from '@mantine/core';
import { stateExplain } from '../lib/connections';

/** A connection's state with what it means on hover, and pf's own names
 *  under that for those who know them. */
export function StateTip({ state, direction, opener, other, children }: {
  state: string;
  /** The state's direction, as pf has it: which end its pair names first. */
  direction: 'in' | 'out';
  opener?: string;
  other?: string;
  children: ReactNode;
}) {
  return (
    <Tooltip
      multiline
      w={320}
      label={
        <Stack gap={4}>
          <Text size="xs">{stateExplain(state, direction, opener, other)}</Text>
          <Text size="xs" c="dimmed">
            <span className="mono">pf: {state}</span>. pfctl prints {direction === 'out' ? 'the end that opened the connection' : 'the end the connection was opened to'} first.
          </Text>
        </Stack>
      }
    >
      <span>{children}</span>
    </Tooltip>
  );
}
