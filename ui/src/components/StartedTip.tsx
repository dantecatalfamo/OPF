// The moment something began, on hover over how long it's been: a
// machine's uptime, a connection's age.
import type { ReactNode } from 'react';
import { Tooltip } from '@mantine/core';

const exact = (d: Date) => d.toLocaleString(undefined, { weekday: 'short', year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' });

/** Shows `label` ("Up since", "Started") and the exact time on hover;
 *  `at` is the moment, or `ageSec` how long ago it was. */
export function StartedTip({ at, ageSec, label = 'Started', children }: { at?: Date | string; ageSec?: number; label?: string; children: ReactNode }) {
  const d = at !== undefined ? new Date(at) : new Date(Date.now() - (ageSec ?? 0) * 1000);
  if (Number.isNaN(d.getTime())) return <>{children}</>;
  return (
    <Tooltip label={`${label} ${exact(d)}`}>
      <span style={{ cursor: 'default' }}>{children}</span>
    </Tooltip>
  );
}
