// Where a downloaded list stands: when it was downloaded, how many
// entries it has, when it's downloaded next, and what went wrong last
// time, if anything. Pf URL aliases and DNS blocklists share it.
import { Text, Tooltip } from '@mantine/core';
import type { RefreshState } from '../lib/api';
import { formatAgo, formatDuration } from '../lib/format';

export function ListState({ applied, fetched, count, refresh }: {
  /** Whether the applied configuration has the list; if not, it's downloaded when applied. */
  applied: boolean;
  fetched?: string;
  /** "1,234 entries", say. */
  count?: string;
  refresh?: RefreshState;
}) {
  if (!applied) return <Text size="xs" c="dimmed">Downloaded when you apply it</Text>;
  const now = Date.now();
  const next = refresh?.next ? Date.parse(refresh.next) - now : undefined;
  const nextText = next === undefined ? '' : next <= 60_000 ? ' · downloading again shortly' : ` · again in ${formatDuration(next / 1000)}`;
  return (
    <>
      {fetched ? (
        <Text size="xs" c="dimmed">{count ? `${count}, ` : ''}downloaded {formatAgo((now - Date.parse(fetched)) / 1000)}{nextText}</Text>
      ) : (
        <Text size="xs" c="dimmed">Not downloaded yet; it will be with the next change you apply</Text>
      )}
      {refresh?.lastError && (
        <Tooltip label={refresh.lastError} multiline w={320}>
          <Text size="xs" c="yellow">
            The last download failed{refresh.lastAttempt ? ` ${formatAgo((now - Date.parse(refresh.lastAttempt)) / 1000)}` : ''}{fetched ? '; the list already here is still in use' : ''}
          </Text>
        </Tooltip>
      )}
    </>
  );
}
