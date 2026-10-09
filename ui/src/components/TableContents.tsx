// What pf's table aliases hold now: a table's addresses in a drawer
// (searched, a page at a time; a dynamic table's taken out, added to or
// emptied by an operator), and an address looked up across every table.
import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router';
import { ActionIcon, Alert, Anchor, Badge, Button, Card, Drawer, Group, Stack, Table, Text, TextInput, Tooltip } from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { IconPlus, IconRefresh, IconSearch, IconTrash } from '@tabler/icons-react';
import { backend, useStore } from '../model/store';
import { ruleLink } from '../lib/aliasUsers';
import { useRole } from '../lib/session';
import { formatAgo, formatDuration, formatLogTime, minutesText } from '../lib/format';
import { isCIDR, isIPv4 } from '../lib/ip';
import type { TableEntriesResource, TableFindResource, TableRuleRef } from '../lib/api';
import { Empty, Mono, SectionTitle } from './ui';

const PAGE = 100;
const POLL_MS = 15_000;

const errorText = (e: unknown) => (e instanceof Error ? e.message : String(e));

function Added({ at, expires }: { at?: string; expires?: string }) {
  if (!at) return null;
  const ago = (Date.now() - new Date(at).getTime()) / 1000;
  const left = expires ? (new Date(expires).getTime() - Date.now()) / 1000 : undefined;
  return (
    <Text size="xs" c="dimmed">
      <Tooltip label={new Date(at).toLocaleString()}><span>added {formatAgo(Math.max(0, ago))}</span></Tooltip>
      {left !== undefined && <> · {left > 0 ? `out in ${formatDuration(left)}` : 'out within the minute'}</>}
    </Text>
  );
}

function RuleLinks({ rules }: { rules: TableRuleRef[] }) {
  const { staged } = useStore();
  return (
    <>
      {rules.map((r, i) => (
        <span key={r.id}>
          {i > 0 && ', '}
          <Anchor component={Link} to={ruleLink(staged, r.id)} size="xs">{r.description || r.id}</Anchor>
        </span>
      ))}
    </>
  );
}

/** A table alias's addresses now, in a drawer; table is the alias's name. */
export function TableDrawer({ table, onClose }: { table?: string; onClose: () => void }) {
  const { canOperate } = useRole();
  const [q, setQ] = useState('');
  const [query, setQuery] = useState('');
  const [limit, setLimit] = useState(PAGE);
  const [data, setData] = useState<TableEntriesResource>();
  const [error, setError] = useState<string>();
  const [adding, setAdding] = useState('');
  const [busy, setBusy] = useState(false);
  const [confirmFlush, setConfirmFlush] = useState(false);
  const [tick, setTick] = useState(0);

  useEffect(() => { setQ(''); setQuery(''); setLimit(PAGE); setData(undefined); setError(undefined); setConfirmFlush(false); }, [table]);
  useEffect(() => {
    const t = setTimeout(() => setQuery(q.trim()), 300);
    return () => clearTimeout(t);
  }, [q]);
  useEffect(() => {
    if (!table) return;
    let live = true;
    const load = () => {
      if (document.hidden) return;
      backend.tableEntries(table, query, 0, limit).then((d) => { if (live) { setData(d); setError(undefined); } }, (e) => live && setError(errorText(e)));
    };
    load();
    const t = setInterval(load, POLL_MS);
    return () => { live = false; clearInterval(t); };
  }, [table, query, limit, tick]);

  const change = useCallback(async (op: 'add' | 'delete' | 'flush', addresses: string[] = []) => {
    if (!table) return;
    setBusy(true);
    try {
      await backend.tableChange(table, op, addresses);
      notifications.show({ color: 'teal', message: op === 'flush' ? `Emptied <${table}>` : op === 'add' ? `Added ${addresses.join(', ')} to <${table}>` : `Took ${addresses.join(', ')} out of <${table}>` });
      setAdding('');
      setConfirmFlush(false);
      setTick((n) => n + 1);
    } catch (e) {
      notifications.show({ color: 'red', title: 'pf didn’t take the change', message: errorText(e) });
    } finally {
      setBusy(false);
    }
  }, [table]);

  const dynamic = data?.kind === 'dynamic';
  const addOk = isIPv4(adding.trim()) || isCIDR(adding.trim());
  return (
    <Drawer opened={!!table} onClose={onClose} position="right" size="lg" title={table && <Text fw={600} className="mono">&lt;{table}&gt;</Text>}>
      {error && <Alert color="red" variant="light" mb="md">{error}</Alert>}
      {!data && !error && <Text size="sm" c="dimmed">Reading pf’s table…</Text>}
      {data && (
        <Stack gap="md">
          <Text size="sm" c="dimmed">
            {dynamic ? 'Filled at runtime' : 'A downloaded list'}
            {data.filledBy.length > 0 && <> by <RuleLinks rules={data.filledBy} /></>}
            {dynamic && <> · {data.expireMinutes ? `each address taken out ${minutesText(data.expireMinutes)} after it was added` : 'addresses stay until it’s emptied or the firewall restarts'}</>}
          </Text>
          {!data.loaded && <Alert color="gray" variant="light">pf doesn’t have this table yet. Apply the change that adds this alias.</Alert>}
          {data.loaded && (
            <>
              <Group gap="sm" align="flex-end">
                <TextInput
                  placeholder="Search"
                  leftSection={<IconSearch size={16} />}
                  value={q}
                  onChange={(e) => setQ(e.currentTarget.value)}
                  style={{ flex: 1 }}
                />
                <Tooltip label="Read it again">
                  <ActionIcon variant="default" size="lg" aria-label="Read it again" onClick={() => setTick((n) => n + 1)}><IconRefresh size={16} /></ActionIcon>
                </Tooltip>
              </Group>
              {dynamic && canOperate && (
                <Group gap="sm" align="flex-start">
                  <TextInput
                    placeholder="Add an address or network by hand"
                    value={adding}
                    onChange={(e) => setAdding(e.currentTarget.value)}
                    onKeyDown={(e) => { if (e.key === 'Enter' && addOk) change('add', [adding.trim()]); }}
                    error={adding.trim() && !addOk ? 'An IPv4 address or network' : undefined}
                    style={{ flex: 1 }}
                  />
                  <Button variant="light" leftSection={<IconPlus size={16} />} disabled={!addOk || busy} onClick={() => change('add', [adding.trim()])}>Add</Button>
                </Group>
              )}
              <Text size="xs" c="dimmed">
                {data.total.toLocaleString()} {data.total === 1 ? 'entry' : 'entries'}
                {query ? `, ${data.matching.toLocaleString()} matching` : ''}
                {dynamic ? ', newest first' : ''}
              </Text>
              <Card withBorder padding={0}>
                {data.entries.length ? (
                  <Table verticalSpacing={6}>
                    <Table.Tbody>
                      {data.entries.map((e) => (
                        <Table.Tr key={(e.negated ? '!' : '') + e.address}>
                          <Table.Td>
                            <Group gap={6}>
                              <Mono>{e.address}</Mono>
                              {e.negated && <Tooltip label="An exception. These addresses aren’t in the table, even though a wider entry covers them."><Badge size="xs" color="gray">except</Badge></Tooltip>}
                            </Group>
                            <Added at={e.added} expires={e.expires} />
                          </Table.Td>
                          {dynamic && canOperate && (
                            <Table.Td w={44}>
                              <Tooltip label="Take it out now">
                                <ActionIcon variant="subtle" color="red" aria-label={`Take ${e.address} out`} disabled={busy} onClick={() => change('delete', [e.address])}><IconTrash size={16} /></ActionIcon>
                              </Tooltip>
                            </Table.Td>
                          )}
                        </Table.Tr>
                      ))}
                    </Table.Tbody>
                  </Table>
                ) : <Empty>{query ? 'Nothing matches.' : dynamic ? 'Empty. Nothing has been added.' : 'Empty.'}</Empty>}
              </Card>
              {data.matching > data.entries.length && (
                <Group justify="center">
                  <Button size="compact-sm" variant="subtle" onClick={() => setLimit((n) => Math.min(1000, n + PAGE))} disabled={limit >= 1000}>
                    {limit >= 1000 ? `Showing the first 1,000 of ${data.matching.toLocaleString()}. Search to find the rest.` : `Show ${Math.min(PAGE, data.matching - data.entries.length)} more`}
                  </Button>
                </Group>
              )}
              {dynamic && canOperate && data.total > 0 && (
                <Group justify="flex-end">
                  {confirmFlush ? (
                    <>
                      <Text size="sm">Take all {data.total.toLocaleString()} out now?</Text>
                      <Button variant="default" size="compact-sm" onClick={() => setConfirmFlush(false)}>Cancel</Button>
                      <Button color="red" size="compact-sm" loading={busy} onClick={() => change('flush')}>Empty it</Button>
                    </>
                  ) : <Button variant="subtle" color="red" size="compact-sm" onClick={() => setConfirmFlush(true)}>Empty the table</Button>}
                </Group>
              )}
            </>
          )}
        </Stack>
      )}
    </Drawer>
  );
}

/** Looks an address up in every table alias: which hold it, and why. */
export function FindInTables({ onOpen }: { onOpen: (table: string) => void }) {
  const { canOperate } = useRole();
  const [addr, setAddr] = useState('');
  const [res, setRes] = useState<TableFindResource>();
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const find = async (a = addr.trim()) => {
    if (!a) return;
    setBusy(true);
    setError(undefined);
    try {
      setRes(await backend.tableFind(a));
    } catch (e) {
      setRes(undefined);
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };
  const takeOut = async (table: string, entry: string) => {
    try {
      await backend.tableChange(table, 'delete', [entry]);
      notifications.show({ color: 'teal', message: `Took ${entry} out of <${table}>` });
      find(res?.address);
    } catch (e) {
      notifications.show({ color: 'red', title: 'pf didn’t take the change', message: errorText(e) });
    }
  };
  return (
    <Card mb="md">
      <SectionTitle>Find an address in the tables</SectionTitle>
      <Group gap="sm" align="flex-start">
        <TextInput
          placeholder="203.0.113.9"
          leftSection={<IconSearch size={16} />}
          value={addr}
          onChange={(e) => setAddr(e.currentTarget.value)}
          onKeyDown={(e) => { if (e.key === 'Enter') find(); }}
          error={error}
          style={{ flex: '1 1 240px' }}
          aria-label="Address to find"
        />
        <Button variant="light" loading={busy} disabled={!addr.trim()} onClick={() => find()}>Find</Button>
      </Group>
      {res && (
        <Stack gap={6} mt="sm">
          {res.tables.length === 0 ? (
            <Text size="sm" c="dimmed">{res.address} isn’t in any table alias now.</Text>
          ) : res.tables.map((t) => (
            <Group key={t.table} justify="space-between" wrap="nowrap" align="flex-start">
              <div>
                <Text size="sm">
                  <Anchor component="button" type="button" className="mono" onClick={() => onOpen(t.table)}>&lt;{t.table}&gt;</Anchor>
                  {' '}has it{t.entry !== res.address ? <> as <Mono>{t.entry}</Mono></> : ''}
                  {t.kind === 'list' ? ' (a downloaded list)' : ''}
                </Text>
                {t.added && <Text size="xs" c="dimmed">added {formatLogTime(t.added)}{t.expires ? `, out ${formatLogTime(t.expires)}` : ''}</Text>}
                <Text size="xs" c="dimmed">{t.usedBy.length ? <>used by <RuleLinks rules={t.usedBy} /></> : 'No rule uses this table, so it has no effect.'}</Text>
              </div>
              {t.kind === 'dynamic' && canOperate && t.entry === res.address && (
                <Button size="compact-sm" variant="subtle" color="red" onClick={() => takeOut(t.table, t.entry)}>Take it out</Button>
              )}
            </Group>
          ))}
          {res.errors.map((e) => <Text key={e} size="xs" c="red">{e}</Text>)}
        </Stack>
      )}
    </Card>
  );
}
