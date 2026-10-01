// DNS resolver › Local names: host names and the other records the
// resolver answers itself, and how each local domain answers names it
// has no record for. The firewall checks everything again; the checks
// here are for saying what's wrong while typing.
import { Fragment, useEffect, useMemo, useState } from 'react';
import { ActionIcon, Anchor, Badge, Button, Group, Menu, Modal, NumberInput, Select, Stack, Table, Text, TextInput, Textarea, Tooltip } from '@mantine/core';
import { useForm } from '@mantine/form';
import { IconChevronDown, IconSettings, IconTrash } from '@tabler/icons-react';
import { Link } from 'react-router';
import { newId, useStore } from '../model/store';
import type { DnsRecord, DnsRecordType, DnsZone, Model } from '../model/types';
import { Mono, SectionTitle } from '../components/ui';

type Kind = 'host' | 'firewall' | DnsRecordType;

const kinds: { kind: Kind; label: string; badge: string; about: string }[] = [
  { kind: 'host', label: 'Host name', badge: 'Host', about: 'A name for an address: devices using OPF for DNS find it by name.' },
  { kind: 'firewall', label: 'The firewall', badge: 'Firewall', about: '' },
  { kind: 'CNAME', label: 'Alias', badge: 'Alias', about: 'Another name for a name that exists already.' },
  { kind: 'MX', label: 'Mail server', badge: 'Mail', about: 'Where mail for a domain goes (MX).' },
  { kind: 'TXT', label: 'Text', badge: 'Text', about: 'Text for programs to read: SPF, domain verification (TXT).' },
  { kind: 'SRV', label: 'Service', badge: 'Service', about: 'Where a service runs, for programs that look it up by name (SRV): _ipp._tcp for printers, _sip._tcp for phones.' },
  { kind: 'PTR', label: 'Reverse name', badge: 'Reverse', about: 'The name an address gives when a program asks what it’s called (PTR).' },
  { kind: 'CAA', label: 'Certificate authorities', badge: 'CA', about: 'Which certificate authorities may issue certificates for a name (CAA).' },
];
const kindOf = (k: Kind) => kinds.find((x) => x.kind === k)!;
const addTitle: Record<DnsRecordType, string> = { CNAME: 'Add an alias', MX: 'Add a mail server', TXT: 'Add text', SRV: 'Add a service', PTR: 'Add a reverse name', CAA: 'Say which certificate authorities may issue' };

const label = /^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$/i;
const hostLabel = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/i;
const isName = (s: string, labels = label) => s.length > 0 && s.length <= 253 && s.split('.').every((l) => labels.test(l));
const isHost = (s: string) => isName(s, hostLabel);
const isIP = (s: string) => /^(\d{1,3})(\.\d{1,3}){3}$/.test(s) ? s.split('.').every((n) => +n <= 255) : /^[0-9a-f:]+$/i.test(s) && s.includes(':') && s.split('::').length <= 2;
const safeText = (s: string) => /^[\x20-\x7e]*$/.test(s) && !/["'\\]/.test(s);
const lower = (s: string) => s.toLowerCase();

// The names this configuration gives addresses (host names, and
// reserved devices' when they're in DNS), as the firewall works out an
// alias to one of them.
function localAddresses(m: Model): Map<string, string[]> {
  const names = new Map<string, string[]>();
  const add = (n: string, ip: string) => {
    const a = names.get(lower(n)) ?? [];
    if (!a.includes(ip)) names.set(lower(n), [...a, ip]);
  };
  for (const o of m.dns.overrides) add(`${o.host}.${o.domain}`, o.ip);
  if (m.dns.registerReservations) for (const s of m.dhcp) for (const r of s.reservations) if (r.hostname) add(`${r.hostname}.${m.system.domain}`, r.ip);
  return names;
}

function zoneOf(m: Model, name: string): DnsZone | undefined {
  const n = lower(name);
  const zones: DnsZone[] = [...(m.dns.zones ?? []).filter((z) => lower(z.name) !== lower(m.system.domain)), { name: m.system.domain, type: systemZoneType(m) }];
  return zones.filter((z) => n === lower(z.name) || n.endsWith('.' + lower(z.name))).sort((a, b) => b.name.length - a.name.length)[0];
}
const systemZoneType = (m: Model) => (m.dns.zones ?? []).find((z) => lower(z.name) === lower(m.system.domain))?.type ?? 'static';

// What the resolver will do with an alias, or why it can't.
function aliasOutcome(m: Model, name: string, target: string): { ok: boolean; text: string } {
  const t = lower(target);
  if (!isHost(target)) return { ok: false, text: 'Enter a name like files.office.arpa' };
  if (t === lower(name)) return { ok: false, text: 'An alias can’t stand for itself' };
  const alias = (m.dns.records ?? []).find((r) => r.type === 'CNAME' && lower(r.name) === t);
  if (alias) return { ok: false, text: `${target} is an alias too; point at ${alias.value}` };
  const addrs = localAddresses(m).get(t);
  if (addrs) return { ok: true, text: `Answers with ${target}’s address, ${addrs.join(', ')}, and follows it if that changes.` };
  const z = zoneOf(m, t);
  if (z?.type === 'static') return { ok: false, text: `${target} has no address here: point at a host name or reserved device. A device’s name from its lease can’t be followed.` };
  return { ok: true, text: `The resolver looks ${target} up and answers with both. Names under the alias answer the same way.` };
}

// Why a record can't go at name, if it can't: an alias must be the only
// thing at its name.
function nameTaken(m: Model, type: DnsRecordType, name: string): string | null {
  const n = lower(name);
  const records = (m.dns.records ?? []).filter((r) => r.type !== 'PTR' && lower(r.name) === n);
  const alias = records.find((r) => r.type === 'CNAME');
  if (alias) return `${name} is an alias for ${alias.value}; an alias must be the only thing at its name`;
  if (type !== 'CNAME') return null;
  if (lower(`${m.system.hostname}.${m.system.domain}`) === n) return `${name} is the firewall’s own name`;
  if (n === lower(m.system.domain) || (m.dns.zones ?? []).some((z) => lower(z.name) === n)) return `${name} is a domain; an alias can’t be a domain itself`;
  if (localAddresses(m).has(n)) return `${name} is already a host name or reserved device`;
  if (records.length) return `${name} has other records; an alias must be the only thing at its name`;
  return null;
}

interface Row {
  key: string;
  name: string;
  kind: Kind;
  value: string;
  detail?: string;
  description?: string;
  /** Absent for the firewall's own name, which is the system's. */
  remove?: (m: Model) => Model;
  what: string;
}

function rows(m: Model): Row[] {
  const out: Row[] = [];
  // The firewall answers with its address on the network asking.
  const inside = m.interfaces.filter((i) => i.role !== 'wan' && i.ipv4.mode === 'static' && i.ipv4.address);
  if (m.system.hostname && m.system.domain && inside.length) {
    out.push({
      key: 'firewall', name: `${m.system.hostname}.${m.system.domain}`, kind: 'firewall',
      value: inside.map((i) => i.ipv4.address).join(', '),
      detail: 'the address on the network asking',
      description: 'The firewall itself',
      what: 'the firewall’s name',
    });
  }
  out.push(...m.dns.overrides.map((o): Row => ({
    key: o.id, name: `${o.host}.${o.domain}`, kind: 'host', value: o.ip, description: o.description,
    what: `host name ${o.host}.${o.domain}`,
    remove: (x) => ({ ...x, dns: { ...x.dns, overrides: x.dns.overrides.filter((y) => y.id !== o.id) } }),
  })));
  const local = localAddresses(m);
  for (const r of m.dns.records ?? []) {
    let value = r.value;
    let detail: string | undefined;
    switch (r.type) {
      case 'CNAME': {
        const a = local.get(lower(r.value));
        detail = a ? `answers with ${a.join(', ')}` : 'looked up, then answered with both';
        break;
      }
      case 'MX': value = `${r.priority ?? 0} ${r.value}`; break;
      case 'SRV': value = r.value === '.' ? 'Not offered here' : `${r.value} port ${r.port}`; detail = `priority ${r.priority ?? 0}, weight ${r.weight ?? 0}`; break;
      case 'CAA': value = `${r.tag} ${r.value}`; break;
    }
    if (r.ttl !== undefined) detail = [detail, `kept ${r.ttl} s`].filter(Boolean).join(' · ');
    out.push({
      key: r.id, name: r.name, kind: r.type, value, detail, description: r.description,
      what: `${kindOf(r.type).label.toLowerCase()} ${r.name}`,
      remove: (x) => ({ ...x, dns: { ...x.dns, records: (x.dns.records ?? []).filter((y) => y.id !== r.id) } }),
    });
  }
  // Grouped by domain, then by name, so a domain's records sit together.
  const sortKey = (r: Row) => (r.kind === 'PTR' ? '~' + r.name : r.name.split('.').reverse().join('.'));
  return out.sort((a, b) => sortKey(a).localeCompare(sortKey(b)) || a.kind.localeCompare(b.kind));
}

// Names grouped by domain, each domain headed by what happens to a name
// in it that isn't listed: so the rule sits on top of the names it's
// about. Names in a domain without a rule of its own are grouped by the
// domain they're in, looked up on the internet as usual; choosing
// "don't exist" there gives the domain its rule.
interface DomainGroup {
  domain: string;
  /** In the configuration's zones (the firewall's domain always is). */
  declared: boolean;
  system: boolean;
  type: DnsZone['type'];
  reverse?: boolean;
  rows: Row[];
}

function groups(m: Model, list: Row[]): DomainGroup[] {
  const sys = m.system.domain;
  const declared = new Map<string, DomainGroup>();
  declared.set(lower(sys), { domain: sys, declared: true, system: true, type: systemZoneType(m), rows: [] });
  for (const z of m.dns.zones ?? []) {
    if (lower(z.name) !== lower(sys)) declared.set(lower(z.name), { domain: z.name, declared: true, system: false, type: z.type, rows: [] });
  }
  const others = new Map<string, DomainGroup>();
  const reverse: DomainGroup = { domain: 'Reverse names', declared: false, system: false, type: 'transparent', reverse: true, rows: [] };
  for (const r of list) {
    if (r.kind === 'PTR') {
      reverse.rows.push(r);
      continue;
    }
    const z = zoneOf(m, r.name);
    if (z && declared.has(lower(z.name))) {
      declared.get(lower(z.name))!.rows.push(r);
      continue;
    }
    const parent = r.name.split('.').slice(1).join('.') || r.name;
    if (!others.has(lower(parent))) others.set(lower(parent), { domain: parent, declared: false, system: false, type: 'transparent', rows: [] });
    others.get(lower(parent))!.rows.push(r);
  }
  const byName = (a: DomainGroup, b: DomainGroup) => a.domain.localeCompare(b.domain);
  const [first, ...rest] = [...declared.values()];
  return [first, ...rest.sort(byName), ...[...others.values()].sort(byName), ...(reverse.rows.length ? [reverse] : [])];
}

// The choice, as the end of "Names here that aren't listed …".
const unlisted: { value: DnsZone['type']; label: string }[] = [
  { value: 'static', label: 'don’t exist' },
  { value: 'transparent', label: 'are looked up on the internet' },
];
const unlistedExample = (type: DnsZone['type'], domain: string) =>
  type === 'static' ? `A device asking for anything else in ${domain} is told there’s no such name.` : `Anything else in ${domain} is looked up on the internet, as usual.`;

export function LocalNames() {
  const { staged, edit } = useStore();
  const [adding, setAdding] = useState<Kind | 'domain' | null>(null);
  const list = useMemo(() => rows(staged), [staged]);
  const grouped = useMemo(() => groups(staged, list), [staged, list]);
  const setType = (g: DomainGroup, type: DnsZone['type']) => {
    if (type === g.type) return;
    const what = `${g.domain}: names not listed ${type === 'static' ? 'don’t exist' : 'are looked up on the internet'}`;
    edit('dns', what, (m) => {
      const rest = (m.dns.zones ?? []).filter((x) => lower(x.name) !== lower(g.domain));
      // The firewall's domain is "don't exist" unless listed.
      const keep = g.system && type === 'static' ? rest : [...rest, { name: g.domain, type }];
      return { ...m, dns: { ...m.dns, zones: keep.length ? keep : undefined } };
    });
  };
  const removeDomain = (g: DomainGroup) =>
    edit('dns', `Removed the rule for ${g.domain}`, (m) => {
      const zs = (m.dns.zones ?? []).filter((x) => lower(x.name) !== lower(g.domain));
      return { ...m, dns: { ...m.dns, zones: zs.length ? zs : undefined } };
    });
  return (
    <>
      <SectionTitle
        right={
          <Menu position="bottom-end" withinPortal>
            <Menu.Target>
              <Button size="xs" variant="light" rightSection={<IconChevronDown size={14} />}>Add</Button>
            </Menu.Target>
            <Menu.Dropdown>
              {kinds.filter((k) => k.kind !== 'firewall').map((k) => (
                <Menu.Item key={k.kind} onClick={() => setAdding(k.kind)}>
                  <Text size="sm">{k.label}</Text>
                </Menu.Item>
              ))}
              <Menu.Divider />
              <Menu.Item onClick={() => setAdding('domain')}>
                <Text size="sm">Domain</Text>
              </Menu.Item>
            </Menu.Dropdown>
          </Menu>
        }
      >
        Local names
      </SectionTitle>
      <Table.ScrollContainer minWidth={640}>
        <Table verticalSpacing={6}>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Name</Table.Th>
              <Table.Th>Type</Table.Th>
              <Table.Th w="34%">Answer</Table.Th>
              <Table.Th w="26%">Description</Table.Th>
              <Table.Th w={40} />
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {grouped.map((g) => (
              <Fragment key={g.domain}>
                <Table.Tr style={{ background: 'var(--mantine-color-default-hover)' }}>
                  <Table.Td colSpan={5} py="sm">
                    <Group justify="space-between" align="flex-start" gap="sm">
                      <div>
                        <Text fw={600} className={g.reverse ? undefined : 'mono'} size="sm">{g.domain}</Text>
                        {g.system && (
                          <Text size="xs" c="dimmed">
                            The firewall’s domain, set in <Anchor component={Link} to="/system/general" size="xs">System › General</Anchor>
                          </Text>
                        )}
                        {g.reverse && <Text size="xs" c="dimmed">The name an address gives when a program asks what it’s called.</Text>}
                      </div>
                      {!g.reverse && (
                        <Group gap="xs" wrap="nowrap" align="flex-start">
                            <Text size="sm" c="dimmed" mt={4}>Names here that aren’t listed</Text>
                            {/* What the choice means, right under it. */}
                            <Select size="xs" w={280} data={unlisted} value={g.type} allowDeselect={false} disabled={!g.declared && !isHost(g.domain)}
                              description={unlistedExample(g.type, g.domain)} inputWrapperOrder={['input', 'description']}
                              styles={{ description: { marginTop: 4, fontSize: 'var(--mantine-font-size-xs)' } }}
                              onChange={(v) => v && setType(g, v as DnsZone['type'])} aria-label={`What happens to names in ${g.domain} that aren’t listed`} />
                            {g.declared && !g.system ? (
                              <Tooltip label="Forget this domain’s rule" withinPortal>
                                <ActionIcon variant="subtle" color="gray" aria-label={`Forget the rule for ${g.domain}`} onClick={() => removeDomain(g)}>
                                  <IconTrash size={16} />
                                </ActionIcon>
                              </Tooltip>
                            ) : <span style={{ width: 28 }} />}
                        </Group>
                      )}
                    </Group>
                  </Table.Td>
                </Table.Tr>
                {g.rows.length === 0 && (
                  <Table.Tr>
                    <Table.Td colSpan={5}><Text size="sm" c="dimmed">No names here yet.</Text></Table.Td>
                  </Table.Tr>
                )}
                {g.rows.map((r) => (
                  <Table.Tr key={r.key}>
                    <Table.Td style={{ whiteSpace: 'nowrap' }}>
                      <Mono>{r.name}</Mono>
                    </Table.Td>
                    <Table.Td style={{ whiteSpace: 'nowrap' }}><Badge size="sm" variant="light" color={r.kind === 'host' ? 'teal' : r.kind === 'firewall' ? 'blue' : 'gray'} styles={{ root: { overflow: 'visible' }, label: { overflow: 'visible' } }}>{kindOf(r.kind).badge}</Badge></Table.Td>
                    <Table.Td style={{ overflowWrap: 'anywhere' }}>
                      {/* Each address whole: a list breaks only between them. */}
                      <Mono>{r.value.split(', ').map((v, i, all) => <span key={i} style={{ whiteSpace: 'nowrap' }}>{v}{i < all.length - 1 ? ', ' : ''}</span>)}</Mono>
                      {r.detail && <Text size="xs" c="dimmed">{r.detail}</Text>}
                    </Table.Td>
                    <Table.Td><Text size="sm" c="dimmed">{r.description}</Text></Table.Td>
                    <Table.Td w={40}>
                      {r.remove ? (
                        <ActionIcon variant="subtle" color="gray" aria-label={`Remove ${r.what}`} onClick={() => edit('dns', `Removed ${r.what}`, r.remove!)}>
                          <IconTrash size={16} />
                        </ActionIcon>
                      ) : (
                        <Tooltip label="Its name is set in System › General" withinPortal>
                          <ActionIcon component={Link} to="/system/general" variant="subtle" color="gray" aria-label="Change the firewall’s name in System › General">
                            <IconSettings size={16} />
                          </ActionIcon>
                        </Tooltip>
                      )}
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Fragment>
            ))}
          </Table.Tbody>
        </Table>
      </Table.ScrollContainer>
      <HostModal opened={adding === 'host'} onClose={() => setAdding(null)} />
      <RecordModal type={adding && adding !== 'host' && adding !== 'firewall' && adding !== 'domain' ? adding : null} onClose={() => setAdding(null)} />
      <DomainModal opened={adding === 'domain'} onClose={() => setAdding(null)} taken={grouped.filter((g) => g.declared).map((g) => lower(g.domain))} />
    </>
  );
}

function DomainModal({ opened, onClose, taken }: { opened: boolean; onClose: () => void; taken: string[] }) {
  const { edit } = useStore();
  const form = useForm<{ name: string; type: DnsZone['type'] }>({
    initialValues: { name: '', type: 'static' },
    validate: {
      name: (v) => {
        const n = lower(v.trim().replace(/\.$/, ''));
        if (!isHost(n)) return 'Enter a domain like lab.example.com';
        if (/^((in-addr|ip6)\.)?arpa$/.test(n)) return 'That holds every reverse name; use a domain under it';
        return taken.includes(n) ? 'Already listed' : null;
      },
    },
  });
  useEffect(() => {
    if (opened) form.reset();
  }, [opened]); // form is stable
  return (
    <Modal opened={opened} onClose={onClose} title={<Text fw={600}>Add a domain</Text>}>
      <form
        onSubmit={form.onSubmit((v) => {
          const name = v.name.trim().replace(/\.$/, '');
          edit('dns', `Added a rule for ${name}: names not listed ${v.type === 'static' ? 'don’t exist' : 'are looked up on the internet'}`, (m) => ({ ...m, dns: { ...m.dns, zones: [...(m.dns.zones ?? []), { name, type: v.type }] } }));
          onClose();
        })}
      >
        <Stack>
          <TextInput label="Domain" placeholder="lab.example.com" data-autofocus spellCheck={false} {...form.getInputProps('name')} />
          <Select label="Names in it that aren’t listed" data={unlisted} allowDeselect={false}
            description={unlistedExample(form.values.type, form.values.name.trim() || 'it')}
            inputWrapperOrder={['label', 'input', 'description', 'error']} {...form.getInputProps('type')} />
          <Text size="xs" c="dimmed">“Don’t exist” suits a domain that only exists on your network. “Looked up on the internet” suits a real one, such as your company’s, when you only want to change a few of its names here.</Text>
          <Group justify="flex-end" mt="sm">
            <Button variant="default" onClick={onClose}>Cancel</Button>
            <Button type="submit">Add</Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}

function HostModal({ opened, onClose }: { opened: boolean; onClose: () => void }) {
  const { staged, edit } = useStore();
  const blank = { host: '', domain: staged.system.domain, ip: '', description: '' };
  const form = useForm({
    initialValues: blank,
    validate: {
      host: (v) => (hostLabel.test(v) ? null : 'Letters, digits and hyphens only'),
      domain: (v) => (isHost(v) ? null : 'Enter a domain like office.arpa'),
      ip: (v) => (isIP(v) ? null : 'Enter an IPv4 or IPv6 address'),
    },
  });
  useEffect(() => {
    if (opened) form.setValues(blank);
  }, [opened, staged.system.domain]); // form is stable
  return (
    <Modal opened={opened} onClose={onClose} title={<Text fw={600}>Add a host name</Text>}>
      <form
        onSubmit={form.onSubmit((v) => {
          edit('dns', `Added host name ${v.host}.${v.domain} → ${v.ip}`, (m) => ({ ...m, dns: { ...m.dns, overrides: [...m.dns.overrides, { id: newId('h'), ...v }] } }));
          onClose();
        })}
      >
        <Stack>
          <Text size="sm" c="dimmed">{kindOf('host').about}</Text>
          <Group grow align="flex-start">
            <TextInput label="Name" placeholder="nas" data-autofocus {...form.getInputProps('host')} />
            <TextInput label="Domain" {...form.getInputProps('domain')} />
          </Group>
          <TextInput label="Address" placeholder="192.168.1.20" {...form.getInputProps('ip')} />
          <TextInput label="Description" {...form.getInputProps('description')} />
          <Group justify="flex-end" mt="sm">
            <Button variant="default" onClick={onClose}>Cancel</Button>
            <Button type="submit">Add</Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}

interface RecordForm {
  name: string;
  value: string;
  priority: number | string;
  weight: number | string;
  port: number | string;
  tag: string;
  ttl: number | string;
  description: string;
}

const num = (v: number | string, lo: number, hi: number) => (typeof v === 'number' && Number.isInteger(v) && v >= lo && v <= hi ? null : `${lo} to ${hi}`);

function RecordModal({ type, onClose }: { type: DnsRecordType | null; onClose: () => void }) {
  const { staged, edit } = useStore();
  const domain = staged.system.domain;
  const blank = (t: DnsRecordType | null): RecordForm => ({
    name: t === 'MX' || t === 'TXT' || t === 'CAA' ? domain : '',
    value: '', priority: t === 'MX' ? 10 : 0, weight: 0, port: '', tag: 'issue', ttl: '', description: '',
  });
  const form = useForm<RecordForm>({
    initialValues: blank(type),
    validate: {
      name: (v) => {
        if (type === 'PTR') return !isIP(v) ? 'Enter an IPv4 or IPv6 address' : (staged.dns.records ?? []).some((r) => r.type === 'PTR' && lower(r.name) === lower(v)) ? `${v} already has a reverse name` : null;
        if (!isName(v) || v.startsWith('*')) return 'Enter a name like office.arpa or _sip._tcp.office.arpa';
        return type ? nameTaken(staged, type, v) : null;
      },
      value: (v, f) => {
        switch (type) {
          case 'CNAME': { const o = aliasOutcome(staged, f.name, v); return o.ok ? null : o.text; }
          case 'TXT': return !v ? 'Enter the text' : v.length > 2048 ? 'At most 2048 characters' : safeText(v) ? null : 'Plain ASCII only, without quotes or backslashes';
          case 'CAA': return !v ? 'Enter what it allows' : safeText(v) && !v.includes(' ') && v.length <= 255 ? null : 'No spaces, quotes or backslashes';
          case 'SRV': return v === '.' || isHost(v) ? null : 'Enter a host name, or . if the service isn’t offered';
          default: return isHost(v) ? null : 'Enter a host name';
        }
      },
      priority: (v) => (type === 'MX' || type === 'SRV' ? num(v, 0, 65535) : null),
      weight: (v) => (type === 'SRV' ? num(v, 0, 65535) : null),
      port: (v) => (type === 'SRV' ? num(v, 0, 65535) : null),
      ttl: (v) => (v === '' ? null : num(v, 0, 604800)),
    },
  });
  useEffect(() => {
    if (type) form.setValues(blank(type));
  }, [type, domain]); // form is stable
  if (!type) return null;
  const k = kindOf(type);
  const alias = type === 'CNAME' && form.values.value ? aliasOutcome(staged, form.values.name, form.values.value) : null;
  const valueLabel: Record<DnsRecordType, string> = { CNAME: 'Stands for', MX: 'Mail server', TXT: 'Text', SRV: 'Host', PTR: 'Name', CAA: 'Value' };
  const placeholder: Record<DnsRecordType, string> = { CNAME: `files.${domain}`, MX: 'mail.example.com', TXT: 'v=spf1 -all', SRV: `printer.${domain}`, PTR: `files.${domain}`, CAA: 'letsencrypt.org' };
  return (
    <Modal opened onClose={onClose} title={<Text fw={600}>{addTitle[type]}</Text>}>
      <form
        onSubmit={form.onSubmit((v) => {
          const r: DnsRecord = { id: newId('r'), name: v.name.trim().replace(/\.$/, ''), type, value: v.value.trim().replace(/(.)\.$/, '$1') };
          if (type === 'TXT') r.value = v.value;
          if (type === 'MX' || type === 'SRV') r.priority = Number(v.priority);
          if (type === 'SRV') { r.weight = Number(v.weight); r.port = Number(v.port); }
          if (type === 'CAA') r.tag = v.tag;
          if (v.ttl !== '') r.ttl = Number(v.ttl);
          if (v.description) r.description = v.description;
          const same = (x: DnsRecord) => x.type === r.type && lower(x.name) === lower(r.name) && lower(x.value) === lower(r.value) && (x.tag ?? '') === (r.tag ?? '') && (x.priority ?? 0) === (r.priority ?? 0) && (x.weight ?? 0) === (r.weight ?? 0) && (x.port ?? 0) === (r.port ?? 0);
          if ((staged.dns.records ?? []).some(same)) {
            form.setFieldError('value', 'That record is there already');
            return;
          }
          edit('dns', `Added ${k.label.toLowerCase()} ${r.name}`, (m) => ({ ...m, dns: { ...m.dns, records: [...(m.dns.records ?? []), r] } }));
          onClose();
        })}
      >
        <Stack>
          <Text size="sm" c="dimmed">{k.about}</Text>
          <TextInput
            label={type === 'PTR' ? 'Address' : 'Name'}
            placeholder={type === 'PTR' ? '192.168.1.20' : type === 'SRV' ? `_ipp._tcp.${domain}` : `nas.${domain}`}
            description={type === 'MX' || type === 'CAA' ? 'Usually the domain itself' : undefined}
            data-autofocus spellCheck={false}
            {...form.getInputProps('name')}
          />
          {type === 'CAA' && (
            <Select label="Allows" data={[{ value: 'issue', label: 'Certificates (issue)' }, { value: 'issuewild', label: 'Wildcard certificates (issuewild)' }, { value: 'iodef', label: 'Where to report a refused request (iodef)' }]} allowDeselect={false} {...form.getInputProps('tag')} />
          )}
          {type === 'TXT' ? (
            <Textarea label={valueLabel[type]} placeholder={placeholder[type]} autosize minRows={2} maxRows={6} spellCheck={false} {...form.getInputProps('value')} />
          ) : (
            <TextInput label={valueLabel[type]} placeholder={type === 'CAA' && form.values.tag === 'iodef' ? 'mailto:security@example.com' : placeholder[type]} spellCheck={false} {...form.getInputProps('value')} />
          )}
          {alias?.ok && <Text size="xs" c="dimmed" mt={-8}>{alias.text}</Text>}
          {(type === 'MX' || type === 'SRV') && (
            <Group grow align="flex-start">
              <NumberInput label={type === 'MX' ? 'Preference' : 'Priority'} description="Lower is tried first" min={0} max={65535} allowDecimal={false} {...form.getInputProps('priority')} />
              {type === 'SRV' && <NumberInput label="Weight" description="Shares among equals" min={0} max={65535} allowDecimal={false} {...form.getInputProps('weight')} />}
              {type === 'SRV' && <NumberInput label="Port" description=" " min={0} max={65535} allowDecimal={false} {...form.getInputProps('port')} />}
            </Group>
          )}
          <Group grow align="flex-start">
            <NumberInput label="Kept for" description="Seconds devices may remember it; 3600 if empty" min={0} max={604800} allowDecimal={false} {...form.getInputProps('ttl')} />
          </Group>
          <TextInput label="Description" {...form.getInputProps('description')} />
          <Group justify="flex-end" mt="sm">
            <Button variant="default" onClick={onClose}>Cancel</Button>
            <Button type="submit">Add</Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}
