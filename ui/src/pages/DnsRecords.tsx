// DNS resolver › Local names: host names and the other records the
// resolver answers itself, and how each local domain answers names it
// has no record for. The firewall checks everything again; the checks
// here are for saying what's wrong while typing.
import { useEffect, useMemo, useState } from 'react';
import { ActionIcon, Badge, Button, Group, Menu, Modal, NumberInput, SegmentedControl, Select, Stack, Table, Text, TextInput, Textarea } from '@mantine/core';
import { useForm } from '@mantine/form';
import { IconChevronDown, IconTrash } from '@tabler/icons-react';
import { newId, useStore } from '../model/store';
import type { DnsRecord, DnsRecordType, DnsZone, Model } from '../model/types';
import { Empty, Mono, SectionTitle } from '../components/ui';

type Kind = 'host' | DnsRecordType;

const kinds: { kind: Kind; label: string; badge: string; about: string }[] = [
  { kind: 'host', label: 'Host name', badge: 'Host', about: 'A name for an address: devices using OPF for DNS find it by name.' },
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
  remove: (m: Model) => Model;
  what: string;
}

function rows(m: Model): Row[] {
  const out: Row[] = m.dns.overrides.map((o) => ({
    key: o.id, name: `${o.host}.${o.domain}`, kind: 'host', value: o.ip, description: o.description,
    what: `host name ${o.host}.${o.domain}`,
    remove: (x) => ({ ...x, dns: { ...x.dns, overrides: x.dns.overrides.filter((y) => y.id !== o.id) } }),
  }));
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

export function LocalNames() {
  const { staged, edit } = useStore();
  const [adding, setAdding] = useState<Kind | null>(null);
  const list = useMemo(() => rows(staged), [staged]);
  return (
    <>
      <SectionTitle
        right={
          <Menu position="bottom-end" withinPortal>
            <Menu.Target>
              <Button size="xs" variant="light" rightSection={<IconChevronDown size={14} />}>Add</Button>
            </Menu.Target>
            <Menu.Dropdown>
              {kinds.map((k) => (
                <Menu.Item key={k.kind} onClick={() => setAdding(k.kind)}>
                  <Text size="sm">{k.label}</Text>
                </Menu.Item>
              ))}
            </Menu.Dropdown>
          </Menu>
        }
      >
        Local names
      </SectionTitle>
      {list.length ? (
        <Table.ScrollContainer minWidth={640}>
          <Table verticalSpacing={6}>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>Name</Table.Th>
                <Table.Th>Type</Table.Th>
                <Table.Th>Answer</Table.Th>
                <Table.Th>Description</Table.Th>
                <Table.Th w={40} />
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {list.map((r) => (
                <Table.Tr key={r.key}>
                  <Table.Td style={{ overflowWrap: 'anywhere' }}>
                    <Mono>{r.name}</Mono>
                  </Table.Td>
                  <Table.Td style={{ whiteSpace: 'nowrap' }}><Badge size="sm" variant="light" color={r.kind === 'host' ? 'teal' : 'gray'} styles={{ root: { overflow: 'visible' }, label: { overflow: 'visible' } }}>{kindOf(r.kind).badge}</Badge></Table.Td>
                  <Table.Td style={{ overflowWrap: 'anywhere' }}>
                    <Mono>{r.value}</Mono>
                    {r.detail && <Text size="xs" c="dimmed">{r.detail}</Text>}
                  </Table.Td>
                  <Table.Td><Text size="sm" c="dimmed">{r.description}</Text></Table.Td>
                  <Table.Td w={40}>
                    <ActionIcon variant="subtle" color="gray" aria-label={`Remove ${r.what}`} onClick={() => edit('dns', `Removed ${r.what}`, r.remove)}>
                      <IconTrash size={16} />
                    </ActionIcon>
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      ) : (
        <Empty>No local names.</Empty>
      )}
      <HostModal opened={adding === 'host'} onClose={() => setAdding(null)} />
      <RecordModal type={adding && adding !== 'host' ? adding : null} onClose={() => setAdding(null)} />
    </>
  );
}

// How each domain answers a name it has no record for: a setting, so
// it sits beside the resolver's others.
export function LocalDomains() {
  const { staged, edit } = useStore();
  const [name, setName] = useState('');
  const sys = staged.system.domain;
  const zones = staged.dns.zones ?? [];
  const list: DnsZone[] = [{ name: sys, type: systemZoneType(staged) }, ...zones.filter((z) => lower(z.name) !== lower(sys))];
  const setType = (z: DnsZone, type: DnsZone['type']) =>
    edit('dns', `${z.name} is now ${type === 'static' ? 'local only' : 'local, then internet'}`, (m) => {
      const rest = (m.dns.zones ?? []).filter((x) => lower(x.name) !== lower(z.name));
      // The system's domain is static unless listed.
      const keep = lower(z.name) === lower(m.system.domain) && type === 'static' ? rest : [...rest, { name: z.name, type }];
      return { ...m, dns: { ...m.dns, zones: keep.length ? keep : undefined } };
    });
  const n = name.trim().replace(/\.$/, '');
  const taken = list.some((z) => lower(z.name) === lower(n));
  const bad = n !== '' && (!isHost(n) || taken || /^((in-addr|ip6)\.)?arpa$/i.test(n));
  return (
    <Stack gap="xs">
      <SectionTitle>Local domains</SectionTitle>
      <Text size="sm" c="dimmed" mt={-8}>
        When a device asks for a name in one of these domains that isn’t in Local names:
      </Text>
      <Text size="sm" c="dimmed">
        <Text span fw={600} c="var(--mantine-color-text)">Local only</Text>: it’s told the name doesn’t exist. For a domain that exists only on your network, like office.arpa.
      </Text>
      <Text size="sm" c="dimmed">
        <Text span fw={600} c="var(--mantine-color-text)">Local, then internet</Text>: it’s looked up on the internet as usual. For a real domain such as your company’s, when you only want to change a few of its names here.
      </Text>
      <Text size="sm" c="dimmed" mb={4}>
        Add a domain to choose for it. Any other domain is looked up on the internet, apart from the names you add for it.
      </Text>
      {list.map((z) => (
        <Group key={z.name} justify="space-between" gap="xs">
          <Mono>{z.name}</Mono>
          <Group gap={6} wrap="nowrap">
            <SegmentedControl size="xs" value={z.type} onChange={(v) => setType(z, v as DnsZone['type'])} data={[{ value: 'static', label: 'Local only' }, { value: 'transparent', label: 'Local, then internet' }]} />
            {z.name !== sys ? (
              <ActionIcon variant="subtle" color="gray" aria-label={`Remove ${z.name}`} onClick={() => edit('dns', `Removed domain ${z.name}`, (m) => {
                const zs = (m.dns.zones ?? []).filter((x) => lower(x.name) !== lower(z.name));
                return { ...m, dns: { ...m.dns, zones: zs.length ? zs : undefined } };
              })}>
                <IconTrash size={16} />
              </ActionIcon>
            ) : <span style={{ width: 28 }} />}
          </Group>
        </Group>
      ))}
      <Group gap="xs" align="flex-start">
        <TextInput size="xs" placeholder="lab.example.com" value={name} onChange={(e) => setName(e.currentTarget.value)} error={bad ? (taken ? 'Already listed' : 'Enter a domain like lab.example.com') : undefined} style={{ flex: '1 1 200px' }} maw={280} spellCheck={false} />
        <Button size="xs" variant="default" disabled={!n || bad} onClick={() => {
          edit('dns', `Added domain ${n}, local only`, (m) => ({ ...m, dns: { ...m.dns, zones: [...(m.dns.zones ?? []), { name: n, type: 'static' }] } }));
          setName('');
        }}>Add domain</Button>
      </Group>
    </Stack>
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
