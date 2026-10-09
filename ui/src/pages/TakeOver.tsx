// System › Take over: a machine OPF doesn't manage yet (read-only, or
// before its first commit) is taken over by importing its own
// configuration. The page shows what OPF understood, what the first
// commit would change (pfctl's word on the ruleset, and each file's
// diff), and takes over with the admin's word: the import is staged as
// OPF's first change, to review and commit. Nothing on the machine
// changes before that commit. Read-only, OPF starts again out of
// read-only mode to stage it.
//
// A machine OPF managed before it was made read-only has a
// configuration of its own, and is handed back by hand on the machine.
import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react';
import { Link } from 'react-router';
import {
  Accordion, Alert, Anchor, Badge, Button, Card, Checkbox, Code, Collapse, Group, List, Loader, SegmentedControl, Stack, Stepper, Table, Text, ThemeIcon, UnstyledButton,
} from '@mantine/core';
import {
  IconAlertTriangle, IconArrowLeft, IconArrowRight, IconCheck, IconChevronDown, IconChevronRight, IconEye, IconFileImport, IconHandStop, IconInfoCircle,
} from '@tabler/icons-react';
import { backend, useStore } from '../model/store';
import { ApiError, type Area, type ImportArea, type ImportFile, type ImportNote, type ImportReport, type PfComparison } from '../lib/api';
import { useMode } from '../lib/mode';
import { useRole } from '../lib/session';
import { Mono, PageHeader, SectionTitle } from '../components/ui';
import { UnifiedDiff } from '../components/UnifiedDiff';

const errorText = (e: unknown) => (e instanceof Error ? e.message : String(e));

const areaLabel: Record<Area, { name: string; file: string; daemon: string }> = {
  dhcp: { name: 'DHCP server', file: '/etc/dhcpd.conf', daemon: 'dhcpd' },
  dns: { name: 'DNS resolver', file: '/var/unbound/etc/unbound.conf', daemon: 'unbound' },
  ntp: { name: 'Time servers', file: '/etc/ntpd.conf', daemon: 'ntpd' },
};

const noteKind: Record<ImportNote['kind'], { label: string; color: string; hint: string }> = {
  model: { label: 'In OPF', color: 'teal', hint: 'Understood: it’s part of OPF’s configuration, and you change it on OPF’s pages' },
  kept: { label: 'As written', color: 'blue', hint: 'Kept exactly as written (a raw rule, or custom pf): same meaning, changed as text' },
  left: { label: 'Left alone', color: 'gray', hint: 'Not part of OPF’s configuration: OPF leaves it as it is' },
  lost: { label: 'Changes', color: 'orange', hint: 'The first commit loses or changes it' },
};

export function TakeOver() {
  const { readOnly, managed } = useMode();
  const { isAdmin } = useRole();
  const { history, changes } = useStore();

  if (managed || history.length > 0) {
    return (
      <>
        <PageHeader title="Take over" />
        {readOnly ? <ManagedBefore /> : <Alert color="gray" variant="light">OPF manages this machine already.</Alert>}
      </>
    );
  }
  return (
    <>
      <PageHeader
        title="Take over this machine"
        description={readOnly
          ? 'OPF is only monitoring this machine. Taking it over hands OPF its configuration, so you change it here instead of by hand.'
          : 'This machine has a configuration of its own. Importing it makes it OPF’s, so nothing changes until you change it.'}
      />
      <Stack gap="md" maw={980}>
        {readOnly && <WhileMonitoring />}
        {!readOnly && changes.length > 0 ? (
          <Alert color="blue" variant="light" icon={<IconInfoCircle size={18} />} title="Changes are staged">
            <Text size="sm" mb="xs">Review and apply them first, or discard them: importing replaces what’s staged.</Text>
            <Button size="xs" component={Link} to="/?review=1">Review the changes</Button>
          </Alert>
        ) : isAdmin ? (
          <Wizard readOnly={readOnly} />
        ) : (
          <Alert color="gray" variant="light">Only an admin can take this machine over.</Alert>
        )}
      </Stack>
    </>
  );
}

function WhileMonitoring() {
  const [open, setOpen] = useState(false);
  return (
    <Card>
      <UnstyledButton onClick={() => setOpen((o) => !o)} w="100%">
        <Group gap="sm" wrap="nowrap">
          <ThemeIcon variant="light" color="blue"><IconEye size={18} /></ThemeIcon>
          <Text fw={600} size="sm" style={{ flex: 1 }}>What OPF does while it only monitors</Text>
          {open ? <IconChevronDown size={16} /> : <IconChevronRight size={16} />}
        </Group>
      </UnstyledButton>
      <Collapse in={open}>
        <List size="sm" spacing={6} mt="sm">
          <List.Item>It shows the machine as it is: devices, connections, the firewall log and its statistics, interfaces, routes, services, logs and graphs.</List.Item>
          <List.Item>It changes nothing. Every change through this interface is refused, and OPF runs nothing that would change the machine: no new rules or settings, no services started or stopped, no connections closed, no accounts made.</List.Item>
          <List.Item>OPF writes only its own state directory (<Mono>/var/opf</Mono>): the graphs’ history and the event log. On OpenBSD the sandbox (unveil) holds it to that.</List.Item>
          <List.Item>The one thing it made is its sign-in groups, on first start, so people can sign in. Give someone a role by hand: <Mono>usermod -G _opfadmin name</Mono>.</List.Item>
        </List>
      </Collapse>
    </Card>
  );
}

function ManagedBefore() {
  return (
    <Card maw={820}>
      <SectionTitle>Managing it again</SectionTitle>
      <Text size="sm" mb="sm">
        OPF has a configuration of its own for this machine, from before it was made read-only, so it can take over again without importing anything. That’s done on the machine itself, as root:
      </Text>
      <Code block>{`rcctl get opf flags          # then set them again without -readonly:
rcctl set opf flags <the same flags, without -readonly>
rm /var/opf/readonly
rcctl restart opf`}</Code>
      <Text size="xs" c="dimmed" mt="sm">
        Restarting changes nothing by itself: OPF keeps its configuration up again (lists, tables, sign-in accounts), and writes the machine’s files only when a change is applied.
      </Text>
    </Card>
  );
}

function Wizard({ readOnly }: { readOnly: boolean }) {
  const [step, setStep] = useState(0);
  const [manage, setManage] = useState<Partial<Record<Area, boolean>>>({});
  const [report, setReport] = useState<ImportReport>();
  const [error, setError] = useState<string>();
  const [loading, setLoading] = useState(false);

  const load = useCallback((m: Partial<Record<Area, boolean>>) => {
    setLoading(true);
    backend.importMachine({ manage: m }).then(
      (r) => { setReport(r); setError(undefined); setLoading(false); },
      (e) => { setError(errorText(e)); setLoading(false); },
    );
  }, []);
  useEffect(() => load({}), [load]);

  const choose = (area: Area, managed: boolean) => {
    const m = { ...manage, [area]: managed };
    setManage(m);
    load(m);
  };

  if (error && !report) {
    return (
      <Alert color="red" variant="light" icon={<IconAlertTriangle size={18} />} title="Couldn’t read this machine’s configuration">
        <Text size="sm" mb="xs">{error}</Text>
        <Button size="xs" variant="light" onClick={() => load(manage)}>Try again</Button>
      </Alert>
    );
  }
  if (!report) {
    return <Card><Group gap="sm"><Loader size="sm" /><Text size="sm">Reading this machine’s configuration…</Text></Group></Card>;
  }
  return (
    <Stepper active={step} onStepClick={setStep} size="sm" allowNextStepsSelect={false}>
      <Stepper.Step label="What OPF found" description="Understood, kept, left alone">
        <Found report={report} loading={loading} onChoose={choose} />
        <Group justify="flex-end" mt="md">
          <Button rightSection={<IconArrowRight size={16} />} onClick={() => setStep(1)} disabled={loading}>What would change</Button>
        </Group>
      </Stepper.Step>
      <Stepper.Step label="What would change" description="The ruleset and each file">
        <Changes report={report} />
        <Group justify="space-between" mt="md">
          <Button variant="default" leftSection={<IconArrowLeft size={16} />} onClick={() => setStep(0)}>Back</Button>
          <Button rightSection={<IconArrowRight size={16} />} onClick={() => setStep(2)}>Take over</Button>
        </Group>
      </Stepper.Step>
      <Stepper.Step label="Take over" description="Stage it, then review">
        <Finish report={report} manage={manage} readOnly={readOnly} onStale={() => { setStep(0); load(manage); }} onBack={() => setStep(1)} />
      </Stepper.Step>
    </Stepper>
  );
}

// ---------- What OPF found ----------

function Found({ report, loading, onChoose }: { report: ImportReport; loading: boolean; onChoose: (a: Area, managed: boolean) => void }) {
  const m = report.model;
  const rules = m.firewall.rules;
  const guided = rules.filter((r) => r.kind === 'form').length;
  const custom = m.firewall.custom.options ? m.firewall.custom.options.split('\n').filter((l) => l.trim()).length : 0;
  const leftIfaces = report.notes.filter((n) => n.kind === 'left' && n.file.startsWith('/etc/hostname.') && !n.text);
  return (
    <Stack gap="md" mt="md">
      <Card>
        <SectionTitle>Interfaces</SectionTitle>
        {m.interfaces.length ? (
          <Table.ScrollContainer minWidth={480}>
            <Table verticalSpacing={6}>
              <Table.Thead>
                <Table.Tr><Table.Th>Name</Table.Th><Table.Th>Device</Table.Th><Table.Th>Address</Table.Th><Table.Th /></Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {m.interfaces.map((i) => (
                  <Table.Tr key={i.id}>
                    <Table.Td><Text size="sm" fw={500}>{i.name}</Text></Table.Td>
                    <Table.Td><Mono>{i.device}</Mono>{i.vlan && <Text span size="xs" c="dimmed"> VLAN {i.vlan.tag}</Text>}</Table.Td>
                    <Table.Td>{i.ipv4.mode === 'static' ? <Mono>{`${i.ipv4.address}/${i.ipv4.prefix}`}</Mono> : <Text size="sm" c="dimmed">{i.ipv4.mode === 'dhcp' ? 'DHCP' : 'None'}</Text>}</Table.Td>
                    <Table.Td>{i.role === 'wan' && <Badge size="sm" variant="light">WAN</Badge>}{!i.enabled && <Badge size="sm" variant="light" color="gray">Down</Badge>}</Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        ) : <Text size="sm" c="dimmed">None OPF can take over.</Text>}
        {leftIfaces.length > 0 && (
          <Stack gap={4} mt="sm">
            {leftIfaces.map((n) => (
              <Text key={n.file} size="xs" c="dimmed"><Mono>{n.file}</Mono>: {n.message}</Text>
            ))}
          </Stack>
        )}
        <Text size="xs" c="dimmed" mt="sm">
          The WAN is the interface with the default route. The others take OPF’s “optional” role: making one the LAN later adds OPF’s anti-lockout rule, which keeps this page and SSH reachable from it.
        </Text>
      </Card>

      <Card>
        <SectionTitle>Firewall</SectionTitle>
        <Group gap="xl" mb="xs">
          <Count n={guided} label={guided === 1 ? 'rule you can edit on OPF’s pages' : 'rules you can edit on OPF’s pages'} />
          <Count n={rules.length - guided} label="kept as written" />
          <Count n={m.firewall.aliases.length} label={m.firewall.aliases.length === 1 ? 'alias' : 'aliases'} />
          <Count n={custom} label="macros, tables and settings kept as written" />
        </Group>
        <Text size="xs" c="dimmed">
          Every rule keeps its place. One OPF can’t show in its own form, or that its form would move, is kept as written: it means the same, and you edit it as text.
        </Text>
      </Card>

      <Card>
        <SectionTitle>Services</SectionTitle>
        <Stack gap="sm">
          {report.areas.map((a) => <AreaRow key={a.area} a={a} loading={loading} onChoose={onChoose} />)}
        </Stack>
      </Card>

      <Card>
        <SectionTitle>File by file</SectionTitle>
        <Notes notes={report.notes} />
      </Card>
    </Stack>
  );
}

function Count({ n, label }: { n: number; label: string }) {
  return (
    <Group gap={6} align="baseline" wrap="nowrap">
      <Text fw={700} size="lg" className="num">{n}</Text>
      <Text size="sm" c="dimmed">{label}</Text>
    </Group>
  );
}

function AreaRow({ a, loading, onChoose }: { a: ImportArea; loading: boolean; onChoose: (a: Area, managed: boolean) => void }) {
  const l = areaLabel[a.area];
  let why: string;
  if (a.exact) why = `OPF writes ${l.file} meaning the same as this machine’s.`;
  else if (!a.running) why = `${l.daemon} isn’t enabled, so nothing changes until you turn it on.`;
  else why = `${l.file} has settings OPF doesn’t have: managed by OPF, they’d go.`;
  return (
    <Group justify="space-between" align="flex-start" wrap="wrap" gap="sm">
      <div style={{ flex: '1 1 260px', minWidth: 0 }}>
        <Group gap={6}>
          <Text size="sm" fw={600}>{l.name}</Text>
          <Text size="sm" c="dimmed">· {a.summary}</Text>
        </Group>
        <Text size="xs" c="dimmed">{why}{!a.managed && ' Left as it is, OPF doesn’t write it or start, stop or restart ' + l.daemon + '; you can hand it over later, on its page.'}</Text>
      </div>
      <SegmentedControl
        size="xs"
        disabled={loading}
        value={a.managed ? 'opf' : 'hand'}
        onChange={(v) => onChoose(a.area, v === 'opf')}
        data={[
          { value: 'opf', label: 'Manage with OPF' },
          { value: 'hand', label: 'Leave as it is' },
        ]}
      />
    </Group>
  );
}

function Notes({ notes }: { notes: ImportNote[] }) {
  const byFile = useMemo(() => {
    const out = new Map<string, ImportNote[]>();
    for (const n of notes) out.set(n.file, [...(out.get(n.file) ?? []), n]);
    return [...out.entries()];
  }, [notes]);
  return (
    <>
      <Group gap="xs" mb="sm">
        {(Object.keys(noteKind) as ImportNote['kind'][]).map((k) => (
          <Badge key={k} size="sm" variant="light" color={noteKind[k].color} title={noteKind[k].hint}>{noteKind[k].label}</Badge>
        ))}
      </Group>
      <Accordion multiple variant="separated" chevronPosition="left">
        {byFile.map(([file, ns]) => {
          const lost = ns.filter((n) => n.kind === 'lost').length;
          return (
            <Accordion.Item key={file} value={file}>
              <Accordion.Control>
                <Group gap="sm" wrap="nowrap">
                  <Mono>{file}</Mono>
                  {lost > 0 && <Badge size="xs" variant="light" color="orange">{lost} {lost === 1 ? 'change' : 'changes'}</Badge>}
                </Group>
              </Accordion.Control>
              <Accordion.Panel>
                <Stack gap={8}>
                  {ns.map((n, i) => (
                    <Group key={i} gap="sm" wrap="nowrap" align="flex-start">
                      <Badge size="xs" variant="light" color={noteKind[n.kind].color} w={74} style={{ flexShrink: 0 }} title={noteKind[n.kind].hint}>{noteKind[n.kind].label}</Badge>
                      <div style={{ minWidth: 0 }}>
                        {n.text && <Text size="xs" ff="monospace" style={{ overflowWrap: 'anywhere' }}>{n.line ? <Text span c="dimmed" size="xs" ff="monospace">{n.line}: </Text> : null}{n.text}</Text>}
                        <Text size="xs" c="dimmed">{n.message}</Text>
                      </div>
                    </Group>
                  ))}
                </Stack>
              </Accordion.Panel>
            </Accordion.Item>
          );
        })}
      </Accordion>
    </>
  );
}

// ---------- What would change ----------

function Changes({ report }: { report: ImportReport }) {
  const changed = report.files.filter((f) => f.status !== 'same');
  return (
    <Stack gap="md" mt="md">
      <Ruleset ruleset={report.ruleset} error={report.rulesetError} />
      <Card>
        <SectionTitle>Files the first commit writes</SectionTitle>
        <Text size="sm" c="dimmed" mb="sm">
          {changed.length
            ? 'Nothing is written until you apply the first commit. Each file then becomes OPF’s, with its header; the diffs show the rest.'
            : 'Every file stays as it is.'}
        </Text>
        <Stack gap={6}>
          {report.files.map((f) => <FileRow key={f.path} f={f} />)}
        </Stack>
      </Card>
    </Stack>
  );
}

function Ruleset({ ruleset, error }: { ruleset?: PfComparison; error?: string }) {
  const [open, setOpen] = useState(false);
  if (!ruleset) {
    return (
      <Alert color="yellow" variant="light" icon={<IconAlertTriangle size={18} />} title="The rulesets couldn’t be compared">
        <Text size="sm">{error}</Text>
      </Alert>
    );
  }
  return (
    <Card>
      <SectionTitle>The firewall’s rules</SectionTitle>
      {ruleset.same ? (
        <Group gap="sm" wrap="nowrap" align="flex-start">
          <ThemeIcon color="teal" variant="light" radius="xl"><IconCheck size={16} /></ThemeIcon>
          <Text size="sm">pfctl reads the pf.conf OPF would write as the same ruleset as this machine’s: the same options, tables and rules, in the same order. OPF’s labels and default rules aside, which change nothing here.</Text>
        </Group>
      ) : (
        <>
          <Group gap="sm" wrap="nowrap" align="flex-start" mb="sm">
            <ThemeIcon color="orange" variant="light" radius="xl"><IconAlertTriangle size={16} /></ThemeIcon>
            <Text size="sm">pfctl reads the pf.conf OPF would write differently from this machine’s:</Text>
          </Group>
          <List size="sm" spacing={4} mb="sm">
            {ruleset.differences.map((d, i) => <List.Item key={i}><Text size="sm" style={{ overflowWrap: 'anywhere' }}>{d}</Text></List.Item>)}
          </List>
        </>
      )}
      <Group><Anchor component="button" type="button" size="xs" onClick={() => setOpen((o) => !o)}>{open ? 'Hide' : 'Show'} the rulesets pfctl read</Anchor></Group>
      <Collapse in={open}>
        <Stack gap="xs" mt="sm">
          <Text size="xs" fw={600}>This machine’s</Text>
          <Code block>{ruleset.machine.join('\n') || '(no rules)'}</Code>
          <Text size="xs" fw={600}>OPF’s, without its labels and default rules</Text>
          <Code block>{ruleset.opf.join('\n') || '(no rules)'}</Code>
        </Stack>
      </Collapse>
    </Card>
  );
}

const fileStatus: Record<ImportFile['status'], { label: string; color: string }> = {
  same: { label: 'Unchanged', color: 'gray' },
  changed: { label: 'Changes', color: 'orange' },
  added: { label: 'New', color: 'blue' },
};

function FileRow({ f }: { f: ImportFile }) {
  const [open, setOpen] = useState(false);
  const s = fileStatus[f.status];
  return (
    <div>
      <UnstyledButton onClick={() => f.diff && setOpen((o) => !o)} w="100%" style={{ cursor: f.diff ? 'pointer' : 'default' }}>
        <Group gap="sm" wrap="nowrap">
          <div style={{ width: 16 }}>{f.diff && (open ? <IconChevronDown size={14} /> : <IconChevronRight size={14} />)}</div>
          <Badge size="xs" variant="light" color={s.color} w={74} style={{ flexShrink: 0 }}>{s.label}</Badge>
          <Mono>{f.path}</Mono>
          <Text size="xs" c="dimmed" visibleFrom="sm" truncate>{f.desc}</Text>
        </Group>
      </UnstyledButton>
      {f.diff && (
        <Collapse in={open}>
          <div style={{ marginTop: 6, marginLeft: 24 }}><UnifiedDiff diff={f.diff} /></div>
        </Collapse>
      )}
    </div>
  );
}

// ---------- Take over ----------

function Finish({ report, manage, readOnly, onStale, onBack }: {
  report: ImportReport; manage: Partial<Record<Area, boolean>>; readOnly: boolean; onStale: () => void; onBack: () => void;
}) {
  const [accept, setAccept] = useState(false);
  const [busy, setBusy] = useState(false);
  const [restarting, setRestarting] = useState(false);
  const [error, setError] = useState<ReactNode>();
  const differs = !report.ruleset?.same;
  const left = report.areas.filter((a) => !a.managed);

  // Read-only, OPF starts again out of read-only mode; once it answers
  // as such, the page loads again, with the import staged.
  useEffect(() => {
    if (!restarting) return;
    let live = true;
    const poll = () => {
      backend.status().then(
        (s) => { if (!live) return; if (!s.readOnly) window.location.assign('/?review=1'); else setTimeout(poll, 1500); },
        // Sessions don't outlive OPF: once it's back, signing in again
        // leads to the review.
        (e) => { if (!live) return; if (e instanceof ApiError && e.code === 'unauthorized') window.location.assign('/?review=1'); else setTimeout(poll, 1500); },
      );
    };
    const t = setTimeout(poll, 2000);
    return () => { live = false; clearTimeout(t); };
  }, [restarting]);

  const takeOver = () => {
    setBusy(true);
    setError(undefined);
    backend.takeOver({ manage, fingerprint: report.fingerprint, acceptDifferences: differs && accept }).then(
      (r) => {
        if (r.restarting) setRestarting(true);
        else window.location.assign('/?review=1');
      },
      (e) => {
        setBusy(false);
        if (e instanceof ApiError && e.code === 'conflict') {
          onStale();
          return;
        }
        setError(errorText(e));
      },
    );
  };

  if (restarting) {
    return (
      <Card mt="md">
        <Group gap="sm" wrap="nowrap">
          <Loader size="sm" />
          <div>
            <Text size="sm" fw={600}>OPF is starting again, out of read-only mode</Text>
            <Text size="xs" c="dimmed">When it’s back, you sign in again, and the import opens, staged as OPF’s first change, for you to review.</Text>
          </div>
        </Group>
      </Card>
    );
  }
  return (
    <Stack gap="md" mt="md">
      {report.problems.length > 0 && (
        <Alert color="red" variant="light" icon={<IconAlertTriangle size={18} />} title="OPF can’t take this configuration over as it is">
          <List size="sm" spacing={4}>
            {report.problems.map((p, i) => <List.Item key={i}><Mono>{p.path}</Mono>: {p.message}</List.Item>)}
          </List>
        </Alert>
      )}
      <Card>
        <SectionTitle>Taking over</SectionTitle>
        <List size="sm" spacing={6} mb="md" icon={<IconFileImport size={14} style={{ marginTop: 3 }} />}>
          {readOnly && <List.Item>OPF starts again, out of read-only mode, and takes <Mono>-readonly</Mono> out of its flags in <Mono>rc.conf.local</Mono>.</List.Item>}
          <List.Item>The import is staged as OPF’s first change. Nothing on the machine changes yet.</List.Item>
          <List.Item>You review it and apply it. Like every change, it waits for you to confirm it, and undoes itself if you don’t, so a mistake can’t lock you out.</List.Item>
          {left.length > 0 && (
            <List.Item icon={<IconHandStop size={14} style={{ marginTop: 3 }} />}>
              Left as they are: {left.map((a) => areaLabel[a.area].name).join(', ')}. Each page says so, and hands it over when you want.
            </List.Item>
          )}
        </List>
        {differs && (
          <Checkbox
            mb="md"
            checked={accept}
            onChange={(e) => setAccept(e.currentTarget.checked)}
            label={report.ruleset ? 'Take over though the firewall’s rules would change as shown' : 'Take over though the rulesets couldn’t be compared'}
          />
        )}
        {error && <Alert color="red" variant="light" mb="md">{error}</Alert>}
        <Group justify="space-between">
          <Button variant="default" leftSection={<IconArrowLeft size={16} />} onClick={onBack}>Back</Button>
          <Button leftSection={<IconFileImport size={16} />} loading={busy} disabled={report.problems.length > 0 || (differs && !accept)} onClick={takeOver}>
            Take over this machine
          </Button>
        </Group>
      </Card>
    </Stack>
  );
}
