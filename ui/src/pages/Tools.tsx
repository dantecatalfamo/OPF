import { useEffect, useRef, useState, type ReactNode } from 'react';
import { useSearchParams } from 'react-router';
import {
  Alert, Badge, Button, Card, Checkbox, Code, Group, NumberInput, ScrollArea, SegmentedControl, Select, SimpleGrid, Stack, Tabs, Text, TextInput,
} from '@mantine/core';
import { useForm } from '@mantine/form';
import { IconPlayerPlay, IconPlayerStop } from '@tabler/icons-react';
import { backend } from '../model/store';
import { ApiError, type ToolRequest, type ToolRun } from '../lib/api';
import { PageHeader } from '../components/ui';

type Tool = ToolRequest['tool'];

// A run as the page follows it: the run's state and every line so far.
function useToolRun() {
  const [run, setRun] = useState<ToolRun>();
  const [error, setError] = useState<ApiError | Error>();
  const timer = useRef<ReturnType<typeof setTimeout>>(undefined);
  const current = useRef<string>(undefined);
  useEffect(() => () => clearTimeout(timer.current), []);

  const follow = (id: string, lines: string[]) => {
    timer.current = setTimeout(async () => {
      if (current.current !== id) return;
      try {
        const r = await backend.toolRun(id, lines.length);
        if (current.current !== id) return;
        const all = [...lines, ...r.lines];
        setRun({ ...r, lines: all });
        if (r.running) follow(id, all);
      } catch (e) {
        setError(e instanceof Error ? e : new Error(String(e)));
      }
    }, 400);
  };

  const start = async (req: ToolRequest) => {
    clearTimeout(timer.current);
    setError(undefined);
    try {
      const r = await backend.startTool(req);
      current.current = r.id;
      setRun(r);
      follow(r.id, r.lines);
    } catch (e) {
      current.current = undefined;
      setRun(undefined);
      setError(e instanceof Error ? e : new Error(String(e)));
    }
  };
  const stop = () => run && backend.cancelTool(run.id).catch(() => {});
  return { run, error, start, stop };
}

// What a finished run found, in words, and what to try next.
interface Outcome {
  ok: boolean;
  text: string;
  next?: { label: string; req: ToolRequest }[];
}

function pingOutcome(run: ToolRun, req: ToolRequest): Outcome | undefined {
  const stats = run.lines.map((l) => l.match(/(\d+) packets transmitted, (\d+) packets received/)).find(Boolean);
  const rtt = run.lines.map((l) => l.match(/= [\d.]+\/([\d.]+)\//)).find(Boolean);
  if (run.lines.some((l) => /Message too long/.test(l))) {
    return { ok: false, text: `Packets of ${req.size} bytes don’t fit on the way without being fragmented. Try a smaller size to find the largest that does.` };
  }
  if (!stats) return undefined;
  const [sent, got] = [Number(stats[1]), Number(stats[2])];
  if (got === 0) {
    return { ok: false, text: `${req.host} didn’t answer any of ${sent} pings. It may be down, unreachable from here, or not answering pings.`, next: [{ label: 'Trace the route to it', req: { tool: 'traceroute', host: req.host } }] };
  }
  return { ok: got === sent, text: `${got} of ${sent} answered${rtt ? `, ${Number(rtt[1]).toFixed(1)} ms on average` : ''}.`, next: got < sent ? [{ label: 'Trace the route', req: { tool: 'traceroute', host: req.host } }] : undefined };
}

function tracerouteOutcome(run: ToolRun, req: ToolRequest): Outcome | undefined {
  // "traceroute to example.com (93.184.215.14), 30 hops max, ..."
  const target = run.lines[0]?.match(/^traceroute6? to \S+ \(([^)]+)\)/)?.[1];
  const hops = run.lines.filter((l) => /^\s*\d+\s/.test(l));
  if (!target || !hops.length) return undefined;
  const answered = hops.filter((l) => !/^\s*\d+\s+(\*\s*)+$/.test(l));
  const reached = answered.find((l) => l.trim().split(/\s+/).slice(1).includes(target));
  if (reached) return { ok: true, text: `Reached ${target} in ${reached.trim().split(/\s+/)[0]} hops.`, next: [{ label: 'Ping it', req: { tool: 'ping', host: req.host } }] };
  const last = answered.at(-1)?.trim().split(/\s+/);
  return {
    ok: false,
    text: last
      ? `${target} never answered. The last router that did is ${last[1]} (hop ${last[0]}), so the trouble is likely there or just after it. Some hosts don’t answer traceroute at all; try ICMP, or ping it.`
      : `No router on the way answered, not even the first. Check this firewall’s internet connection.`,
    next: [{ label: 'Ping it', req: { tool: 'ping', host: req.host } }],
  };
}

function dnsOutcome(run: ToolRun): Outcome | undefined {
  const status = run.lines.map((l) => l.match(/status: ([A-Z]+)/)).find(Boolean)?.[1];
  if (!status) return run.lines.some((l) => /connection timed out|no servers could be reached/.test(l)) ? { ok: false, text: 'The DNS server didn’t answer.' } : undefined;
  if (status === 'NXDOMAIN') return { ok: false, text: 'The name doesn’t exist.' };
  if (status !== 'NOERROR') return { ok: false, text: `The server answered ${status}.` };
  const start = run.lines.findIndex((l) => l.startsWith(';; ANSWER SECTION'));
  const answers = start < 0 ? [] : run.lines.slice(start + 1).filter((l) => l && !l.startsWith(';')).map((l) => l.split(/\s+/));
  if (!answers.length) return { ok: true, text: 'The name exists, but has no records of that type.' };
  const addrs = answers.filter((a) => a[3] === 'A' || a[3] === 'AAAA').map((a) => a[4]);
  return {
    ok: true,
    text: `${answers.length} ${answers.length === 1 ? 'answer' : 'answers'}${addrs.length ? `: ${addrs.slice(0, 4).join(', ')}` : ''}.`,
    next: addrs.slice(0, 2).map((a) => ({ label: `Ping ${a}`, req: { tool: 'ping' as const, host: a } })),
  };
}

function portOutcome(run: ToolRun, req: ToolRequest): Outcome | undefined {
  const proto = req.protocol === 'udp' ? 'UDP' : 'TCP';
  if (run.lines.some((l) => /succeeded/.test(l))) {
    return { ok: true, text: req.protocol === 'udp' ? `Nothing refused UDP port ${req.port}; with UDP that’s all a test can tell.` : `Something is listening on port ${req.port}.` };
  }
  if (run.lines.some((l) => /Connection refused/.test(l))) {
    return { ok: false, text: `${req.host} answered, but nothing is listening on ${proto} port ${req.port} (the connection was refused).` };
  }
  return { ok: false, text: `Nothing answered on ${proto} port ${req.port}: the host may be down, or a firewall on the way drops it.`, next: [{ label: `Ping ${req.host}`, req: { tool: 'ping', host: req.host } }] };
}

function Output({ run, outcome, onNext, onStop }: { run?: ToolRun; outcome?: Outcome; onNext: (r: ToolRequest) => void; onStop: () => void }) {
  const viewport = useRef<HTMLDivElement>(null);
  useEffect(() => {
    viewport.current?.scrollTo({ top: viewport.current.scrollHeight });
  }, [run?.lines.length]);
  if (!run) return null;
  const status = run.running
    ? <Badge color="blue" variant="light">Running</Badge>
    : run.error
      ? <Badge color="yellow" variant="light">{run.error}</Badge>
      : <Badge color={run.exitCode === 0 ? 'teal' : 'gray'} variant="light">Finished{run.exitCode ? ` (exit ${run.exitCode})` : ''}</Badge>;
  return (
    <Stack gap="sm">
      <Group justify="space-between" wrap="wrap" gap="xs">
        <Text size="xs" c="dimmed" className="mono" style={{ overflowWrap: 'anywhere', flex: '1 1 240px' }}>{run.command}</Text>
        <Group gap="xs" wrap="nowrap" style={{ flexShrink: 0 }}>
          {status}
          {run.running && <Button size="xs" variant="default" leftSection={<IconPlayerStop size={14} />} onClick={onStop}>Stop</Button>}
        </Group>
      </Group>
      <ScrollArea.Autosize mah={420} viewportRef={viewport} type="auto">
        <Code block style={{ whiteSpace: 'pre', minHeight: 60 }}>{run.lines.join('\n') || (run.running ? '…' : '(no output)')}</Code>
      </ScrollArea.Autosize>
      {run.truncated && <Text size="xs" c="yellow">It printed more than OPF keeps, so it was stopped.</Text>}
      {outcome && (
        <Alert color={outcome.ok ? 'teal' : 'yellow'} variant="light">
          <Stack gap="xs">
            <Text size="sm">{outcome.text}</Text>
            {outcome.next && outcome.next.length > 0 && (
              <Group gap="xs">
                {outcome.next.map((n) => <Button key={n.label} size="xs" variant="light" onClick={() => onNext(n.req)}>{n.label}</Button>)}
              </Group>
            )}
          </Stack>
        </Alert>
      )}
    </Stack>
  );
}

// A tool's form, its run and output. initial and runKey let a next step
// (or a link) fill the form and start it.
function ToolPanel<V extends Record<string, unknown>>({ defaults, initial, runKey, toRequest, fields, outcome, onNext, help }: {
  defaults: V;
  initial?: Partial<V>;
  runKey: number;
  toRequest: (v: V) => ToolRequest;
  fields: (form: ReturnType<typeof useForm<V>>) => ReactNode;
  outcome: (run: ToolRun, req: ToolRequest) => Outcome | undefined;
  onNext: (r: ToolRequest) => void;
  help: string;
}) {
  const form = useForm<V>({ initialValues: { ...defaults, ...initial } });
  const { run, error, start, stop } = useToolRun();
  const [req, setReq] = useState<ToolRequest>();
  const submit = (v: V) => {
    const r = toRequest(v);
    setReq(r);
    form.clearErrors();
    start(r);
  };
  useEffect(() => {
    if (!runKey || !initial) return;
    const v = { ...defaults, ...initial };
    form.setValues(v);
    submit(v);
  }, [runKey]); // a next step or link asked for a run
  useEffect(() => {
    // The server names the field it refused.
    if (error instanceof ApiError) for (const d of error.details) form.setFieldError(d.path, d.message ?? error.message);
  }, [error]);
  const fieldError = error instanceof ApiError && error.details.length > 0;
  return (
    <Card>
      <form onSubmit={form.onSubmit(submit)}>
        <Stack>
          <Text size="sm" c="dimmed">{help}</Text>
          {fields(form)}
          <Group>
            <Button type="submit" leftSection={<IconPlayerPlay size={16} />} loading={run?.running} disabled={run?.running}>Run</Button>
          </Group>
          {error && !fieldError && <Alert color="red" variant="light">{error.message}</Alert>}
          {/* Judged once it has finished: a trace still going hasn't failed. */}
          <Output run={run} outcome={run && req && !run.running && !run.error ? outcome(run, req) : undefined} onNext={onNext} onStop={stop} />
        </Stack>
      </form>
    </Card>
  );
}

// Descriptions under the inputs, so a row of fields lines up.
const below: ('label' | 'input' | 'description' | 'error')[] = ['label', 'input', 'description', 'error'];

const family = [{ value: '', label: 'Either' }, { value: 'ipv4', label: 'IPv4' }, { value: 'ipv6', label: 'IPv6' }];
const dnsTypes = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'PTR', 'SOA', 'SRV', 'TXT', 'CAA', 'DS', 'DNSKEY', 'HTTPS', 'SVCB', 'ANY'];
const hostHelp = 'An address, or a name such as example.com (international names in their xn-- form).';

export function Tools() {
  const [params, setParams] = useSearchParams();
  const tab = (params.get('tool') as Tool) || 'ping';
  // A next step or a link: the tool, what to fill in, and a key to run it.
  const [pending, setPending] = useState<{ req: ToolRequest; key: number }>(() => {
    const t = params.get('tool') as Tool | null;
    const host = params.get('host') ?? undefined;
    return t && (host || params.get('name')) ? { req: { tool: t, host, name: params.get('name') ?? undefined, port: Number(params.get('port')) || undefined }, key: 1 } : { req: { tool: 'ping' }, key: 0 };
  });
  const next = (req: ToolRequest) => {
    setParams({ tool: req.tool }, { replace: true });
    setPending((p) => ({ req, key: p.key + 1 }));
  };
  const initial = (t: Tool) => (pending.req.tool === t ? pending.req : undefined);
  const key = (t: Tool) => (pending.req.tool === t ? pending.key : 0);

  return (
    <>
      <PageHeader title="Tools" description="Test the network from the firewall itself: whether a host answers, the route to it, what DNS says, whether a port is open." />
      <Tabs value={tab} onChange={(v) => v && setParams({ tool: v }, { replace: true })} keepMounted>
        <Tabs.List mb="md">
          <Tabs.Tab value="ping">Ping</Tabs.Tab>
          <Tabs.Tab value="traceroute">Traceroute</Tabs.Tab>
          <Tabs.Tab value="dns">DNS lookup</Tabs.Tab>
          <Tabs.Tab value="port">Port test</Tabs.Tab>
        </Tabs.List>
        <Tabs.Panel value="ping">
          <ToolPanel
            runKey={key('ping')} initial={initial('ping') as never} onNext={next} outcome={pingOutcome}
            help="Sends a few pings and times the answers. Don’t fragment, with a size, finds the largest packet that gets through (1472 fits a normal 1500-byte link)."
            defaults={{ host: '', count: 5 as number | string, size: 56 as number | string, family: '', dontFragment: false }}
            toRequest={(v) => ({ tool: 'ping', host: v.host, count: Number(v.count) || undefined, size: Number(v.size) || undefined, family: v.family as ToolRequest['family'], dontFragment: v.dontFragment })}
            fields={(f) => (
              <SimpleGrid cols={{ base: 1, sm: 2, lg: 4 }}>
                <TextInput inputWrapperOrder={below} label="Host" description={hostHelp} placeholder="9.9.9.9" {...f.getInputProps('host')} />
                <NumberInput label="Pings" min={1} max={50} {...f.getInputProps('count')} />
                <NumberInput inputWrapperOrder={below} label="Size" description="Data bytes in each" min={1} max={9000} {...f.getInputProps('size')} />
                <Stack gap={6}>
                  <Text size="sm" fw={500}>Address family</Text>
                  <SegmentedControl size="xs" data={family} {...f.getInputProps('family')} />
                  <Checkbox mt={4} label="Don’t fragment" {...f.getInputProps('dontFragment', { type: 'checkbox' })} />
                </Stack>
              </SimpleGrid>
            )}
          />
        </Tabs.Panel>
        <Tabs.Panel value="traceroute">
          <ToolPanel
            runKey={key('traceroute')} initial={initial('traceroute') as never} onNext={next} outcome={tracerouteOutcome}
            help="Lists each router on the way to a host, and how long each takes to answer. Where the answers stop is usually where the problem is. Some routers never answer, which isn’t a fault."
            defaults={{ host: '', protocol: 'udp', maxHops: 30 as number | string, family: '', asNumbers: false, names: false }}
            toRequest={(v) => ({ tool: 'traceroute', host: v.host, protocol: v.protocol, maxHops: Number(v.maxHops) || undefined, family: v.family as ToolRequest['family'], asNumbers: v.asNumbers, names: v.names })}
            fields={(f) => (
              <SimpleGrid cols={{ base: 1, sm: 2, lg: 4 }}>
                <TextInput inputWrapperOrder={below} label="Host" description={hostHelp} placeholder="example.com" {...f.getInputProps('host')} />
                <Select inputWrapperOrder={below} label="Probe with" description="ICMP gets through more firewalls" data={[{ value: 'udp', label: 'UDP' }, { value: 'icmp', label: 'ICMP (like ping)' }]} allowDeselect={false} {...f.getInputProps('protocol')} />
                <NumberInput label="Most hops" min={1} max={64} {...f.getInputProps('maxHops')} />
                <Stack gap={6}>
                  <Text size="sm" fw={500}>Address family</Text>
                  <SegmentedControl size="xs" data={family} {...f.getInputProps('family')} />
                  <Checkbox mt={4} label="Look up each hop’s name (slower)" {...f.getInputProps('names', { type: 'checkbox' })} />
                  <Checkbox label="Show each hop’s network (AS)" {...f.getInputProps('asNumbers', { type: 'checkbox' })} />
                </Stack>
              </SimpleGrid>
            )}
          />
        </Tabs.Panel>
        <Tabs.Panel value="dns">
          <ToolPanel
            runKey={key('dns')} initial={initial('dns') as never} onNext={next} outcome={(r) => dnsOutcome(r)}
            help="Asks DNS about a name, or an address for its name. Asking this firewall’s resolver shows what your devices get; asking another server, or tracing from the root, shows whether the problem is here or upstream."
            defaults={{ name: '', type: 'A', server: '', trace: false, dnssec: false }}
            toRequest={(v) => ({ tool: 'dns', name: v.name, type: v.type, server: v.server.trim() || undefined, trace: v.trace, dnssec: v.dnssec })}
            fields={(f) => (
              <SimpleGrid cols={{ base: 1, sm: 2, lg: 4 }}>
                <TextInput label="Name or address" placeholder="example.com" {...f.getInputProps('name')} />
                <Select label="Record type" data={dnsTypes} allowDeselect={false} searchable {...f.getInputProps('type')} />
                <TextInput inputWrapperOrder={below} label="Server" description="Empty asks this firewall’s resolver" placeholder="9.9.9.9" disabled={f.values.trace} {...f.getInputProps('server')} />
                <Stack gap={6} pt={4}>
                  <Checkbox label="Trace from the root servers" {...f.getInputProps('trace', { type: 'checkbox' })} />
                  <Checkbox label="Show DNSSEC records" {...f.getInputProps('dnssec', { type: 'checkbox' })} />
                </Stack>
              </SimpleGrid>
            )}
          />
        </Tabs.Panel>
        <Tabs.Panel value="port">
          <ToolPanel
            runKey={key('port')} initial={initial('port') as never} onNext={next} outcome={portOutcome}
            help="Checks whether something answers on a port, from the firewall. For TCP that’s a clear yes or no; UDP can only show that nothing refused."
            defaults={{ host: '', port: 443 as number | string, protocol: 'tcp', family: '' }}
            toRequest={(v) => ({ tool: 'port', host: v.host, port: Number(v.port) || 0, protocol: v.protocol, family: v.family as ToolRequest['family'] })}
            fields={(f) => (
              <SimpleGrid cols={{ base: 1, sm: 2, lg: 4 }}>
                <TextInput inputWrapperOrder={below} label="Host" description={hostHelp} placeholder="192.168.1.20" {...f.getInputProps('host')} />
                <NumberInput label="Port" min={1} max={65535} {...f.getInputProps('port')} />
                <Stack gap={6}>
                  <Text size="sm" fw={500}>Protocol</Text>
                  <SegmentedControl size="xs" data={[{ value: 'tcp', label: 'TCP' }, { value: 'udp', label: 'UDP' }]} {...f.getInputProps('protocol')} />
                </Stack>
                <Stack gap={6}>
                  <Text size="sm" fw={500}>Address family</Text>
                  <SegmentedControl size="xs" data={family} {...f.getInputProps('family')} />
                </Stack>
              </SimpleGrid>
            )}
          />
        </Tabs.Panel>
      </Tabs>
    </>
  );
}
