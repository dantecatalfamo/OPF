// What a tool's finished run found, in words, and the next thing to
// try, read from the output of OpenBSD's ping, traceroute, dig and nc.
import type { ToolRequest, ToolRun } from './api';

// What a finished run found, in words, and what to try next.
export interface Outcome {
  ok: boolean;
  text: string;
  next?: { label: string; req: ToolRequest }[];
}

// Failures any tool can hit before it gets going, as OpenBSD's tools
// word them.
export function commonOutcome(run: ToolRun, req: ToolRequest): Outcome | undefined {
  const host = req.host ?? req.name ?? '';
  if (run.lines.some((l) => /no address associated with name|unknown host|hostname nor servname/.test(l))) {
    return { ok: false, text: `${host} doesn’t resolve: DNS has no address for it${req.family === 'ipv6' ? ' (IPv6)' : ''}.`, next: [{ label: `Look up ${host}`, req: { tool: 'dns', name: host, type: req.family === 'ipv6' ? 'AAAA' : 'A' } }] };
  }
  if (run.lines.some((l) => /No route to host|Network is unreachable/.test(l)) && !run.lines.some((l) => /bytes from|^\s*\d+\s+\S+\s+[\d.]+ ms/.test(l))) {
    const v6 = (req.host ?? '').includes(':') || req.family === 'ipv6';
    return { ok: false, text: `This firewall has no route to ${host}${v6 ? '. IPv6 may not be set up on its internet connection' : ''}.` };
  }
  return undefined;
}

export function pingOutcome(run: ToolRun, req: ToolRequest): Outcome | undefined {
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

export function tracerouteOutcome(run: ToolRun, req: ToolRequest): Outcome | undefined {
  // "traceroute to example.com (93.184.215.14), 30 hops max, ..."
  const header = run.lines[0]?.match(/^traceroute6? to \S+ \(([^)]+)\), (\d+) hops max/);
  const target = header?.[1];
  const maxHops = Number(header?.[2]);
  const hops = run.lines.filter((l) => /^\s*\d+\s/.test(l));
  if (!target || !hops.length) return undefined;
  const answered = hops.filter((l) => !/^\s*\d+\s+(\*\s*)+$/.test(l));
  const reached = answered.find((l) => l.trim().split(/\s+/).slice(1).includes(target));
  if (reached) {
    const n = Number(reached.trim().split(/\s+/)[0]);
    return { ok: true, text: `Reached ${target} in ${n} ${n === 1 ? 'hop' : 'hops'}.`, next: [{ label: 'Ping it', req: { tool: 'ping', host: req.host } }] };
  }
  const last = answered.at(-1)?.trim().split(/\s+/);
  // Routers answered all the way to the limit: it ran out of hops, it
  // didn't stop anywhere.
  if (last && Number(last[0]) === maxHops && hops.at(-1) === answered.at(-1) && maxHops < 64) {
    return { ok: false, text: `It didn’t reach ${target} within ${maxHops} hops, but every router on the way answered.`, next: [{ label: `Trace up to ${Math.min(64, maxHops * 2)} hops`, req: { ...req, maxHops: Math.min(64, maxHops * 2) } }] };
  }
  return {
    ok: false,
    text: last
      ? `${target} never answered. The last router that did is ${last[1]} (hop ${last[0]}), so the trouble is likely there or just after it. Some hosts don’t answer traceroute at all; try ICMP, or ping it.`
      : `No router on the way answered, not even the first. Check this firewall’s internet connection.`,
    next: [{ label: 'Ping it', req: { tool: 'ping', host: req.host } }],
  };
}

export function dnsOutcome(run: ToolRun, req: ToolRequest): Outcome | undefined {
  const status = run.lines.map((l) => l.match(/status: ([A-Z]+)/)).find(Boolean)?.[1];
  if (!status && run.lines.some((l) => /connection timed out|no servers could be reached/.test(l))) {
    return req.server || req.trace
      ? { ok: false, text: `${req.server || 'The DNS servers'} didn’t answer.` }
      : { ok: false, text: 'This firewall’s DNS resolver didn’t answer. Check that it’s turned on (Services › DNS resolver), or ask another server.', next: [{ label: 'Ask 9.9.9.9 instead', req: { ...req, server: '9.9.9.9' } }] };
  }
  if (!status) return undefined;
  if (status === 'NXDOMAIN') return { ok: false, text: 'The name doesn’t exist.' };
  if (status !== 'NOERROR') return { ok: false, text: `The server answered ${status}.` };
  const start = run.lines.findIndex((l) => l.startsWith(';; ANSWER SECTION'));
  const answers = start < 0 ? [] : run.lines.slice(start + 1).filter((l) => l && !l.startsWith(';')).map((l) => l.split(/\s+/));
  if (!answers.length) return { ok: true, text: 'The name exists, but has no records of that type.' };
  const addrs = answers.filter((a) => a[3] === 'A' || a[3] === 'AAAA').map((a) => a[4]);
  // name TTL class type data...
  const values = answers.map((a) => a.slice(4).join(' ').replace(/\.$/, '')).filter(Boolean);
  return {
    ok: true,
    text: `${answers.length} ${answers.length === 1 ? 'answer' : 'answers'}${values.length ? `: ${values.slice(0, 4).join(', ')}${values.length > 4 ? '…' : ''}` : ''}.`,
    next: addrs.slice(0, 2).map((a) => ({ label: `Ping ${a}`, req: { tool: 'ping' as const, host: a } })),
  };
}

export function portOutcome(run: ToolRun, req: ToolRequest): Outcome | undefined {
  const proto = req.protocol === 'udp' ? 'UDP' : 'TCP';
  if (run.lines.some((l) => /succeeded/.test(l))) {
    return { ok: true, text: req.protocol === 'udp' ? `Nothing refused UDP port ${req.port}; with UDP that’s all a test can tell.` : `Something is listening on port ${req.port}.` };
  }
  if (run.lines.some((l) => /Connection refused/.test(l))) {
    return { ok: false, text: `${req.host} answered, but nothing is listening on ${proto} port ${req.port} (the connection was refused).` };
  }
  return { ok: false, text: `Nothing answered on ${proto} port ${req.port}: the host may be down, or a firewall on the way drops it.`, next: [{ label: `Ping ${req.host}`, req: { tool: 'ping', host: req.host } }] };
}

