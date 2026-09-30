// The diagnostic tools for the offline preview, which has no server:
// each run is sample output played out over time, in the formats the
// OpenBSD tools print (cmd/opf/mockdiag.go does the same for the mock).
import { ApiError, type ToolRequest, type ToolRun } from './api';

interface LocalRun {
  run: ToolRun;
  lines: { at: number; text: string }[];
  exitCode: number;
  endAt: number;
}

const runs = new Map<string, LocalRun>();
let next = 1;

const hostRE = /^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?)+$/;

function sampleAddr(host: string): string {
  if (/^[\d.]+$/.test(host) || host.includes(':')) return host;
  let h = 0;
  for (const c of host) h = (h * 31 + c.charCodeAt(0)) >>> 0;
  return `93.184.${(h >> 8) & 255}.${h & 255}`;
}

function script(req: ToolRequest): { lines: [number, string][]; exitCode: number } {
  const host = req.host?.trim() ?? '';
  const addr = sampleAddr(host);
  const down = host.startsWith('192.0.2.') || host.includes('unreachable');
  switch (req.tool) {
    case 'ping': {
      const count = req.count || 5;
      const size = req.size || 56;
      const lines: [number, string][] = [[0, `PING ${host} (${addr}): ${size} data bytes`]];
      if (!down) for (let i = 0; i < count; i++) lines.push([1000, `${size + 8} bytes from ${addr}: icmp_seq=${i} ttl=56 time=${(8.2 + (i % 4) / 10).toFixed(3)} ms`]);
      lines.push([down ? (count + 2) * 1000 : 0, ''], [0, `--- ${host} ping statistics ---`],
        [0, `${count} packets transmitted, ${down ? 0 : count} packets received, ${down ? '100.0' : '0.0'}% packet loss`]);
      if (!down) lines.push([0, 'round-trip min/avg/max/std-dev = 8.200/8.350/8.500/0.112 ms']);
      return { lines, exitCode: down ? 1 : 0 };
    }
    case 'traceroute': {
      const lines: [number, string][] = [[0, `traceroute to ${host} (${addr}), ${req.maxHops || 30} hops max, 40 byte packets`]];
      ['203.0.113.1', '198.51.100.1', '198.51.100.65'].forEach((h, i) => lines.push([400, `${String(i + 1).padStart(2)}  ${h}  ${(1.2 + i * 2.3).toFixed(3)} ms  ${(1.4 + i * 2.3).toFixed(3)} ms  ${(1.3 + i * 2.3).toFixed(3)} ms`]));
      if (down) for (let i = 4; i <= 6; i++) lines.push([6000, `${String(i).padStart(2)}  * * *`]);
      else lines.push([400, ` 4  ${addr}  10.400 ms  10.600 ms  10.500 ms`]);
      return { lines, exitCode: 0 };
    }
    case 'dns': {
      const name = req.name?.trim() ?? '';
      const type = (req.type || 'A').toUpperCase();
      const answer = name.includes('nonexistent') ? '' : type === 'A' ? `${name}.\t\t300\tIN\tA\t${sampleAddr(name)}` : `${name}.\t\t3600\tIN\t${type}\t; (sample)`;
      const lines: [number, string][] = [
        [150, ''], [0, `; <<>> dig 9.10.8-P1 <<>> ${name} ${type}`], [0, ';; Got answer:'],
        [0, `;; ->>HEADER<<- opcode: QUERY, status: ${answer ? 'NOERROR' : 'NXDOMAIN'}, id: 41236`], [0, ''],
        [0, ';; QUESTION SECTION:'], [0, `;${name}.\t\t\tIN\t${type}`], [0, ''],
      ];
      if (answer) lines.push([0, ';; ANSWER SECTION:'], [0, answer], [0, '']);
      lines.push([0, ';; Query time: 12 msec'], [0, `;; SERVER: ${req.server || '127.0.0.1'}#53(${req.server || '127.0.0.1'})`]);
      return { lines, exitCode: 0 };
    }
    case 'port': {
      const open = !down && ['22', '25', '53', '80', '443', '853'].includes(String(req.port));
      const proto = req.protocol === 'udp' ? 'udp' : 'tcp';
      return open
        ? { lines: [[80, `Connection to ${host} ${req.port} port [${proto}/*] succeeded!`]], exitCode: 0 }
        : { lines: [[down ? 5000 : 50, `nc: connect to ${addr} port ${req.port} (${proto}) failed: Connection refused`]], exitCode: 1 };
    }
  }
}

export function startLocalTool(req: ToolRequest): ToolRun {
  const field = req.tool === 'dns' ? 'name' : 'host';
  const value = (req.tool === 'dns' ? req.name : req.host)?.trim() ?? '';
  if (!hostRE.test(value) && !/^[0-9a-fA-F:.]+$/.test(value)) {
    throw new ApiError(422, 'invalid', `"${value}" isn't an address or a host name`, [{ path: field, message: `"${value}" isn't an address or a host name` }]);
  }
  const { lines, exitCode } = script(req);
  const now = Date.now();
  let at = now;
  const timed = lines.map(([delay, text]) => ({ at: (at += delay), text }));
  const id = `local${next++}`;
  const run: ToolRun = { id, tool: req.tool, command: `${req.tool} ${value}`, started: new Date(now).toISOString(), running: true, from: 0, lines: [], next: 0 };
  runs.set(id, { run, lines: timed, exitCode, endAt: at });
  return { ...run };
}

export function localToolRun(id: string, from: number): ToolRun {
  const r = runs.get(id);
  if (!r) throw new ApiError(404, 'not_found', 'no such run');
  const now = Date.now();
  const shown = r.lines.filter((l) => l.at <= now).map((l) => l.text);
  if (r.run.running && now >= r.endAt) {
    r.run = { ...r.run, running: false, finished: new Date(r.endAt).toISOString(), exitCode: r.exitCode };
  }
  return { ...r.run, from, lines: shown.slice(from), next: shown.length };
}

export function cancelLocalTool(id: string) {
  const r = runs.get(id);
  if (!r) throw new ApiError(404, 'not_found', 'no such run');
  const now = Date.now();
  r.lines = r.lines.filter((l) => l.at <= now);
  r.endAt = now;
  r.run = { ...r.run, running: false, finished: new Date(now).toISOString(), error: 'stopped' };
}
