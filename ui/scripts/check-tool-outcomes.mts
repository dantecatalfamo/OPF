// Checks the Tools page's result summaries (src/lib/toolOutcomes.ts)
// against real output from OpenBSD's ping, traceroute, dig and nc:
// every run gets a summary, printed for reading. npm run check:tools.
import { readFileSync } from 'node:fs';
import * as o from '../src/lib/toolOutcomes.ts';
// Output of the tools captured on OpenBSD, each run as "### <command>",
// its output, and "### exit <status>".
const text = readFileSync(new URL('../../internal/diag/testdata/openbsd-7.9-tools.txt', import.meta.url), 'utf8');
let missing = 0;
const runs = text.split('### ').slice(1).map((chunk) => {
  const [cmd, ...rest] = chunk.split('\n');
  return { cmd, lines: rest };
}).filter((r) => !r.cmd.startsWith('exit'));
for (const { cmd, lines } of runs) {
  const argv = cmd.split(' ');
  const after = argv.slice(argv.indexOf('--') + 1);
  const out = lines.slice(0, lines.findIndex((l) => l.startsWith('### exit')));
  const run = { id: 'x', tool: 'ping', command: cmd, started: '', running: false, from: 0, lines: out.filter((l) => !l.startsWith('### ')), next: 0 } as any;
  let req: any, f: any;
  if (argv[0].startsWith('ping')) { req = { tool: 'ping', host: after[0], size: Number(argv[argv.indexOf('-s') + 1]) }; f = o.pingOutcome; }
  else if (argv[0].startsWith('traceroute')) { req = { tool: 'traceroute', host: after[0] }; f = o.tracerouteOutcome; }
  else if (argv[0] === 'dig') { req = { tool: 'dns', name: argv[argv.indexOf('-q') + 1] ?? argv[argv.indexOf('-x') + 1], server: argv[1].startsWith('@') && argv[1] !== '@127.0.0.1' ? argv[1].slice(1) : undefined }; f = o.dnsOutcome; }
  else { req = { tool: 'port', host: after[0], port: Number(after[1]), protocol: argv.includes('-u') ? 'udp' : 'tcp' }; f = o.portOutcome; }
  const res = o.commonOutcome(run, req) ?? f(run, req);
  if (!res) missing++;
  console.log(`${cmd}\n   → ${res ? `${res.ok ? 'OK' : 'NO'}: ${res.text}${res.next ? ` [${res.next.map((n: any) => n.label).join(', ')}]` : ''}` : '(no summary)'}`);
}
if (missing) {
  console.error(`${missing} runs have no summary`);
  process.exit(1);
}
