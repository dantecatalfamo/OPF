// An in-memory stand-in for the server, for the offline preview build.
// It follows the server's rules (versions, pending commits that revert
// on their own, changes staged again after a revert), and generates,
// validates and parses with the Go code itself, compiled to WebAssembly
// (cmd/opfwasm), so what the preview shows is what the appliance would.
import type { Model, Rule } from '../model/types';
import { call, GeneratorError } from '@wasmgen';
import { sampleHistory, sampleModel } from '../model/sample';
import { unifiedDiff } from './diff';
import { cancelLocalTool, localToolRun, startLocalTool } from './localTools';
import { leases as sampleLeases, arpTable as sampleArpTable, routingTable as sampleRoutingTable, sampleDnsBlocked, sampleDnsStats, sampleEvents, sampleSystemLog, sampleMetrics, sampleFirewallLog, sampleGateways, sampleInterfaces, samplePfStates, samplePfStatus, sampleRuleCounters, sampleSystem, sampleUpdates } from '../model/live';
import {
  ApiError, type ChangeNote, type CommitDetail, type CommitResource, type ConfigResource, type FileChange,
  type DhcpLeasesResource, type LeaseNamesResource, type StagedResource, type StatusResource,
  type ARPTableResource, type RoutingTableResource, type GatewaysResource, type InterfacesResource, type SystemResource, type UpdatesResource,
  type DnsBlockedResource, type MetricsResource, type EventsRequest, type DnsToolName, type DnsToolResult, type SystemLogName, type SystemLogRequest, type SystemLogResource, type WebhookStatus, type WebhookSecretRequest, type EventsResource, type DnsListStatus, type DnsStatsResource, type RefreshState, type TableStatus, type ToolRequest, type ToolRun, type FirewallLogResource, type PfState, type PfStatesResource, type PfStatesRequest, type PfStatusResource, type RuleCountersResource, type Derived, type GeneratedFile, type PfLine, type RenderTarget, type Rendered,
} from './api';

const CONFIRM_MS = 60_000;
const MODEL_PATH = '/var/opf/config.json';

interface Record {
  resource: CommitResource;
  before: Model;
  after: Model;
  diffs: { path: string; diff: string }[];
}

function version(m: Model): string {
  const s = JSON.stringify(m);
  let h = 5381;
  for (let i = 0; i < s.length; i++) h = ((h * 33) ^ s.charCodeAt(i)) >>> 0;
  return h.toString(16).padStart(8, '0');
}

// Generator errors come back the way the server reports them.
async function generate<T>(name: string, request: unknown): Promise<T> {
  try {
    return await call<T>(name, request);
  } catch (e) {
    if (e instanceof GeneratorError) throw new ApiError(422, 'invalid', e.message);
    throw e;
  }
}

async function files(m: Model): Promise<Map<string, string>> {
  const gen = await generate<GeneratedFile[]>('files', { model: m });
  return new Map([[MODEL_PATH, JSON.stringify(m, null, 2) + '\n'], ...gen.map((f) => [f.path, f.content] as [string, string])]);
}

async function fileChanges(from: Model, to: Model): Promise<FileChange[]> {
  const a = await files(from);
  const out: FileChange[] = [];
  const b = await files(to);
  for (const [path, content] of b) {
    const before = a.get(path);
    if (before === content) continue;
    out.push({
      path, status: before === undefined ? 'added' : 'modified',
      diff: unifiedDiff(before ?? '', content, `${path} (live)`, `${path} (staged)`),
      needsConfirm: path === '/etc/pf.conf', model: path === MODEL_PATH,
    });
  }
  // Files the new model no longer generates, such as a deleted VLAN's.
  for (const [path, before] of a) {
    if (!b.has(path)) out.push({ path, status: 'removed', diff: unifiedDiff(before, '', `${path} (live)`, `${path} (staged)`) });
  }
  return out;
}

const clone = <T,>(v: T): T => structuredClone(v);

let live: Model = clone(sampleModel);
let staged: Model | null = null;
let pending: { id: string; timer: ReturnType<typeof setTimeout> } | null = null;
const records: Record[] = sampleHistory(Date.now()).map(({ entry, before, after }) => ({
  resource: {
    id: entry.id, time: new Date(entry.time).toISOString(), status: entry.status, message: entry.message,
    changes: entry.changes.map((c) => ({ area: c.section, summary: c.summary })), files: [],
  },
  before, after, diffs: [],
}));

async function stagedResource(): Promise<StagedResource> {
  if (!staged) throw new ApiError(404, 'nothing_staged', 'nothing is staged');
  return { version: version(staged), base: version(live), model: clone(staged), changes: await fileChanges(live, staged) };
}

function record(id: string): Record {
  const r = records.find((x) => x.resource.id === id);
  if (!r) throw new ApiError(404, 'not_found', `no commit "${id}"`);
  return r;
}

function requirePending(id: string): Record {
  const r = record(id);
  if (!pending) throw new ApiError(409, 'not_pending', `commit ${id} isn't waiting for confirmation`);
  if (pending.id !== id) throw new ApiError(409, 'not_pending', `commit ${pending.id} is waiting for confirmation, not ${id}`);
  return r;
}

function finishRevert(r: Record) {
  if (pending) clearTimeout(pending.timer);
  pending = null;
  r.resource = { ...r.resource, status: 'reverted', deadline: undefined };
  live = clone(r.before);
  staged = clone(r.after); // staged again so it can be fixed
}

function newID(): string {
  const d = new Date();
  const p = (n: number, w = 2) => String(n).padStart(w, '0');
  return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}.${p(d.getMilliseconds(), 3)}`;
}

export const localApi = {
  pfRuleset: async (model: Model) => generate<PfLine[]>('ruleset', { model }),
  pfDerived: async (model: Model) => generate<Derived>('derived', { model }),
  pfRender: async (model: Model, target: RenderTarget) => generate<Rendered>('render', { model, ...target }),
  parseRule: async (text: string, model?: Model): Promise<Rule | undefined> => {
    try {
      const rule = await call<Rule | null>('parse', { text, model });
      return rule?.kind === 'form' ? rule : undefined;
    } catch {
      return undefined; // not a pf rule, like the server's 422
    }
  },
  status: async (): Promise<StatusResource> => ({
    live: version(live),
    staged: staged ? version(staged) : undefined,
    pending: pending ? clone(record(pending.id).resource) : undefined,
    release: '7.9',
  }),
  live: async (): Promise<ConfigResource> => ({ version: version(live), model: clone(live) }),
  staged: async (): Promise<StagedResource | null> => (staged ? stagedResource() : null),
  stage: async (base: string, model: Model, _overwrite?: string[]): Promise<StagedResource> => {
    if (pending) throw new ApiError(409, 'commit_pending', 'a commit is waiting for confirmation; confirm or revert it first');
    if (base !== version(live)) throw new ApiError(409, 'conflict', 'the configuration was changed; reload and redo your changes');
    const problems = await generate<{ path: string; message: string }[]>('validate', { model });
    if (problems.length) throw new ApiError(422, 'invalid', `the configuration has ${problems.length} problem(s)`, problems);
    staged = version(model) === version(live) ? null : clone(model);
    return staged ? stagedResource() : { version: version(live), base, model: clone(model), changes: [] };
  },
  discard: async () => {
    if (pending) throw new ApiError(409, 'commit_pending', 'a commit is waiting for confirmation');
    staged = null;
  },
  commits: async (): Promise<CommitResource[]> => records.map((r) => clone(r.resource)),
  commit: async (id: string): Promise<CommitDetail> => {
    const r = record(id);
    return { ...clone(r.resource), diffs: r.diffs, log: '(offline preview: no commands were run)' };
  },
  createCommit: async (stagedVersion: string, message: string, changes: ChangeNote[]): Promise<CommitResource> => {
    if (!staged) throw new ApiError(409, 'nothing_staged', 'nothing is staged');
    if (version(staged) !== stagedVersion) throw new ApiError(409, 'conflict', 'the staged configuration changed; review it again');
    if (pending) throw new ApiError(409, 'commit_pending', 'a commit is already waiting for confirmation');
    const changed = await fileChanges(live, staged);
    const needsConfirm = changed.some((c) => c.needsConfirm);
    const id = newID();
    const r: Record = {
      resource: {
        id, time: new Date().toISOString(), status: needsConfirm ? 'pending' : 'applied', message, changes,
        deadline: needsConfirm ? new Date(Date.now() + CONFIRM_MS).toISOString() : undefined,
        files: changed.map((c) => ({ path: c.path, created: c.status === 'added', removed: c.status === 'removed', needsConfirm: c.needsConfirm, model: c.model })),
      },
      before: clone(live), after: clone(staged),
      diffs: changed.map((c) => ({ path: c.path, diff: c.diff })),
    };
    records.unshift(r);
    live = clone(staged);
    staged = null;
    if (needsConfirm) pending = { id, timer: setTimeout(() => finishRevert(r), CONFIRM_MS) };
    return clone(r.resource);
  },
  confirm: async (id: string): Promise<CommitResource> => {
    const r = requirePending(id);
    clearTimeout(pending!.timer);
    pending = null;
    r.resource = { ...r.resource, status: 'confirmed', deadline: undefined };
    return clone(r.resource);
  },
  revert: async (id: string): Promise<CommitResource> => {
    const r = requirePending(id);
    finishRevert(r);
    return clone(r.resource);
  },
  // The sample's dynamic leases (ui/src/model/live.ts), named as the
  // server would name them if nothing else claims the name.
  leaseNames: async (): Promise<LeaseNamesResource> => {
    const d = live.dns;
    if (!d.enabled || !d.registerDynamicLeases) return { enabled: false, registered: [], refused: [] };
    const reserved = live.dhcp.flatMap((s) => s.reservations);
    const taken = new Set([live.system.hostname, ...reserved.map((r) => r.hostname), ...d.overrides.map((o) => o.host), 'wpad', 'isatap', 'localhost']);
    const dynamic = sampleLeases.filter((l) => !reserved.some((r) => r.ip === l.ip));
    return {
      enabled: true,
      checked: new Date().toISOString(),
      registered: dynamic.filter((l) => !taken.has(l.hostname)).map((l) => ({ name: `${l.hostname}.${live.system.domain}`, ip: l.ip })),
      refused: dynamic.filter((l) => taken.has(l.hostname)).map((l) => ({ ip: l.ip, hostname: l.hostname, reason: 'the name is taken by the configuration' })),
    };
  },
  // The sample's leases (ui/src/model/live.ts), without the reserved
  // devices: dhcpd doesn't record leases for fixed addresses.
  dhcpLeases: async (): Promise<DhcpLeasesResource> => {
    const names = await localApi.leaseNames();
    const reserved = live.dhcp.flatMap((s) => s.reservations);
    const now = Date.now();
    return {
      leases: sampleLeases.filter((l) => !reserved.some((r) => r.ip === l.ip)).map((l) => ({
        ip: l.ip, mac: l.mac, hostname: l.hostname, iface: l.iface,
        starts: new Date(now - 3600_000).toISOString(), ends: new Date(now + l.expiresInMin * 60_000).toISOString(),
        dnsName: names.registered.find((r) => r.ip === l.ip)?.name,
        dnsRefused: names.refused.find((r) => r.ip === l.ip)?.reason,
      })),
    };
  },
  commitConfig: async (id: string, which: 'before' | 'after'): Promise<ConfigResource> => {
    const r = record(id);
    const model = which === 'before' ? r.before : r.after;
    return { version: version(model), model: clone(model) };
  },
  arpTable: async (): Promise<ARPTableResource> => ({ entries: clone(sampleArpTable) }),
  routingTable: async (): Promise<RoutingTableResource> => ({ ipv4: clone(sampleRoutingTable), ipv6: [] }),
  system: async (): Promise<SystemResource> => sampleSystem(),
  updates: async (): Promise<UpdatesResource> => sampleUpdates(),
  checkUpdates: async (): Promise<UpdatesResource> => sampleUpdates(),
  interfaces: async (): Promise<InterfacesResource> => sampleInterfaces(live),
  gateways: async (): Promise<GatewaysResource> => sampleGateways(live),
  pfStatus: async (): Promise<PfStatusResource> => samplePfStatus(samplePfStates(live, closedStates).states.length),
  pfStates: async (r: PfStatesRequest = {}): Promise<PfStatesResource> => {
    // As the server pages it: filtered, busiest first.
    const all = samplePfStates(live, closedStates).states;
    const match = all
      .filter((c) => !r.proto || (c.proto === 'ipv6-icmp' ? 'icmp' : c.proto) === r.proto)
      .filter((c) => !r.query || `${c.source} ${c.destination} ${c.translated ?? ''}`.includes(r.query.trim()))
      .sort((a, b) => b.bytes - a.bytes);
    const from = r.offset ?? 0;
    return { states: match.slice(from, from + (r.limit || 200)), total: match.length, read: all.length };
  },
  killState: async (s: Pick<PfState, 'id' | 'creatorId'>): Promise<void> => {
    closedStates.add(s.id);
  },
  ruleCounters: async (): Promise<RuleCountersResource> => sampleRuleCounters(live),
  firewallLog: async (): Promise<FirewallLogResource> => sampleFirewallLog(live),
  tables: async (): Promise<TableStatus[]> =>
    live.firewall.aliases.filter((a) => a.type === 'url').map((a) => {
      const fetched = tableFetched.get(a.name) ?? new Date(Date.now() - 5 * 3600_000).toISOString();
      return { name: a.name, url: a.url ?? '', fetched, entries: 1184, refresh: sampleRefresh(fetched, a.refreshHours) };
    }),
  dnsLists: async (): Promise<DnsListStatus[]> =>
    (live.dns.blocklists ?? []).map((l) => {
      const fetched = tableFetched.get('dns:' + l.id) ?? new Date(Date.now() - 3 * 3600_000).toISOString();
      return { id: l.id, name: l.name, url: l.url, enabled: l.enabled, fetched, blocked: 48213, allowed: 12, skipped: {}, refresh: sampleRefresh(fetched, l.refreshHours) };
    }),
  dnsStats: async (): Promise<DnsStatsResource> => sampleDnsStats(live, (live.dns.blocklists ?? []).filter((l) => l.enabled).length * 48225),
  dnsBlocked: async (): Promise<DnsBlockedResource> => sampleDnsBlocked(live),
  // The preview can't send anything: webhooks' URLs are remembered, and
  // a test says why nothing went.
  webhooks: async (): Promise<WebhookStatus[]> => (live.notifications?.webhooks ?? []).concat(staged?.notifications?.webhooks ?? []).map((w) => ({ id: w.id, ...previewHooks.get(w.id) })),
  setWebhookSecret: async (id: string, r: WebhookSecretRequest): Promise<WebhookStatus & { key?: string }> => {
    const u = new URL(r.url);
    const st = { id, target: `${u.protocol}//${u.host}`, signed: r.signing !== 'none' };
    previewHooks.set(id, st);
    return { ...st, key: r.signing === 'generate' ? 'preview-key-not-secret-0123456789abcdef0123456789abcdef0123456789' : undefined };
  },
  testWebhook: async (id: string): Promise<WebhookStatus> => {
    const st = { ...previewHooks.get(id), id, lastAttempt: new Date().toISOString(), lastError: 'The preview can’t send anything; on a firewall this would.' };
    previewHooks.set(id, st);
    return st;
  },
  dnsTool: async (tool: DnsToolName, name?: string): Promise<DnsToolResult> => {
    if (tool === 'local') return { lines: [`${live.system.domain}. static`, ...live.dns.overrides.map((o) => `${o.host}.${o.domain}.\t3600\tIN\tA\t${o.ip}`)] };
    if (tool === 'lookup') return { lines: [`The following name servers are used for lookup of ${name}.`, 'com.\t172800\tIN\tNS\ta.gtld-servers.net.'] };
    if (tool === 'cache') return { lines: [`${name}.\t2400\tIN\tA\t192.0.2.10`] };
    return { lines: ['ok'] };
  },
  systemLog: async (log: SystemLogName, r: SystemLogRequest = {}): Promise<SystemLogResource> => {
    const all = sampleSystemLog(log);
    const q = r.query?.toLowerCase();
    const match = all.filter((l) => (!r.program || l.program === r.program) && (!q || `${l.program ?? ''} ${l.message}`.toLowerCase().includes(q)));
    return { log, lines: match.slice(0, r.limit || 300), matched: match.length, read: all.length, programs: [...new Set(all.map((l) => l.program).filter((p): p is string => !!p))].sort() };
  },
  events: async (r: EventsRequest = {}): Promise<EventsResource> => {
    const all = sampleEvents(live)
      .filter((e) => !r.kinds?.length || r.kinds.includes(e.kind))
      .filter((e) => !r.query || `${e.message} ${e.subject ?? ''}`.toLowerCase().includes(r.query.toLowerCase()))
      .filter((e) => !r.before || e.time < r.before);
    const n = r.limit || 100;
    return { events: all.slice(0, n), more: all.length > n };
  },
  metrics: async (series: string[], range: number, step?: number): Promise<MetricsResource> => sampleMetrics(live, series, range, step),
  refreshDnsList: async (id: string): Promise<DnsListStatus> => {
    const l = (live.dns.blocklists ?? []).find((x) => x.id === id);
    if (!l) throw new ApiError(404, 'not_found', `no DNS blocklist "${id}" in the applied configuration`);
    await new Promise((r) => setTimeout(r, 700));
    const fetched = new Date().toISOString();
    tableFetched.set('dns:' + id, fetched);
    return { id, name: l.name, url: l.url, enabled: l.enabled, fetched, blocked: 48240, allowed: 12, skipped: {}, refresh: sampleRefresh(fetched, l.refreshHours) };
  },
  refreshAlias: async (name: string): Promise<TableStatus> => {
    const a = live.firewall.aliases.find((x) => x.name === name && x.type === 'url');
    if (!a) throw new ApiError(404, 'not_found', `no downloaded list called "${name}" in the applied configuration`);
    await new Promise((r) => setTimeout(r, 700));
    const fetched = new Date().toISOString();
    tableFetched.set(name, fetched);
    return { name, url: a.url ?? '', fetched, entries: 1191, refresh: sampleRefresh(fetched, a.refreshHours) };
  },
  startTool: async (req: ToolRequest): Promise<ToolRun> => startLocalTool(req),
  toolRun: async (id: string, from: number): Promise<ToolRun> => localToolRun(id, from),
  cancelTool: async (id: string): Promise<void> => cancelLocalTool(id),
};

// Webhooks' shown URLs in the preview.
const previewHooks = new Map<string, WebhookStatus>();

// When the sample's lists were refreshed on the Aliases page.
const tableFetched = new Map<string, string>();

function sampleRefresh(fetched: string, hours?: number): RefreshState {
  const every = hours ?? 24;
  return { everyHours: every, next: new Date(Date.parse(fetched) + every * 3600_000).toISOString() };
}

// Connections closed on the Connections page, gone from the sample.
const closedStates = new Set<string>();

