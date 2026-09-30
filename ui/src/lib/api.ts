// Client for OPF's JSON API (docs/api.md). Every call either returns
// the resource or throws an ApiError carrying the server's error code.

import type { Model, NatRule, PortForward, Rule, Section } from '../model/types';

const API_BASE = '/api';

// The shared preview build has no backend; its stand-in API
// (localApi.ts) runs the Go generators compiled to WebAssembly.
export const offline = import.meta.env.MODE === 'preview';

export type ErrorCode =
  | 'invalid' | 'conflict' | 'not_found' | 'nothing_staged' | 'commit_pending' | 'not_pending'
  | 'modified_outside' | 'check_failed' | 'unsupported' | 'internal';

export interface ErrorDetail {
  path: string;
  message?: string;
  output?: string;
}

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: ErrorCode,
    message: string,
    readonly details: ErrorDetail[] = [],
  ) {
    super(message);
  }
}

export interface ConfigResource {
  version: string;
  model: Model;
}

export interface FileChange {
  path: string;
  status: 'added' | 'modified' | 'removed';
  diff: string;
  needsConfirm?: boolean;
  model?: boolean;
  modifiedOutside?: boolean;
}

export interface StagedResource {
  version: string;
  base: string;
  model: Model;
  changes: FileChange[];
}

export interface ChangeNote {
  area: Section;
  summary: string;
}

export type CommitStatus = 'applying' | 'pending' | 'applied' | 'confirmed' | 'reverted' | 'failed';

export interface CommitResource {
  id: string;
  time: string;
  status: CommitStatus;
  deadline?: string;
  message: string;
  changes: ChangeNote[];
  files: { path: string; created?: boolean; removed?: boolean; needsConfirm?: boolean; model?: boolean }[];
}

export interface CommitDetail extends CommitResource {
  diffs: { path: string; diff: string }[];
  log: string;
}

/** What the DHCP lease watcher last did (GET /api/dns/leases). */
export interface LeaseNamesResource {
  enabled: boolean;
  checked?: string;
  /** from: what the device asked for, when the name was rewritten from it (sanitized). */
  registered: { name: string; ip: string; from?: string }[];
  /** Hostnames are chosen by the devices; the server has sanitized them. */
  refused: { ip: string; hostname: string; reason: string }[];
  truncated?: boolean;
  error?: string;
}

/** dhcpd's current leases (GET /api/dhcp/leases), by address. */
export interface DhcpLeasesResource {
  leases: {
    ip: string;
    mac?: string;
    /** What the device asked to be called; chosen by it, sanitized by the server. */
    hostname?: string;
    iface?: string;
    starts?: string;
    /** Absent: the lease doesn't end. */
    ends?: string;
    dnsName?: string;
    dnsRefused?: string;
  }[];
  truncated?: boolean;
  error?: string;
}

/** System ARP table (GET /api/network/arp). */
export interface ARPTableResource {
  entries: {
    ip: string;
    mac: string;
    iface: string;
    expires?: string;
    flags?: string;
    hostname?: string;
  }[];
  error?: string;
}

/** The machine (GET /api/system). Parts that couldn't be read are missing, with a line in errors each. */
export interface SystemResource {
  hostname: string;
  release: string;
  version: string;
  machine: string;
  cpuModel: string;
  vendor?: string;
  product?: string;
  cpus: number;
  bootedAt?: string;
  load?: [number, number, number];
  /** Percent of time in each state over the last few seconds. */
  cpu?: { user: number; nice: number; system: number; spin: number; interrupt: number; idle: number };
  /** Bytes; in use is total minus free. */
  memory?: { total: number; free: number; active: number; inactive: number };
  swap?: { total: number; used: number };
  disks: { device: string; mount: string; total: number; used: number; available: number }[];
  sensors: { device: string; type: string; index: number; value: string; number?: number; unit?: string; description?: string; status?: string }[];
  /** OpenNTPD's state; missing when ntpd isn't running. */
  time?: { synced: boolean; stratum?: number; status: string; source?: string; offsetMs?: number };
  errors: string[];
}

export interface WgPeerState {
  publicKey: string;
  description?: string;
  endpoint?: string;
  txBytes: number;
  rxBytes: number;
  /** Seconds since the last handshake; missing if there hasn't been one. */
  handshakeAgo?: number;
  allowedIps: string[];
}

/** An interface as the system has it, by device name. */
export interface InterfaceState {
  name: string;
  flags: string[];
  up: boolean;
  running: boolean;
  mtu?: number;
  mac?: string;
  description?: string;
  media?: string;
  /** Link: "active", "no carrier"; missing when the driver doesn't say. */
  status?: string;
  groups: string[];
  ipv4: string[];
  ipv6: string[];
  vlan?: { id: number; parent: string };
  carp?: { state: string; device: string; vhid: number; advskew: number };
  wireguard?: { port?: number; publicKey?: string; peers: WgPeerState[] };
  counters?: { rxBytes: number; txBytes: number; rxPackets: number; txPackets: number; rxErrors: number; txErrors: number; collisions: number };
  /** Bits per second over the last few seconds. */
  rxBps?: number;
  txBps?: number;
}

/** GET /api/network/interfaces */
export interface InterfacesResource {
  interfaces: InterfaceState[];
  errors: string[];
}

/** GET /api/network/gateways: each gateway's health, by gateway id. */
export interface GatewaysResource {
  gateways: Record<string, { address?: string; online: boolean; lossPct: number; rttMs?: number; error?: string }>;
}

/** GET /api/system/updates */
export interface UpdatesResource {
  checkedAt?: string;
  checking: boolean;
  patches: string[];
  error?: string;
}

/** pf's own state (GET /api/pf/status). */
export interface PfStatusResource {
  info?: {
    enabled: boolean;
    /** Seconds since pf was enabled. */
    enabledFor?: number;
    debug?: string;
    states: number;
    halfOpenTcp: number;
    /** Totals since pf was enabled, by pfctl's names (match, state-mismatch...). */
    counters: Record<string, number>;
    /** Traffic on the statistics interface (set loginterface). */
    iface?: { name: string; bytesIn: number; bytesOut: number; packetsInPassed: number; packetsInBlocked: number; packetsOutPassed: number; packetsOutBlocked: number };
  };
  stateLimit?: number;
  /** Packets blocked per second on the statistics interface, lately. */
  blockedPerSec?: number;
  errors: string[];
}

/** One entry of pf's state table. */
export interface PfState {
  id: string;
  creatorId: string;
  /** The interface it's bound to, or "all". */
  iface: string;
  proto: string;
  direction: 'in' | 'out';
  /** The ends as the device that opened the connection sees them. */
  source: string;
  destination: string;
  /** The other side of NAT or a port forward, when there is one. */
  translated?: string;
  state: string;
  ageSec: number;
  expiresSec: number;
  packets: number;
  bytes: number;
  rule: number;
  /** The label of the rule that created it. */
  label?: string;
}

/** GET /api/pf/states */
export interface PfStatesResource {
  states: PfState[];
  truncated?: boolean;
  error?: string;
}

/** GET /api/pf/rules/counters: counters by OPF label. */
export interface RuleCountersResource {
  labels: Record<string, { evaluations: number; packets: number; bytes: number; states: number }>;
  error?: string;
}

/** A packet pf logged. */
export interface FirewallLogEntry {
  time: string;
  /** pf's number for the rule; -1 is pf's default rule (no rule, pf itself). */
  rule: number;
  anchor?: string;
  reason: string;
  action: string;
  direction: 'in' | 'out';
  /** The device it was logged on. */
  iface: string;
  proto?: string;
  source?: string;
  destination?: string;
  info?: string;
  /** The label of the rule that logged it, when that's known. */
  label?: string;
}

/** GET /api/logs/firewall, newest first. */
export interface FirewallLogResource {
  entries: FirewallLogEntry[];
  /** When the loaded rules may last have changed; entries before it have no label. */
  rulesSince?: string;
  error?: string;
}

/** System routing table (GET /api/network/routes). */
export interface RoutingTableResource {
  ipv4: {
    destination: string;
    gateway: string;
    flags: string;
    iface: string;
    priority?: number;
    source?: string;
  }[];
  ipv6?: {
    destination: string;
    gateway: string;
    flags: string;
    iface: string;
    priority?: number;
    source?: string;
  }[];
  error?: string;
}

/** Where a pf.conf line came from, so the UI can link to it. */
export interface Origin {
  label: string;
  to: string;
}

export interface PfLine {
  text: string;
  origin?: Origin;
}

export interface GeneratedFile {
  path: string;
  content: string;
}

/** What the pages show that the generators work out (internal/pf Derive). */
export interface Derived {
  automaticNat: NatRule[];
  /** "Your networks" as a VPN device's configuration lists them. */
  localNetworks: string[];
  /** Each rule's pf text, by rule id. */
  rules: Record<string, string>;
  /** Whether a reference to each interface is in parentheses by default. */
  dynamicIfaces: Record<string, boolean>;
  selfDynamic: boolean;
}

/** One object's pf text: its description as a comment, and its rules. */
export interface Rendered {
  comment?: string;
  lines: string[];
}

export type RenderTarget = { rule: Rule } | { nat: NatRule } | { forward: PortForward };

export interface StatusResource {
  live: string;
  staged?: string;
  pending?: CommitResource;
  /** The running OpenBSD release, such as 7.9. */
  release?: string;
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    method,
    headers: body === undefined ? {} : { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (response.status === 204) return undefined as T;
  const text = await response.text();
  let data: unknown;
  try {
    data = text ? JSON.parse(text) : undefined;
  } catch {
    throw new ApiError(response.status, 'internal', `The server sent something that isn't JSON (HTTP ${response.status}).`);
  }
  if (!response.ok) {
    const e = (data as { error?: { code: ErrorCode; message: string; details?: ErrorDetail[] } })?.error;
    throw new ApiError(response.status, e?.code ?? 'internal', e?.message ?? `HTTP ${response.status}`, e?.details ?? []);
  }
  return data as T;
}

const enc = encodeURIComponent;

export const api = {
  status: () => request<StatusResource>('GET', '/status'),
  live: () => request<ConfigResource>('GET', '/config'),
  /** The staged model, or null when nothing is staged. */
  staged: async () => {
    try {
      return await request<StagedResource>('GET', '/config/staged');
    } catch (e) {
      if (e instanceof ApiError && e.code === 'nothing_staged') return null;
      throw e;
    }
  },
  stage: (base: string, model: Model, overwrite?: string[]) =>
    request<StagedResource>('PUT', '/config/staged', { base, model, ...(overwrite?.length ? { overwrite } : {}) }),
  discard: () => request<void>('DELETE', '/config/staged'),
  commits: () => request<CommitResource[]>('GET', '/commits'),
  commit: (id: string) => request<CommitDetail>('GET', `/commits/${enc(id)}`),
  createCommit: (staged: string, message: string, changes: ChangeNote[]) =>
    request<CommitResource>('POST', '/commits', { staged, message, changes }),
  confirm: (id: string) => request<CommitResource>('POST', `/commits/${enc(id)}/confirm`),
  revert: (id: string) => request<CommitResource>('POST', `/commits/${enc(id)}/revert`),
  /** The configuration before or after a commit. Restoring it is staging it. */
  commitConfig: (id: string, which: 'before' | 'after') => request<ConfigResource>('GET', `/commits/${enc(id)}/config/${which}`),
  leaseNames: () => request<LeaseNamesResource>('GET', '/dns/leases'),
  dhcpLeases: () => request<DhcpLeasesResource>('GET', '/dhcp/leases'),
  arpTable: () => request<ARPTableResource>('GET', '/network/arp'),
  routingTable: () => request<RoutingTableResource>('GET', '/network/routes'),
  system: () => request<SystemResource>('GET', '/system'),
  updates: () => request<UpdatesResource>('GET', '/system/updates'),
  interfaces: () => request<InterfacesResource>('GET', '/network/interfaces'),
  gateways: () => request<GatewaysResource>('GET', '/network/gateways'),
  pfStatus: () => request<PfStatusResource>('GET', '/pf/status'),
  pfStates: () => request<PfStatesResource>('GET', '/pf/states'),
  /** Ends a connection. It's gone at once; the device can reconnect if the rules allow. */
  killState: (s: Pick<PfState, 'id' | 'creatorId'>) => request<void>('POST', '/pf/states/kill', { id: s.id, creatorId: s.creatorId }),
  ruleCounters: () => request<RuleCountersResource>('GET', '/pf/rules/counters'),
  firewallLog: () => request<FirewallLogResource>('GET', '/logs/firewall'),

  /** A model's pf.conf, each line with where it came from. */
  pfRuleset: async (model: Model) => (await request<{ lines: PfLine[] }>('POST', '/pf/ruleset', { model })).lines,
  pfDerived: (model: Model) => request<Derived>('POST', '/pf/derived', { model }),
  /** The pf text for one rule, NAT rule or port forward. */
  pfRender: (model: Model, target: RenderTarget) => request<Rendered>('POST', '/pf/render', { model, ...target }),
  /** A guided rule parsed from pf text, or undefined if the form can't hold it. */
  parseRule: async (text: string, model?: Model): Promise<Rule | undefined> => {
    try {
      const { rule } = await request<{ rule: Rule }>('POST', '/pf/parse', { text, model });
      return rule.kind === 'form' ? rule : undefined;
    } catch (e) {
      if (e instanceof ApiError && e.status === 422) return undefined;
      throw e;
    }
  },
};
