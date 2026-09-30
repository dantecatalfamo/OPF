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
