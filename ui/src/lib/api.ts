// Client for OPF's JSON API (docs/api.md). Every call either returns
// the resource or throws an ApiError carrying the server's error code.

import type { Model, Rule, Section } from '../model/types';
import { ruleText } from '../model/generate';

const API_BASE = '/api';

// The shared preview build has no backend; the store simulates the
// server there, and the pf helpers fall back to the TypeScript
// generator.
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
  status: 'added' | 'modified';
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
  files: { path: string; created?: boolean; needsConfirm?: boolean; model?: boolean }[];
}

export interface CommitDetail extends CommitResource {
  diffs: { path: string; diff: string }[];
  log: string;
}

/** What the DHCP lease watcher last did (GET /api/dns/leases). */
export interface LeaseNamesResource {
  enabled: boolean;
  checked?: string;
  registered: { name: string; ip: string }[];
  /** Hostnames are chosen by the devices; the server has sanitized them. */
  refused: { ip: string; hostname: string; reason: string }[];
  truncated?: boolean;
  error?: string;
}

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

  /** pf rule text for a rule. */
  renderRule: async (rule: Rule, model?: Model): Promise<string> => {
    if (offline && model) return ruleText(rule, model);
    return (await request<{ text: string }>('POST', '/pf/render', { rule, model })).text;
  },
  /** A guided rule parsed from pf text, or undefined if the form can't hold it. */
  parseRule: async (text: string, model?: Model): Promise<Rule | undefined> => {
    if (offline) return undefined;
    try {
      const { rule } = await request<{ rule: Rule }>('POST', '/pf/parse', { text, model });
      return rule.kind === 'form' ? rule : undefined;
    } catch (e) {
      if (e instanceof ApiError && e.status === 422) return undefined;
      throw e;
    }
  },
};
