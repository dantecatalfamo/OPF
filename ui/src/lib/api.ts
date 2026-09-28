// API client for pf.conf parsing and generation endpoints.

import type { Model, Rule } from '../model/types';
import { generateFiles, ruleText } from '../model/generate';

const API_BASE = '/api';

// The shared preview build has no backend. It uses the TypeScript
// generator instead, and can't parse pf text back into a form.
const offline = import.meta.env.MODE === 'preview';

export interface ParseRuleResponse {
  rule?: Rule;
  error?: string;
}

export interface GenerateRuleResponse {
  text?: string;
  error?: string;
}

export interface GenerateConfigResponse {
  content?: string;
  error?: string;
}

/**
 * Parse a pf rule from syntax text into a Rule object.
 * Returns a FormRule if the syntax can be represented in the form,
 * otherwise returns a RawRule.
 */
export async function parseRule(rule: string, model?: Model): Promise<ParseRuleResponse> {
  if (offline) return { error: 'Not available in the preview' };
  const response = await fetch(`${API_BASE}/parse-rule`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ rule, model }),
  });

  if (!response.ok) {
    const text = await response.text();
    return { error: `HTTP ${response.status}: ${text}` };
  }

  return response.json();
}

/**
 * Generate pf.conf syntax from a Rule object.
 * This is used for the preview in the rule drawer.
 */
export async function generateRule(rule: Rule, model?: Model): Promise<GenerateRuleResponse> {
  if (offline && model) return { text: ruleText(rule, model) };
  const response = await fetch(`${API_BASE}/generate-rule`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ rule, model }),
  });

  if (!response.ok) {
    const text = await response.text();
    return { error: `HTTP ${response.status}: ${text}` };
  }

  return response.json();
}

/**
 * Generate a full config file from the model.
 * @param model - The configuration model
 * @param file - The file to generate: "pf.conf", "dhcpd.conf", "unbound.conf", or "hostname.<device>"
 */
export async function generateConfig(model: Model, file: string = 'pf.conf'): Promise<GenerateConfigResponse> {
  if (offline) {
    const f = generateFiles(model).find((x) => x.path.endsWith(`/${file}`));
    return f ? { content: f.content } : { error: `unknown file: ${file}` };
  }
  const response = await fetch(`${API_BASE}/generate-config`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ model, file }),
  });

  if (!response.ok) {
    const text = await response.text();
    return { error: `HTTP ${response.status}: ${text}` };
  }

  return response.json();
}

/**
 * Try to parse pf syntax into a FormRule.
 * Returns the rule if successful, or undefined if it can't be converted.
 * Useful for the "Parse from pf syntax" feature in the rule drawer.
 */
export async function tryParseAsFormRule(text: string, model?: Model): Promise<Rule | undefined> {
  const result = await parseRule(text, model);
  if (result.error || !result.rule) {
    return undefined;
  }
  // Only return if it was parsed as a FormRule
  if (result.rule.kind === 'form') {
    return result.rule;
  }
  return undefined;
}

// ---------- Model-Authoritative API ----------

export interface GeneratedFile {
  path: string;
  content: string;
}

export interface PreviewResponse {
  files: GeneratedFile[];
  error?: string;
}

/**
 * Preview what files would be generated from a model.
 * This uses the backend generator (single source of truth).
 */
export async function previewModel(model: Model): Promise<PreviewResponse> {
  if (offline) return { files: generateFiles(model) };
  const response = await fetch(`${API_BASE}/model/preview`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(model),
  });

  if (!response.ok) {
    const text = await response.text();
    return { files: [], error: `HTTP ${response.status}: ${text}` };
  }

  return response.json();
}

export interface FileError {
  path: string;
  error: string;
  output?: string;
}

export interface ApplyResponse {
  files: GeneratedFile[];
  staged: number;
  error?: string;
  details?: FileError[];
}

/**
 * Apply a model: generate files, validate, and stage for commit.
 * This is the model-authoritative way to apply changes.
 */
export async function applyModel(model: Model): Promise<ApplyResponse> {
  if (offline) {
    const files = generateFiles(model);
    return { files, staged: files.length };
  }
  const response = await fetch(`${API_BASE}/model/apply`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ model }),
  });

  if (!response.ok) {
    const text = await response.text();
    return { files: [], staged: 0, error: `HTTP ${response.status}: ${text}` };
  }

  return response.json();
}
