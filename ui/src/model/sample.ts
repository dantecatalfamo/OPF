// Example data for the preview build: a small office gateway. None of
// this is anyone's real configuration.
import type { FormRule, HistoryEntry, Model } from './types';
import sampleModelJson from './sample-model.json';

export function formRule(r: Partial<FormRule> & Pick<FormRule, 'id' | 'interfaces' | 'description'>): FormRule {
  return {
    kind: 'form', enabled: true, action: 'pass', direction: 'in', quick: true, family: 'inet', protocol: 'any',
    source: { type: 'any' }, destination: { type: 'any' }, log: 'off', ...r,
  };
}

// The sample model lives in sample-model.json so the Go side can load
// it too: the mock server starts from it, and a Go test checks it
// decodes into the Go model without losing anything.
export const sampleModel = sampleModelJson as Model;

const hour = 3600_000;

function withRuleEnabled(m: Model, id: string, enabled: boolean): Model {
  return { ...m, firewall: { ...m.firewall, rules: m.firewall.rules.map((r) => (r.id === id ? { ...r, enabled } : r)) } };
}

// A little history for the offline preview, with the model before and
// after each commit so restoring works.
export interface SampleCommit {
  entry: HistoryEntry;
  before: Model;
  after: Model;
}

export function sampleHistory(now: number): SampleCommit[] {
  const prev = withRuleEnabled(sampleModel, 'r5', false);
  return [
    {
      entry: {
        id: '20260925-141203.000', time: now - 3 * hour, status: 'confirmed', message: 'Keep IoT devices off the LAN',
        changes: [{ id: 1, section: 'firewall', summary: 'Enabled rule “Keep IoT devices off the other networks” on IoT' }],
      },
      before: prev, after: sampleModel,
    },
    {
      entry: {
        id: '20260924-093340.000', time: now - 28 * hour, status: 'reverted', message: 'Renumber the LAN',
        changes: [{ id: 2, section: 'interfaces', summary: 'LAN: address set to 10.0.0.1/24' }],
      },
      before: prev, after: prev,
    },
    {
      entry: {
        id: '20260922-161512.000', time: now - 3 * 24 * hour, status: 'applied', message: 'Connect the warehouse',
        changes: [
          { id: 3, section: 'routing', summary: 'Added route 10.20.0.0/16 via WAREHOUSE' },
          { id: 4, section: 'wireguard', summary: 'Added VPN device “Warehouse router” on Sites (10.9.0.2/32)' },
        ],
      },
      before: prev, after: prev,
    },
  ];
}
