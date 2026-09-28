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

// A little history so the History page has something to show.
export function sampleHistory(now: number): HistoryEntry[] {
  const prev = withRuleEnabled(sampleModel, 'r5', false);
  return [
    {
      id: '20260925-141203', time: now - 3 * hour, user: 'admin', status: 'confirmed',
      changes: [{ id: 1, section: 'firewall', summary: 'Enabled rule “Keep IoT devices off the other networks” on IoT' }],
      before: prev, after: sampleModel,
    },
    {
      id: '20260924-093340', time: now - 28 * hour, user: 'admin', status: 'reverted',
      changes: [{ id: 2, section: 'interfaces', summary: 'LAN: address set to 10.0.0.1/24' }],
      before: prev, after: prev,
    },
    {
      id: '20260922-161512', time: now - 3 * 24 * hour, user: 'admin', status: 'applied',
      changes: [
        { id: 3, section: 'routing', summary: 'Added route 10.20.0.0/16 via WAREHOUSE' },
        { id: 4, section: 'wireguard', summary: 'Added VPN device “Warehouse router” (10.8.0.10/32)' },
      ],
      before: prev, after: prev,
    },
  ];
}
