import { Switch, Text, Tooltip } from '@mantine/core';
import { hostOf } from '../lib/reverseNames';

/** An address's reverse name, under it, when it has one. The name comes
 *  from whoever runs the address's reverse zone: text, never markup. */
export function HostName({ addr, names }: { addr?: string; names: Map<string, string> }) {
  const h = hostOf(addr);
  const n = h && names.get(h);
  if (!n) return null;
  return <Text size="xs" c="dimmed" className="mono" title={n}><Wrapped name={n} /></Text>;
}

/** A host name that wraps only after its dots. */
export function Wrapped({ name }: { name: string }) {
  const parts = name.split('.');
  return <>{parts.map((p, i) => <span key={i}>{p}{i < parts.length - 1 && <>.<wbr /></>}</span>)}</>;
}

/** Turns names on or off, for every page that shows them. */
export function NamesSwitch({ checked, onChange }: { checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <Tooltip multiline w={300} label="Show each address’s name, looked up with reverse DNS through the firewall’s own resolver. For an address on the internet, the lookup goes to whoever runs that address’s reverse DNS.">
      <Switch label="Names" checked={checked} onChange={(e) => onChange(e.currentTarget.checked)} />
    </Tooltip>
  );
}
