// Whether the firewall can look a WireGuard peer's host name up, shown
// under the field as it's entered. netstart sets the peer with
// ifconfig, which looks the name up then: one that doesn't resolve
// holds up every commit while it waits, and the tunnel never connects.
import { useEffect, useState } from 'react';
import { Alert, Text } from '@mantine/core';
import { useDebouncedValue } from '@mantine/hooks';
import { IconAlertTriangle } from '@tabler/icons-react';
import { backend } from '../model/store';
import type { HostLookup } from '../lib/api';

/** The host name in host:port, or undefined for an address or something that isn't host:port yet. */
export function peerHostName(endpoint: string): string | undefined {
  const m = /^([A-Za-z0-9.-]+):\d{1,5}$/.exec(endpoint.trim());
  if (!m || /^[0-9.]+$/.test(m[1]) || !/[A-Za-z]/.test(m[1])) return undefined;
  return m[1].replace(/\.$/, '').toLowerCase();
}

export function PeerNameCheck({ endpoint }: { endpoint: string }) {
  const [host] = useDebouncedValue(peerHostName(endpoint), 600);
  const [found, setFound] = useState<{ host: string; lookup?: HostLookup }>();
  useEffect(() => {
    if (!host) return;
    let live = true;
    setFound({ host });
    // A refusal (a viewer's role, the preview) shows nothing.
    backend.lookupHost(host).then((lookup) => live && setFound({ host, lookup }), () => live && setFound(undefined));
    return () => { live = false; };
  }, [host]);
  if (!host || found?.host !== host || peerHostName(endpoint) !== host) return null;
  const l = found.lookup;
  if (!l) return <Text size="xs" c="dimmed">Looking up {host} on the firewall…</Text>;
  const slow = l.seconds >= 2 ? ` The lookup took ${Math.round(l.seconds)} s, which every commit waits too.` : '';
  if (l.addresses.length) {
    return <Text size="xs" c={slow ? 'yellow' : 'dimmed'}>The firewall finds {host} at {l.addresses.join(', ')}.{slow}</Text>;
  }
  return (
    <Alert color="yellow" variant="light" p="sm" icon={<IconAlertTriangle size={16} />} title={`The firewall can’t look up ${host}`}>
      <Text size="sm">
        {l.error ? `The lookup failed: ${l.error}.` : 'It finds no address for that name.'} Until it can, the tunnel doesn’t connect, and every commit waits while the firewall tries.
        Check the name, or enter the server’s address instead.
      </Text>
    </Alert>
  );
}
