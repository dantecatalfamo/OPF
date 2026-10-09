// A link to a device's page (Devices), from wherever a
// device is shown: the traffic, the DNS activity, DHCP leases, ARP,
// connections.
import { useEffect, useState, type ReactNode } from 'react';
import { Link } from 'react-router';
import { Anchor, Text, Tooltip } from '@mantine/core';
import { backend } from '../model/store';
import type { DeviceInfo } from '../lib/api';
import { hostOf } from '../lib/reverseNames';

export function DeviceLink({ deviceKey, children, size = 'sm', c }: { deviceKey: string; children: ReactNode; size?: string; c?: string }) {
  return <Anchor component={Link} to={`/devices/${encodeURIComponent(deviceKey)}`} size={size} c={c}>{children}</Anchor>;
}

/** The key a device is kept under, from its MAC address. */
export const macKey = (mac: string) => `mac:${mac.toLowerCase()}`;

// The devices OPF knows, by address, for pages that show bare addresses
// (Connections): read once a minute, and an address-only device isn't
// one it knows.
const DEVICES_MS = 60_000;
let known: { at: number; byAddr: Map<string, DeviceInfo> } | undefined;

export function useKnownDevices(): Map<string, DeviceInfo> {
  const [byAddr, setByAddr] = useState(known?.byAddr ?? new Map<string, DeviceInfo>());
  useEffect(() => {
    let live = true;
    const load = () => {
      if (known && Date.now() - known.at < DEVICES_MS) {
        setByAddr(known.byAddr);
        return;
      }
      backend.devices().then((r) => {
        const m = new Map<string, DeviceInfo>();
        for (const d of r.devices) if (d.kind !== 'address') for (const a of d.addresses) m.set(a, d);
        known = { at: Date.now(), byAddr: m };
        if (live) setByAddr(m);
      }, () => {});
    };
    load();
    const t = setInterval(load, DEVICES_MS);
    return () => { live = false; clearInterval(t); };
  }, []);
  return byAddr;
}

/** An address, with or without a port, linked to its device's page when
 *  it's a device OPF knows. */
export function AddressLink({ end, devices }: { end: string; devices: Map<string, DeviceInfo> }) {
  const d = devices.get(hostOf(end) ?? '');
  if (!d) return <Text span className="mono" size="sm">{end}</Text>;
  return (
    <Tooltip label={`${d.name || d.mac || d.key}: open its device page`}>
      <Anchor component={Link} to={`/devices/${encodeURIComponent(d.key)}`} size="sm" className="mono">{end}</Anchor>
    </Tooltip>
  );
}
