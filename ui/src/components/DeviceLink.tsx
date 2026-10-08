// A link to a device's page (Diagnostics › Devices), from wherever a
// device is shown: the traffic, the DNS activity, DHCP leases, ARP.
import type { ReactNode } from 'react';
import { Link } from 'react-router';
import { Anchor } from '@mantine/core';

export function DeviceLink({ deviceKey, children, size = 'sm', c }: { deviceKey: string; children: ReactNode; size?: string; c?: string }) {
  return <Anchor component={Link} to={`/diagnostics/devices/${encodeURIComponent(deviceKey)}`} size={size} c={c}>{children}</Anchor>;
}

/** The key a device is kept under, from its MAC address. */
export const macKey = (mac: string) => `mac:${mac.toLowerCase()}`;
