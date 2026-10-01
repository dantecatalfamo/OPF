import type { Section } from '../model/types';

export const sectionLabel: Record<Section, string> = {
  system: 'System',
  interfaces: 'Interfaces',
  routing: 'Routing',
  firewall: 'Firewall',
  dhcp: 'DHCP server',
  dns: 'DNS resolver',
  wireguard: 'WireGuard VPN',
  notifications: 'Notifications',
};
