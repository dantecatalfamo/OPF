// The pages, in the sidebar's sections; the command palette finds them
// too.
import {
  IconActivity, IconDevices, IconGauge, IconNetwork, IconServer2, IconSettings, IconShieldHalf,
} from '@tabler/icons-react';

export interface NavItem {
  label: string;
  to: string;
  /** Only for admins (and servers without accounts). */
  admin?: boolean;
}
export interface NavGroup {
  label: string;
  icon: typeof IconGauge;
  to?: string;
  items?: NavItem[];
}

export const nav: NavGroup[] = [
  { label: 'Dashboard', icon: IconGauge, to: '/' },
  {
    label: 'Devices', icon: IconDevices, items: [
      { label: 'All devices', to: '/devices' },
      { label: 'Traffic', to: '/devices/traffic' },
      { label: 'ARP table', to: '/devices/arp' },
    ],
  },
  {
    label: 'Network', icon: IconNetwork, items: [
      { label: 'Interfaces', to: '/interfaces' },
      { label: 'Routing', to: '/network/routing' },
    ],
  },
  {
    label: 'Firewall', icon: IconShieldHalf, items: [
      { label: 'Rules', to: '/firewall/rules' },
      { label: 'NAT', to: '/firewall/nat' },
      { label: 'Aliases', to: '/firewall/aliases' },
      { label: 'Connections', to: '/firewall/connections' },
      { label: 'Firewall log', to: '/firewall/log' },
      { label: 'Ruleset', to: '/firewall/ruleset' },
      { label: 'Settings', to: '/firewall/settings' },
    ],
  },
  {
    label: 'Services', icon: IconServer2, items: [
      { label: 'DHCP server', to: '/services/dhcp' },
      { label: 'DNS resolver', to: '/services/dns' },
      { label: 'WireGuard VPN', to: '/services/wireguard' },
    ],
  },
  {
    label: 'Monitoring', icon: IconActivity, items: [
      { label: 'Graphs', to: '/monitoring/graphs' },
      { label: 'Events', to: '/monitoring/events' },
      { label: 'Tools', to: '/monitoring/tools' },
    ],
  },
  {
    label: 'System', icon: IconSettings, items: [
      { label: 'General', to: '/system/general' },
      { label: 'Users', to: '/system/users', admin: true },
      { label: 'Notifications', to: '/system/notifications' },
      { label: 'Change history', to: '/system/history' },
      { label: 'System logs', to: '/system/logs' },
      { label: 'Configuration files', to: '/system/files' },
      { label: 'Storage', to: '/system/storage' },
    ],
  },
];

const matches = (path: string, to: string) => (to === '/' ? path === '/' : path === to || path.startsWith(to + '/'));

// The page's item is the one whose path matches most of it: on
// /devices/traffic that's Traffic, not All devices; on a device's page,
// All devices.
const allPaths = nav.flatMap((g) => (g.to ? [g.to] : g.items!.map((i) => i.to)));
export const activePath = (path: string) =>
  allPaths.filter((to) => matches(path, to)).sort((a, b) => b.length - a.length)[0];
