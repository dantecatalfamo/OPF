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
  /** Other words it's found by in the command palette. */
  keywords?: string;
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
      { label: 'All devices', to: '/devices', keywords: 'hosts clients machines computers' },
      { label: 'Traffic', to: '/devices/traffic', keywords: 'bandwidth usage bytes per device top talkers' },
      { label: 'ARP table', to: '/devices/arp', keywords: 'mac addresses neighbours neighbors' },
    ],
  },
  {
    label: 'Network', icon: IconNetwork, items: [
      { label: 'Interfaces', to: '/interfaces', keywords: 'ports nics network cards vlan wan lan ip address' },
      { label: 'Routing', to: '/network/routing', keywords: 'routes default route' },
    ],
  },
  {
    label: 'Firewall', icon: IconShieldHalf, items: [
      { label: 'Rules', to: '/firewall/rules', keywords: 'filter pass block allow deny policy' },
      { label: 'NAT', to: '/firewall/nat', keywords: 'network address translation masquerade' },
      { label: 'Aliases', to: '/firewall/aliases', keywords: 'tables lists groups of addresses url lists' },
      { label: 'Connections', to: '/firewall/connections', keywords: 'states state table sessions kill close' },
      { label: 'Firewall log', to: '/firewall/log', keywords: 'pflog blocked packets logged' },
      { label: 'Ruleset', to: '/firewall/ruleset', keywords: 'pf.conf generated rules raw' },
      { label: 'Settings', to: '/firewall/settings', keywords: 'firewall options pf' },
    ],
  },
  {
    label: 'Services', icon: IconServer2, items: [
      { label: 'DHCP server', to: '/services/dhcp', keywords: 'dhcpd leases address pool range' },
      { label: 'DNS resolver', to: '/services/dns', keywords: 'unbound name server dns' },
      { label: 'WireGuard VPN', to: '/services/wireguard', keywords: 'vpn tunnels peers remote access wg' },
    ],
  },
  {
    label: 'Monitoring', icon: IconActivity, items: [
      { label: 'Graphs', to: '/monitoring/graphs', keywords: 'charts history metrics cpu memory' },
      { label: 'Events', to: '/monitoring/events', keywords: 'event log alerts what happened' },
      { label: 'Tools', to: '/monitoring/tools', keywords: 'diagnostics ping traceroute dns lookup port test' },
    ],
  },
  {
    label: 'System', icon: IconSettings, items: [
      { label: 'General', to: '/system/general', keywords: 'hostname domain time zone clock ntp' },
      { label: 'Users', to: '/system/users', admin: true, keywords: 'accounts admins roles operators' },
      { label: 'Notifications', to: '/system/notifications', keywords: 'webhooks alerts slack' },
      { label: 'Change history', to: '/system/history', keywords: 'commits revert undo audit changes' },
      { label: 'System logs', to: '/system/logs', keywords: 'syslog messages daemon' },
      { label: 'Configuration files', to: '/system/files', keywords: 'files /etc config' },
      { label: 'Storage', to: '/system/storage', keywords: 'disk space usage limits size memory' },
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

/** A tab or a card within a page, for the command palette. */
export interface Place {
  label: string;
  /** The page it's on, as the sidebar names it. */
  page: string;
  to: string;
  keywords?: string;
  admin?: boolean;
}

export const places: Place[] = [
  // Devices
  { label: 'Traffic per device', page: 'Firewall › Settings', to: '/firewall/settings#traffic', keywords: 'count bandwidth keep days devices' },
  // Network
  { label: 'Gateways', page: 'Routing', to: '/network/routing/gateways', keywords: 'gateway monitoring latency loss default' },
  { label: 'Static routes', page: 'Routing', to: '/network/routing/routes', keywords: 'route network via' },
  { label: 'Routing table', page: 'Routing', to: '/network/routing/table', keywords: 'netstat routes kernel' },
  // Firewall
  { label: 'Floating rules', page: 'Rules', to: '/firewall/rules/floating', keywords: 'several interfaces groups' },
  { label: 'Port forwarding', page: 'NAT', to: '/firewall/nat/forwards', keywords: 'forward port open inbound rdr redirect' },
  { label: 'Outbound NAT', page: 'NAT', to: '/firewall/nat/outbound', keywords: 'masquerade source nat hybrid manual' },
  { label: 'Blocking', page: 'Firewall › Settings', to: '/firewall/settings#blocking', keywords: 'block policy drop return reject' },
  { label: 'Connection tracking', page: 'Firewall › Settings', to: '/firewall/settings#connections', keywords: 'states timeouts optimization' },
  { label: 'Packet normalization (scrub)', page: 'Firewall › Settings', to: '/firewall/settings#scrub', keywords: 'scrub mss fragments' },
  { label: 'Limits', page: 'Firewall › Settings', to: '/firewall/settings#limits', keywords: 'table entries states maximum memory' },
  // Services
  { label: 'Reserved addresses', page: 'DHCP server', to: '/services/dhcp#reservations', keywords: 'static lease fixed address reserve' },
  { label: 'Connected devices', page: 'DHCP server', to: '/services/dhcp#leases', keywords: 'leases clients' },
  { label: 'Overview', page: 'DNS resolver', to: '/services/dns?tab=overview', keywords: 'queries cache hits stats' },
  { label: 'Activity', page: 'DNS resolver', to: '/services/dns?tab=activity', keywords: 'top names looked up queries per device history' },
  { label: 'Local names', page: 'DNS resolver', to: '/services/dns?tab=names', keywords: 'host overrides records a aaaa cname ptr mx domains zones' },
  { label: 'Settings', page: 'DNS resolver', to: '/services/dns?tab=settings', keywords: 'forwarders forwarding dnssec dns over tls answer on interfaces' },
  { label: 'DNS activity settings', page: 'DNS resolver › Settings', to: '/services/dns?tab=settings#activity', keywords: 'keep retention days devices' },
  { label: 'Blocking', page: 'DNS resolver', to: '/services/dns?tab=blocking', keywords: 'blocklists block lists ad blocking adblock ads trackers malware rpz never block allow' },
  { label: 'Tools', page: 'DNS resolver', to: '/services/dns?tab=tools', keywords: 'cache lookup flush test a name' },
  // Monitoring
  { label: 'Ping', page: 'Tools', to: '/monitoring/tools?tool=ping', keywords: 'icmp reachable latency mtu' },
  { label: 'Traceroute', page: 'Tools', to: '/monitoring/tools?tool=traceroute', keywords: 'path hops route' },
  { label: 'DNS lookup', page: 'Tools', to: '/monitoring/tools?tool=dns', keywords: 'resolve name dig nslookup host' },
  { label: 'Port test', page: 'Tools', to: '/monitoring/tools?tool=port', keywords: 'tcp udp open port reachable nc' },
  // System
  { label: 'Identity and time', page: 'System › General', to: '/system/general#identity', keywords: 'hostname domain time zone ntp servers clock' },
  { label: 'DNS for the firewall itself', page: 'System › General', to: '/system/general#system-dns', keywords: 'resolv.conf nameservers own dns servers' },
  { label: 'Graphs', page: 'System › General', to: '/system/general#graphs', keywords: 'keep history series' },
  { label: 'Updates', page: 'System › General', to: '/system/general#updates', keywords: 'syspatch patches upgrade security fixes' },
  { label: 'Your account', page: 'System › General', to: '/system/general#account', keywords: 'password sign out' },
  { label: 'Signed in now', page: 'Users', to: '/system/users#sessions', keywords: 'sessions sign out', admin: true },
  { label: 'Messages', page: 'System logs', to: '/system/logs?log=messages', keywords: '/var/log/messages kernel syslog' },
  { label: 'Daemons', page: 'System logs', to: '/system/logs?log=daemon', keywords: '/var/log/daemon unbound dhcpd services' },
  { label: 'Logins', page: 'System logs', to: '/system/logs?log=authlog', keywords: '/var/log/authlog ssh doas authentication' },
  { label: 'Mail', page: 'System logs', to: '/system/logs?log=maillog', keywords: '/var/log/maillog smtpd' },
  { label: 'Kernel', page: 'System logs', to: '/system/logs?log=dmesg', keywords: 'dmesg boot hardware drivers' },
];
