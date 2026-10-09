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
  /** Shown in read-only mode too: it only watches the machine. The rest
   *  are about OPF's own configuration, which a machine it only
   *  monitors doesn't have. */
  monitors?: boolean;
  /** Only while OPF doesn't manage the machine yet: read-only, or
   *  before its first commit. */
  takeOver?: boolean;
}
export interface NavGroup {
  label: string;
  icon: typeof IconGauge;
  to?: string;
  items?: NavItem[];
  monitors?: boolean;
}

export const nav: NavGroup[] = [
  { label: 'Dashboard', icon: IconGauge, to: '/', monitors: true },
  {
    label: 'Devices', icon: IconDevices, items: [
      { label: 'All devices', to: '/devices', keywords: 'hosts clients machines computers', monitors: true },
      { label: 'Traffic', to: '/devices/traffic', keywords: 'bandwidth usage bytes per device top talkers' },
      { label: 'ARP table', to: '/devices/arp', keywords: 'mac addresses neighbours neighbors', monitors: true },
    ],
  },
  {
    label: 'Network', icon: IconNetwork, items: [
      { label: 'Interfaces', to: '/interfaces', keywords: 'ports nics network cards vlan wan lan ip address', monitors: true },
      { label: 'Routing', to: '/network/routing', keywords: 'routes default route', monitors: true },
    ],
  },
  {
    label: 'Firewall', icon: IconShieldHalf, items: [
      { label: 'Rules', to: '/firewall/rules', keywords: 'filter pass block allow deny policy' },
      { label: 'NAT', to: '/firewall/nat', keywords: 'network address translation masquerade' },
      { label: 'Aliases', to: '/firewall/aliases', keywords: 'tables lists groups of addresses url lists' },
      { label: 'Connections', to: '/firewall/connections', keywords: 'states state table sessions kill close', monitors: true },
      { label: 'Firewall log', to: '/firewall/log', keywords: 'pflog blocked packets logged', monitors: true },
      { label: 'Statistics', to: '/firewall/stats', keywords: 'pf stats counters pfctl info memory limits timeouts interfaces state table congestion', monitors: true },
      { label: 'Sign-in access', to: '/firewall/authpf', keywords: 'authpf ssh sign in login contractors guests captive access while signed in' },
      { label: 'Ruleset', to: '/firewall/ruleset', keywords: 'pf.conf generated rules raw' },
      { label: 'Settings', to: '/firewall/settings', keywords: 'firewall options pf' },
    ],
  },
  {
    label: 'Services', icon: IconServer2, items: [
      { label: 'All services', to: '/services', keywords: 'daemons rcctl rc.d rc.conf start stop restart reload boot sshd ntpd smtpd', monitors: true },
      { label: 'DHCP server', to: '/services/dhcp', keywords: 'dhcpd leases address pool range' },
      { label: 'DNS resolver', to: '/services/dns', keywords: 'unbound name server dns' },
      { label: 'WireGuard VPN', to: '/services/wireguard', keywords: 'vpn tunnels peers remote access wg' },
    ],
  },
  {
    label: 'Monitoring', icon: IconActivity, items: [
      { label: 'Graphs', to: '/monitoring/graphs', keywords: 'charts history metrics cpu memory', monitors: true },
      { label: 'Events', to: '/monitoring/events', keywords: 'event log alerts what happened', monitors: true },
      { label: 'Tools', to: '/monitoring/tools', keywords: 'diagnostics ping traceroute dns lookup port test', monitors: true },
    ],
  },
  {
    label: 'System', icon: IconSettings, items: [
      { label: 'General', to: '/system/general', keywords: 'hostname domain time zone clock ntp' },
      { label: 'Users', to: '/system/users', admin: true, keywords: 'accounts admins roles operators' },
      { label: 'Notifications', to: '/system/notifications', keywords: 'webhooks alerts slack' },
      { label: 'Change history', to: '/system/history', keywords: 'commits revert undo audit changes' },
      { label: 'System logs', to: '/system/logs', keywords: 'syslog messages daemon', monitors: true },
      { label: 'Configuration files', to: '/system/files', keywords: 'files /etc config', monitors: true },
      { label: 'Take over', to: '/system/take-over', keywords: 'read-only monitor import manage control', monitors: true, takeOver: true },
      { label: 'Storage', to: '/system/storage', keywords: 'disk space usage limits size memory', monitors: true },
    ],
  },
];

const matches = (path: string, to: string) => (to === '/' ? path === '/' : path === to || path.startsWith(to + '/'));

// The page's item is the one whose path matches most of it: on
// /devices/traffic that's Traffic, not All devices; on a device's page,
// All devices.
const allPaths = nav.flatMap((g) => (g.to ? [g.to] : g.items!.map((i) => i.to)));
const allItems: (NavItem | NavGroup)[] = nav.flatMap((g): (NavItem | NavGroup)[] => (g.to ? [g] : g.items!));
export const activePath = (path: string) =>
  allPaths.filter((to) => matches(path, to)).sort((a, b) => b.length - a.length)[0];

/** Whether a sidebar item is shown, read-only or not, and whether OPF
 *  manages the machine yet. */
export const itemShown = (i: NavItem | NavGroup, readOnly: boolean, managed = true) => {
  if ('takeOver' in i && i.takeOver) return readOnly || !managed;
  return readOnly ? !!i.monitors : true;
};

/** Whether the page at a path is there, read-only or not: the page of
 *  the sidebar item it's under (a device's page is All devices'). */
export function pageShown(path: string, readOnly: boolean, managed = true) {
  const to = activePath(path);
  const item = allItems.find((i) => i.to === to);
  return !item || itemShown(item, readOnly, managed);
}

/** A tab or a card within a page, for the command palette. */
export interface Place {
  label: string;
  /** The page it's on, as the sidebar names it. */
  page: string;
  to: string;
  keywords?: string;
  admin?: boolean;
  /** false: not in read-only mode, though its page is (a tab of OPF's
   *  own configuration). */
  monitors?: false;
}

/** Whether a place is there, read-only or not. */
export const placeShown = (p: Place, readOnly: boolean) => !readOnly || (p.monitors !== false && pageShown(p.to.split(/[?#]/)[0], readOnly));

export const places: Place[] = [
  // Devices
  { label: 'Traffic per device', page: 'Firewall › Settings', to: '/firewall/settings#traffic', keywords: 'count bandwidth keep days devices' },
  // Network
  { label: 'Gateways', page: 'Routing', to: '/network/routing/gateways', keywords: 'gateway monitoring latency loss default', monitors: false },
  { label: 'Static routes', page: 'Routing', to: '/network/routing/routes', keywords: 'route network via', monitors: false },
  { label: 'Routing table', page: 'Routing', to: '/network/routing/table', keywords: 'netstat routes kernel' },
  // Firewall
  { label: 'Counters', page: 'Statistics', to: '/firewall/stats#counters', keywords: 'pf counters match state-mismatch congestion memory drops' },
  { label: 'Limit counters', page: 'Statistics', to: '/firewall/stats#limit-counters', keywords: 'max-src-conn overload syncookies synflood' },
  { label: 'State and source tables', page: 'Statistics', to: '/firewall/stats#tables', keywords: 'searches inserts removals source tracking fragments' },
  { label: 'Interface statistics', page: 'Statistics', to: '/firewall/stats#interfaces', keywords: 'passed blocked packets bytes per interface' },
  { label: 'Memory limits', page: 'Statistics', to: '/firewall/stats#memory', keywords: 'pfctl -s memory hard limit states tables' },
  { label: 'Timeouts', page: 'Statistics', to: '/firewall/stats#timeouts', keywords: 'tcp.established udp adaptive pfctl -s timeouts' },
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
  { label: 'Name and time zone', page: 'System › General', to: '/system/general#identity', keywords: 'hostname domain time zone clock' },
  { label: 'Time', page: 'System › General', to: '/system/general#time', keywords: 'ntp ntpd time servers clock sync sensors gps constraints serve time listen' },
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
