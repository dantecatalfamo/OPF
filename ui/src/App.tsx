import { useEffect } from 'react';
import { BrowserRouter, MemoryRouter, Navigate, Route, Routes, useLocation } from 'react-router';
import { useMantineColorScheme } from '@mantine/core';
import { AppLayout } from './components/AppLayout';
import { Dashboard } from './pages/Dashboard';
import { Interfaces } from './pages/Interfaces';
import { InterfaceEdit } from './pages/InterfaceEdit';
import { FirewallRules } from './pages/FirewallRules';
import { Nat } from './pages/Nat';
import { Ruleset } from './pages/Ruleset';
import { FirewallSettings } from './pages/FirewallSettings';
import { Routing } from './pages/Routing';
import { Aliases } from './pages/Aliases';
import { Dhcp } from './pages/Dhcp';
import { Dns } from './pages/Dns';
import { WireGuardPage } from './pages/WireGuard';
import { SystemGeneral } from './pages/SystemGeneral';
import { Users } from './pages/Users';
import { History } from './pages/History';
import { Connections } from './pages/Connections';
import { Tools } from './pages/Tools';
import { Graphs } from './pages/Graphs';
import { Events } from './pages/Events';
import { Notifications } from './pages/Notifications';
import { SystemLogs } from './pages/SystemLogs';
import { ConfigFiles } from './pages/ConfigFiles';
import { Storage } from './pages/Storage';
import { Traffic } from './pages/Traffic';
import { Device, Devices } from './pages/Devices';
import { FirewallLog } from './pages/FirewallLog';
import { ARP } from './pages/ARP';

const preview = import.meta.env.MODE === 'preview';

// In the shared preview the host page sets data-theme on <html>; follow it.
function useHostTheme() {
  const { setColorScheme } = useMantineColorScheme();
  useEffect(() => {
    if (!preview) return;
    const root = document.documentElement;
    const sync = () => {
      const t = root.dataset.theme;
      setColorScheme(t === 'dark' || t === 'light' ? t : 'auto');
    };
    sync();
    const obs = new MutationObserver(sync);
    obs.observe(root, { attributes: true, attributeFilter: ['data-theme'] });
    return () => obs.disconnect();
  }, [setColorScheme]);
}

// Where the pages once under Diagnostics are now, for links and bookmarks
// made before they moved.
const moved: [string, string][] = [
  ['graphs', '/monitoring/graphs'],
  ['events', '/monitoring/events'],
  ['tools', '/monitoring/tools'],
  ['devices', '/devices'],
  ['traffic', '/devices/traffic'],
  ['arp', '/devices/arp'],
  ['connections', '/firewall/connections'],
  ['log', '/firewall/log'],
  ['system-logs', '/system/logs'],
  ['files', '/system/files'],
  ['storage', '/system/storage'],
];

function MovedFromDiagnostics() {
  const { pathname, search, hash } = useLocation();
  const [page, ...rest] = pathname.replace(/^\/diagnostics\/?/, '').split('/');
  const to = moved.find(([from]) => from === page)?.[1];
  if (!to) return <Navigate to="/" replace />;
  return <Navigate to={[to, ...rest].join('/') + search + hash} replace />;
}

function AppRoutes() {
  return (
    <Routes>
      <Route element={<AppLayout />}>
        <Route index element={<Dashboard />} />
        <Route path="interfaces" element={<Interfaces />} />
        <Route path="interfaces/:id" element={<InterfaceEdit />} />
        <Route path="firewall/rules" element={<FirewallRules />} />
        <Route path="firewall/rules/:iface" element={<FirewallRules />} />
        <Route path="network/routing" element={<Routing />} />
        <Route path="network/routing/:tab" element={<Routing />} />
        <Route path="firewall/nat" element={<Nat />} />
        <Route path="firewall/nat/:tab" element={<Nat />} />
        <Route path="firewall/ruleset" element={<Ruleset />} />
        <Route path="firewall/settings" element={<FirewallSettings />} />
        <Route path="firewall/aliases" element={<Aliases />} />
        <Route path="services/dhcp" element={<Dhcp />} />
        <Route path="services/dns" element={<Dns />} />
        <Route path="services/wireguard" element={<WireGuardPage />} />
        <Route path="services/wireguard/:tunnel" element={<WireGuardPage />} />
        <Route path="system/general" element={<SystemGeneral />} />
        <Route path="system/users" element={<Users />} />
        <Route path="system/history" element={<History />} />
        <Route path="system/notifications" element={<Notifications />} />
        <Route path="devices" element={<Devices />} />
        <Route path="devices/traffic" element={<Traffic />} />
        <Route path="devices/arp" element={<ARP />} />
        <Route path="devices/:key" element={<Device />} />
        <Route path="firewall/connections" element={<Connections />} />
        <Route path="firewall/log" element={<FirewallLog />} />
        <Route path="monitoring/graphs" element={<Graphs />} />
        <Route path="monitoring/events" element={<Events />} />
        <Route path="monitoring/tools" element={<Tools />} />
        <Route path="system/logs" element={<SystemLogs />} />
        <Route path="system/files" element={<ConfigFiles />} />
        <Route path="system/storage" element={<Storage />} />
        <Route path="diagnostics/*" element={<MovedFromDiagnostics />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}

export function App() {
  useHostTheme();
  return preview ? (
    <MemoryRouter>
      <AppRoutes />
    </MemoryRouter>
  ) : (
    <BrowserRouter>
      <AppRoutes />
    </BrowserRouter>
  );
}
