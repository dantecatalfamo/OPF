import { useEffect } from 'react';
import { BrowserRouter, MemoryRouter, Navigate, Route, Routes } from 'react-router';
import { useMantineColorScheme } from '@mantine/core';
import { AppLayout } from './components/AppLayout';
import { Dashboard } from './pages/Dashboard';
import { Interfaces } from './pages/Interfaces';
import { InterfaceEdit } from './pages/InterfaceEdit';
import { FirewallRules } from './pages/FirewallRules';
import { PortForwards } from './pages/PortForwards';
import { Aliases } from './pages/Aliases';
import { Dhcp } from './pages/Dhcp';
import { Dns } from './pages/Dns';
import { WireGuardPage } from './pages/WireGuard';
import { SystemGeneral } from './pages/SystemGeneral';
import { History } from './pages/History';
import { Connections } from './pages/Connections';
import { FirewallLog } from './pages/FirewallLog';

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

function AppRoutes() {
  return (
    <Routes>
      <Route element={<AppLayout />}>
        <Route index element={<Dashboard />} />
        <Route path="interfaces" element={<Interfaces />} />
        <Route path="interfaces/:id" element={<InterfaceEdit />} />
        <Route path="firewall/rules" element={<FirewallRules />} />
        <Route path="firewall/rules/:iface" element={<FirewallRules />} />
        <Route path="firewall/forwards" element={<PortForwards />} />
        <Route path="firewall/aliases" element={<Aliases />} />
        <Route path="services/dhcp" element={<Dhcp />} />
        <Route path="services/dns" element={<Dns />} />
        <Route path="services/wireguard" element={<WireGuardPage />} />
        <Route path="system/general" element={<SystemGeneral />} />
        <Route path="system/history" element={<History />} />
        <Route path="diagnostics/connections" element={<Connections />} />
        <Route path="diagnostics/log" element={<FirewallLog />} />
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
