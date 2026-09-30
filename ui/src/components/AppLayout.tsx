import { useEffect, useState } from 'react';
import { Link, Outlet, useLocation } from 'react-router';
import {
  ActionIcon, AppShell, Avatar, Badge, Burger, Button, Group, Menu, NavLink, ScrollArea, Text, Tooltip,
  useComputedColorScheme, useMantineColorScheme,
} from '@mantine/core';
import { useDisclosure } from '@mantine/hooks';
import {
  IconActivity, IconArrowRight, IconChecks, IconClockHour4, IconGauge, IconLogout, IconMoon, IconNetwork,
  IconServer2, IconSettings, IconShieldHalf, IconSun, IconUser,
} from '@tabler/icons-react';
import { Brand } from './Brand';
import { ApplyModal } from './ApplyModal';
import { ConfirmModal } from './ConfirmModal';
import { useStore } from '../model/store';
import { useNow } from '../lib/useNow';

interface NavItem {
  label: string;
  to: string;
}
interface NavGroup {
  label: string;
  icon: typeof IconGauge;
  to?: string;
  items?: NavItem[];
}

const nav: NavGroup[] = [
  { label: 'Dashboard', icon: IconGauge, to: '/' },
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
    label: 'System', icon: IconSettings, items: [
      { label: 'General', to: '/system/general' },
      { label: 'Change history', to: '/system/history' },
    ],
  },
  {
    label: 'Diagnostics', icon: IconActivity, items: [
      { label: 'Tools', to: '/diagnostics/tools' },
      { label: 'Connections', to: '/diagnostics/connections' },
      { label: 'ARP table', to: '/diagnostics/arp' },
      { label: 'Firewall log', to: '/diagnostics/log' },
    ],
  },
];

const isActive = (path: string, to: string) => (to === '/' ? path === '/' : path === to || path.startsWith(to + '/'));

function Navigation({ onNavigate }: { onNavigate: () => void }) {
  const { pathname } = useLocation();
  return (
    <>
      {nav.map((g) =>
        g.to ? (
          <NavLink
            key={g.label}
            component={Link}
            to={g.to}
            label={g.label}
            leftSection={<g.icon size={18} stroke={1.6} />}
            active={isActive(pathname, g.to)}
            onClick={onNavigate}
            variant="light"
            fw={500}
          />
        ) : (
          <NavLink
            key={g.label}
            label={g.label}
            leftSection={<g.icon size={18} stroke={1.6} />}
            defaultOpened
            childrenOffset={30}
            fw={500}
          >
            {g.items!.map((i) => (
              <NavLink
                key={i.to}
                component={Link}
                to={i.to}
                label={i.label}
                active={isActive(pathname, i.to)}
                onClick={onNavigate}
                variant="light"
              />
            ))}
          </NavLink>
        ),
      )}
    </>
  );
}

function Countdown({ deadline }: { deadline: number }) {
  const now = useNow(250);
  return <span className="num">{Math.max(0, Math.ceil((deadline - now) / 1000))}s</span>;
}

function PendingButton({ onReview, onConfirm }: { onReview: () => void; onConfirm: () => void }) {
  const { changes, confirming } = useStore();
  if (confirming) {
    return (
      <Button color="amber" c="dark.9" className="pulse" leftSection={<IconClockHour4 size={18} />} onClick={onConfirm}>
        Confirm changes · <Countdown deadline={confirming.deadline} />
      </Button>
    );
  }
  if (changes.length > 0) {
    return (
      <Button color="amber" c="dark.9" rightSection={<IconArrowRight size={16} />} onClick={onReview}>
        {changes.length} pending change{changes.length === 1 ? '' : 's'}
      </Button>
    );
  }
  return (
    <Group gap={6} visibleFrom="sm" c="dimmed">
      <IconChecks size={16} />
      <Text size="sm">All changes applied</Text>
    </Group>
  );
}

export function AppLayout() {
  const [navOpened, nav] = useDisclosure();
  const [reviewOpened, review] = useDisclosure();
  const [confirmOpened, setConfirmOpened] = useState(false);
  const { staged, confirming, release } = useStore();
  const { setColorScheme } = useMantineColorScheme();
  const scheme = useComputedColorScheme('light');

  // Show the confirmation dialog as soon as a commit starts waiting.
  useEffect(() => setConfirmOpened(!!confirming), [confirming]);

  return (
    <AppShell
      header={{ height: 60 }}
      navbar={{ width: 248, breakpoint: 'sm', collapsed: { mobile: !navOpened } }}
      padding={{ base: 'md', sm: 'xl' }}
    >
      <AppShell.Header px="md" style={{ background: 'var(--opf-surface)' }}>
        <Group h="100%" justify="space-between" wrap="nowrap">
          <Group gap="md" wrap="nowrap">
            <Burger opened={navOpened} onClick={nav.toggle} hiddenFrom="sm" size="sm" aria-label="Menu" />
            <Brand />
            <Badge variant="default" size="lg" radius="sm" visibleFrom="md" fw={500} tt="none">
              <span className="mono">{staged.system.hostname}.{staged.system.domain}</span>
            </Badge>
          </Group>
          <Group gap="sm" wrap="nowrap">
            <PendingButton onReview={review.open} onConfirm={() => setConfirmOpened(true)} />
            <Tooltip label={scheme === 'dark' ? 'Light theme' : 'Dark theme'}>
              <ActionIcon
                variant="subtle"
                color="gray"
                size="lg"
                onClick={() => setColorScheme(scheme === 'dark' ? 'light' : 'dark')}
                aria-label="Toggle color scheme"
              >
                {scheme === 'dark' ? <IconSun size={18} /> : <IconMoon size={18} />}
              </ActionIcon>
            </Tooltip>
            <Menu position="bottom-end" width={200}>
              <Menu.Target>
                <ActionIcon variant="subtle" color="gray" size="lg" radius="xl" aria-label="Account">
                  <Avatar size={30} radius="xl" color="harbor">
                    <IconUser size={16} />
                  </Avatar>
                </ActionIcon>
              </Menu.Target>
              <Menu.Dropdown>
                <Menu.Label>Signed in as admin</Menu.Label>
                <Menu.Item component={Link} to="/system/general" leftSection={<IconSettings size={16} />}>
                  Settings
                </Menu.Item>
                <Menu.Item leftSection={<IconLogout size={16} />}>Sign out</Menu.Item>
              </Menu.Dropdown>
            </Menu>
          </Group>
        </Group>
      </AppShell.Header>

      <AppShell.Navbar p="sm" style={{ background: 'var(--opf-surface)' }}>
        <AppShell.Section grow component={ScrollArea}>
          <Navigation onNavigate={nav.close} />
        </AppShell.Section>
        <AppShell.Section>
          <Text size="xs" c="dimmed" px="sm" pt="sm">
            OPF 0.1{release ? ` · OpenBSD ${release}` : ''}
          </Text>
        </AppShell.Section>
      </AppShell.Navbar>

      <AppShell.Main>
        <div style={{ maxWidth: 1180, margin: '0 auto' }}>
          <Outlet />
        </div>
      </AppShell.Main>

      <ApplyModal opened={reviewOpened} onClose={review.close} />
      <ConfirmModal opened={confirmOpened} onClose={() => setConfirmOpened(false)} />
    </AppShell>
  );
}
