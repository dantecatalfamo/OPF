import { useEffect, useState } from 'react';
import { Link, Outlet, useLocation, useSearchParams } from 'react-router';
import {
  ActionIcon, Alert, Anchor, AppShell, Avatar, Badge, Burger, Button, Group, Kbd, Menu, NavLink, ScrollArea, Text, Tooltip, UnstyledButton,
  useComputedColorScheme, useMantineColorScheme,
} from '@mantine/core';
import { useDisclosure, useHotkeys, useOs } from '@mantine/hooks';
import {
  IconAlertTriangle, IconArrowRight, IconChecks, IconClockHour4, IconEye, IconLogout, IconMoon, IconSearch, IconSettings, IconSun, IconUser,
} from '@tabler/icons-react';
import { Brand } from './Brand';
import { ApplyModal } from './ApplyModal';
import { ConfirmModal } from './ConfirmModal';
import { useStore } from '../model/store';
import { useRole, useSession } from '../lib/session';
import { offline } from '../lib/api';
import { useNow } from '../lib/useNow';
import { activePath, itemShown, nav, pageShown } from '../lib/nav';
import { useLive } from '../lib/live';
import { useMode } from '../lib/mode';
import { CommandPalette } from './CommandPalette';
import type { Role } from '../lib/api';

const roleLabel: Record<Role, string> = { admin: 'admin', operator: 'operator', view: 'read-only' };

function Navigation({ onNavigate }: { onNavigate: () => void }) {
  const { pathname } = useLocation();
  const { isAdmin, readOnly } = useRole();
  const { managed } = useMode();
  const active = activePath(pathname);
  return (
    <>
      {nav.filter((g) => (g.to ? itemShown(g, readOnly, managed) : g.items!.some((i) => itemShown(i, readOnly, managed)))).map((g) =>
        g.to ? (
          <NavLink
            key={g.label}
            component={Link}
            to={g.to}
            label={g.label}
            leftSection={<g.icon size={18} stroke={1.6} />}
            active={active === g.to}
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
            {g.items!.filter((i) => (!i.admin || isAdmin) && itemShown(i, readOnly, managed)).map((i) => (
              <NavLink
                key={i.to}
                component={Link}
                to={i.to}
                label={i.label}
                active={active === i.to}
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
  const { readOnly } = useRole();
  if (readOnly) {
    return (
      <Tooltip label="OPF only watches this machine and changes nothing on it">
        <Badge component={Link} to="/system/take-over" variant="light" color="blue" size="lg" radius="sm" tt="none" fw={500} leftSection={<IconEye size={14} />} style={{ cursor: 'pointer' }}>
          Monitoring only
        </Badge>
      </Tooltip>
    );
  }
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

// A page about OPF's own configuration, reached read-only by a link or
// an old bookmark: there's no such configuration to show.
function NotWhileMonitoring() {
  return (
    <Alert color="gray" variant="light" title="Not while OPF is only monitoring" icon={<IconEye size={18} />} maw={680}>
      <Text size="sm" mb="xs">
        This page shows OPF’s own configuration. OPF is only monitoring this machine, so there is none to show. Everything here is configured by hand. You can see the machine’s files under{' '}
        <Anchor component={Link} to="/system/files" size="sm">Configuration files</Anchor>.
      </Text>
      <Anchor component={Link} to="/system/take-over" size="sm">Taking this machine over</Anchor>
    </Alert>
  );
}

export function AppLayout() {
  const [navOpened, nav] = useDisclosure();
  const [reviewOpened, review] = useDisclosure();
  const [paletteOpened, palette] = useDisclosure();
  // In text fields too: Ctrl-K isn't anything a field needs.
  useHotkeys([['mod+K', palette.toggle]], []);
  const mac = ['macos', 'ios'].includes(useOs());
  const [confirmOpened, setConfirmOpened] = useState(false);
  const { staged, confirming, release } = useStore();
  const { accounts, session, signOut } = useSession();
  const { canEdit, readOnly } = useRole();
  const { data: sys } = useLive('system');
  const { setColorScheme } = useMantineColorScheme();
  const scheme = useComputedColorScheme('light');

  // Show the confirmation dialog as soon as a commit starts waiting.
  useEffect(() => setConfirmOpened(!!confirming), [confirming]);
  // ?review opens the review of what's staged: taking the machine over
  // lands here, with its import staged.
  const [params, setParams] = useSearchParams();
  const { changes } = useStore();
  useEffect(() => {
    if (!params.has('review')) return;
    if (changes.length > 0) review.open();
    const next = new URLSearchParams(params);
    next.delete('review');
    setParams(next, { replace: true });
  }, [params, changes.length]); // review and setParams are stable

  // A link to a card on a page (#limits): scroll to it once it's there,
  // which may be after the page has loaded its data.
  const { pathname, search, hash } = useLocation();
  useEffect(() => {
    if (!hash) return;
    let tries = 0;
    const t = setInterval(() => {
      const el = document.getElementById(decodeURIComponent(hash.slice(1)));
      if (el || ++tries > 20) {
        clearInterval(t);
        el?.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    }, 100);
    return () => clearInterval(t);
  }, [pathname, search, hash]);

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
              <span className="mono">{readOnly ? sys?.hostname ?? '…' : `${staged.system.hostname}.${staged.system.domain}`}</span>
            </Badge>
          </Group>
          <Group gap="sm" wrap="nowrap">
            <UnstyledButton
              onClick={palette.open}
              visibleFrom="sm"
              aria-label="Go to"
              px="sm"
              py={5}
              style={{ border: '1px solid var(--mantine-color-default-border)', borderRadius: 6 }}
            >
              <Group gap={8} wrap="nowrap" c="dimmed">
                <IconSearch size={16} />
                <Text size="sm">Go to</Text>
                <Kbd size="xs">{mac ? '⌘' : 'Ctrl'} K</Kbd>
              </Group>
            </UnstyledButton>
            <Tooltip label="Go to">
              <ActionIcon variant="subtle" color="gray" size="lg" hiddenFrom="sm" onClick={palette.open} aria-label="Go to">
                <IconSearch size={18} />
              </ActionIcon>
            </Tooltip>
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
                <Menu.Label>{session ? `Signed in as ${session.user} (${roleLabel[session.role]})` : 'No accounts on this server'}</Menu.Label>
                {!readOnly && (
                  <Menu.Item component={Link} to="/system/general" leftSection={<IconSettings size={16} />}>
                    Settings
                  </Menu.Item>
                )}
                {accounts && <Menu.Item leftSection={<IconLogout size={16} />} onClick={signOut}>Sign out</Menu.Item>}
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
          {readOnly && (
            <Alert color="blue" variant="light" mb="md" icon={<IconEye size={18} />}>
              OPF is only monitoring this machine. It shows what’s happening and changes nothing. You still configure the machine by hand. <Anchor component={Link} to="/system/take-over" size="sm">Taking it over</Anchor>
            </Alert>
          )}
          {accounts && session && !canEdit && !readOnly && (
            <Alert color="blue" variant="light" mb="md">
              {session.role === 'operator'
                ? 'You’re signed in as an operator. You can see everything, keep or undo a change someone applied, and run tools. You can’t change the configuration.'
                : 'You’re signed in read-only. You can see everything, but you can’t change anything.'}
            </Alert>
          )}
          {!accounts && !offline && (
            <Alert color="yellow" variant="light" mb="md" icon={<IconAlertTriangle size={18} />}>
              This is the development server. It has no accounts, so anyone who can reach it can change everything. It only listens on this machine.
            </Alert>
          )}
          {readOnly && !pageShown(pathname, true) ? <NotWhileMonitoring /> : <Outlet />}
        </div>
      </AppShell.Main>

      <CommandPalette opened={paletteOpened} onClose={palette.close} />
      <ApplyModal opened={reviewOpened} onClose={review.close} />
      <ConfirmModal opened={confirmOpened} onClose={() => setConfirmOpened(false)} />
    </AppShell>
  );
}
