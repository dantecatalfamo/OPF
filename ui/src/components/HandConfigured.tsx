// An area OPF leaves as it's configured by hand (system.unmanaged): a
// machine taken over keeps its own DHCP server, resolver or time
// servers until the admin hands them over. Its page says so, and hands
// it over: OPF then writes the file from the settings the import
// understood, and runs the daemon with them, once the change is applied.
import { useState, type ReactNode } from 'react';
import { Alert, Button, Checkbox, Group, Modal, Stack, Text } from '@mantine/core';
import { IconHandStop } from '@tabler/icons-react';
import { useStore } from '../model/store';
import { useRole } from '../lib/session';
import type { Area } from '../lib/api';
import type { Model, Section } from '../model/types';
import { Mono } from './ui';

interface AreaInfo {
  what: string;
  file: string;
  daemon: string;
  section: Section;
  /** What the page shows of the import, for when OPF manages it. */
  kept: string;
  /** Turning it on as OPF hands it over, if asked. */
  turnOn?: { label: string; apply: (m: Model) => Model };
}

const areas: Record<Area, AreaInfo> = {
  dhcp: {
    what: 'DHCP server', file: '/etc/dhcpd.conf', daemon: 'dhcpd', section: 'dhcp',
    kept: 'The scopes on this page are what OPF understood from that file. They stay off until OPF manages the server.',
    turnOn: { label: 'Hand out addresses on every scope', apply: (m) => ({ ...m, dhcp: m.dhcp.map((s) => ({ ...s, enabled: true })) }) },
  },
  dns: {
    what: 'DNS resolver', file: '/var/unbound/etc/unbound.conf', daemon: 'unbound', section: 'dns',
    kept: 'The statistics and tools on this page use the resolver that’s running now. The settings on this page are what OPF understood from that file. They stay off until OPF manages the resolver.',
    turnOn: { label: 'Run the resolver', apply: (m) => ({ ...m, dns: { ...m.dns, enabled: true } }) },
  },
  ntp: {
    what: 'time servers', file: '/etc/ntpd.conf', daemon: 'ntpd', section: 'system',
    kept: 'The time servers on this page are what OPF understood from that file.',
  },
};

/** Whether the model leaves an area as it's configured by hand. */
export function handConfigured(m: Model, area: Area) {
  return !!m.system.unmanaged?.includes(area);
}

/** A page's notice that OPF leaves its area alone, with the way to hand
 *  it over; nothing when OPF manages it. compact: a line, for a card. */
export function HandConfigured({ area, compact }: { area: Area; compact?: boolean }) {
  const { staged, edit } = useStore();
  const { canEdit } = useRole();
  const [opened, setOpened] = useState(false);
  const [turnOn, setTurnOn] = useState(true);
  if (!handConfigured(staged, area)) return null;
  const a = areas[area];

  const handOver = () => {
    edit(a.section, `OPF manages the ${a.what}`, (m) => {
      let next: Model = { ...m, system: { ...m.system, unmanaged: (m.system.unmanaged ?? []).filter((x) => x !== area) } };
      if (a.turnOn && turnOn) next = a.turnOn.apply(next);
      if (!next.system.unmanaged?.length) delete next.system.unmanaged;
      return next;
    });
    setOpened(false);
  };

  const button = canEdit && (
    <Button size="xs" variant="light" onClick={() => { setTurnOn(true); setOpened(true); }}>Manage with OPF</Button>
  );
  let body: ReactNode;
  if (compact) {
    body = (
      <Group justify="space-between" wrap="nowrap" gap="sm">
        <Text size="sm">Configured by hand. OPF leaves <Mono>{a.file}</Mono> and {a.daemon} as they are.</Text>
        {button}
      </Group>
    );
  } else {
    body = (
      <Stack gap="xs">
        <Text size="sm">
          OPF leaves this machine’s {a.what} alone. It doesn’t write <Mono>{a.file}</Mono>, or start, stop or restart {a.daemon}. {a.kept}
        </Text>
        {button && <Group>{button}</Group>}
      </Stack>
    );
  }
  return (
    <>
      <Alert color="gray" variant="light" icon={<IconHandStop size={18} />} title={compact ? undefined : 'Configured by hand'} mb="md">
        {body}
      </Alert>
      <Modal opened={opened} onClose={() => setOpened(false)} title={`Let OPF manage the ${a.what}`}>
        <Stack>
          <Text size="sm">
            When you apply this change, OPF replaces <Mono>{a.file}</Mono> with one written from its own settings, and {a.daemon} uses it from then on. Review the change to see exactly what the file will contain.
          </Text>
          {a.turnOn && <Checkbox label={a.turnOn.label} checked={turnOn} onChange={(e) => setTurnOn(e.currentTarget.checked)} />}
          {a.turnOn && !turnOn && (
            <Text size="xs" c="dimmed">If this is unchecked, OPF stops {a.daemon} when the change is applied.</Text>
          )}
          <Group justify="flex-end">
            <Button variant="default" onClick={() => setOpened(false)}>Cancel</Button>
            <Button onClick={handOver}>Manage with OPF</Button>
          </Group>
        </Stack>
      </Modal>
    </>
  );
}
