// System › General: where the firewall's own lookups go (system.dns),
// and the servers they go to now, from resolv.conf.
import { useEffect } from 'react';
import { Link } from 'react-router';
import { Alert, Anchor, Button, Card, Checkbox, Group, SegmentedControl, Stack, TagsInput, Text } from '@mantine/core';
import { useForm } from '@mantine/form';
import { IconAlertTriangle } from '@tabler/icons-react';
import { useStore } from '../model/store';
import { useLive } from '../lib/live';
import { useRole } from '../lib/session';
import type { SystemDnsMode } from '../model/types';
import { Mono, SectionTitle } from '../components/ui';

// The C library reads three nameservers.
const MAX_NAMESERVERS = 3;

const help: Record<SystemDnsMode, string> = {
  wan: 'The servers the WAN learns with its DHCP lease, as OpenBSD does by default. A WAN with a fixed address learns none.',
  self: 'OPF’s own DNS resolver first, so the firewall gets your local names and blocklists too. The servers below answer if it doesn’t, then the WAN’s unless you choose only these.',
  servers: 'These servers first, such as Quad9 (9.9.9.9) or your provider’s. The WAN’s come after them while there’s room (the system asks at most three), unless you choose only these.',
};

const isIP = (s: string) => /^\d{1,3}(\.\d{1,3}){3}$/.test(s) ? s.split('.').every((o) => Number(o) <= 255) : /^[0-9a-f:]+$/i.test(s) && s.includes(':');

interface Values {
  mode: SystemDnsMode;
  servers: string[];
  only: boolean;
}

export function FirewallDns() {
  const { staged, applied, edit } = useStore();
  const { canEdit } = useRole();
  const { data: sys } = useLive('system');
  const current = staged.system.dns;
  const pick = (): Values => ({ mode: current?.mode ?? 'wan', servers: current?.servers ?? [], only: !!current?.only });
  const max = (mode: SystemDnsMode) => (mode === 'self' ? MAX_NAMESERVERS - 1 : MAX_NAMESERVERS);
  const form = useForm<Values>({
    initialValues: pick(),
    validate: {
      servers: (v, vals) => {
        if (vals.mode === 'wan') return null;
        if (vals.mode === 'servers' && !v.length) return 'Add at least one server';
        if (v.length > max(vals.mode)) return `At most ${max(vals.mode)}: the system asks no more than three`;
        const bad = v.find((s) => !isIP(s));
        return bad ? `${bad} isn’t an IP address` : null;
      },
      mode: (v) => (v === 'self' && !staged.dns.enabled ? 'The DNS resolver is off' : null),
    },
  });
  useEffect(() => {
    form.setValues(pick());
    form.resetDirty();
  }, [current]); // form is stable

  const v = form.values;
  const wan = staged.interfaces.find((i) => i.role === 'wan');
  const fixedWan = wan?.enabled && wan.ipv4.mode !== 'dhcp';
  const servers = sys?.dns?.servers;
  const asking = servers?.filter((s) => !s.unused) ?? [];

  const save = form.onSubmit((v) => {
    const summary = (v.mode === 'wan' ? 'The firewall asks the WAN’s DNS servers'
      : v.mode === 'self' ? `The firewall asks its own resolver${v.servers.length ? `, then ${v.servers.join(', ')}` : ''}`
        : `The firewall asks ${v.servers.join(', ')}`) + (v.mode !== 'wan' && v.only ? ', never the WAN’s' : '');
    edit('system', summary, (m) => {
      const system = { ...m.system };
      if (v.mode === 'wan') delete system.dns;
      else system.dns = { mode: v.mode, ...(v.servers.length ? { servers: v.servers } : {}), ...(v.only ? { only: true } : {}) };
      return { ...m, system };
    });
  });

  return (
    <Card>
      <form onSubmit={save}>
        <SectionTitle>DNS for the firewall itself</SectionTitle>
        <Stack gap="md">
          <Text size="sm" c="dimmed">
            Where the firewall’s own lookups go: checking for updates, downloading blocklists and lists of addresses, its tools.
            Devices on your networks are told under <Anchor component={Link} to="/services/dhcp" size="sm">DHCP server</Anchor>.
          </Text>
          <Stack gap={6}>
            <SegmentedControl
              disabled={!canEdit}
              data={[
                { value: 'wan', label: 'From the WAN' },
                { value: 'self', label: 'Its own resolver', disabled: !staged.dns.enabled },
                { value: 'servers', label: 'These servers' },
              ]}
              {...form.getInputProps('mode')}
            />
            <Text size="xs" c="dimmed">{help[v.mode]}{v.mode === 'self' && !staged.dns.enabled ? ' The DNS resolver is off.' : ''}</Text>
            {form.errors.mode && <Text size="xs" c="red">{form.errors.mode}</Text>}
          </Stack>
          {v.mode !== 'wan' && (
            <TagsInput
              label={v.mode === 'self' ? 'If it doesn’t answer' : 'Servers'}
              description={v.mode === 'self' ? `Optional, at most ${max('self')}` : `In the order they’re asked, at most ${MAX_NAMESERVERS}`}
              placeholder="9.9.9.9" disabled={!canEdit}
              {...form.getInputProps('servers')}
            />
          )}
          {v.mode !== 'wan' && (
            <Checkbox
              label={v.mode === 'self' ? 'Only these: never the WAN’s servers' : 'Only these servers: never the WAN’s'}
              description="Keeps the firewall’s lookups off your provider’s DNS servers: the DHCP client ignores the ones its lease brings."
              disabled={!canEdit}
              {...form.getInputProps('only', { type: 'checkbox' })}
            />
          )}
          {v.mode !== 'wan' && v.only && wan?.ipv6 === 'slaac' && (
            <Text size="xs" c="dimmed">The WAN also takes IPv6 settings from your provider’s routers, which can bring DNS servers too; those aren’t ignored. Asking now, below, shows any.</Text>
          )}
          {v.mode === 'wan' && fixedWan && (
            <Alert color="yellow" variant="light" p="sm" icon={<IconAlertTriangle size={16} />}>
              The WAN ({wan!.name}) has a fixed address, so it learns no DNS servers: unless resolv.conf names some by hand, the firewall has none. Choose its own resolver or these servers.
            </Alert>
          )}
          {servers && (
            <Stack gap={4}>
              <Text size="sm" fw={500}>Asking now</Text>
              {asking.length === 0 ? (
                <Alert color="red" variant="light" p="sm" icon={<IconAlertTriangle size={16} />}>
                  The firewall has no DNS server, so it can’t look anything up: update checks and list downloads fail.
                  {fixedWan && applied.system.dns === undefined ? ' Its WAN has a fixed address and learns none.' : ''}
                </Alert>
              ) : (
                servers.map((s, i) => (
                  <Text key={`${s.address}-${i}`} size="sm" c={s.unused ? 'dimmed' : undefined}>
                    <Mono>{s.address}</Mono>{' '}
                    <Text span size="xs" c="dimmed">
                      {s.address === '127.0.0.1' ? 'its own resolver, ' : ''}
                      {s.from === 'lo0' ? 'set by OPF' : s.from ? `learned on ${s.from}` : 'written in resolv.conf by hand'}
                      {s.unused ? '; not asked: the system asks at most three' : ''}
                    </Text>
                  </Text>
                ))
              )}
            </Stack>
          )}
          <Group justify="flex-end">
            <Button type="submit" disabled={!form.isDirty() || !canEdit}>Save</Button>
          </Group>
        </Stack>
      </form>
    </Card>
  );
}
