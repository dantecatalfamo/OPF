import { Alert, Checkbox, Group, Select, Stack, Switch, Text } from '@mantine/core';
import { IconAlertTriangle } from '@tabler/icons-react';
import type { InterfaceState } from '../lib/api';
import { mediaLabel } from '../lib/live';
import { modeHelp, modeLabel, offeredModes, type AggregateMode } from '../lib/aggregate';
import type { Aggregate } from '../model/types';
import { StatusDot } from './ui';

/** An aggregate as its form has it. */
export interface AggregateValues {
  mode: AggregateMode;
  ports: string[];
  /** Failover's port to use while it's up; the others wait. */
  primary: string;
  lacpPassive: boolean;
  lacpFast: boolean;
}

export const aggregateValues = (a?: Aggregate): AggregateValues => ({
  mode: a?.proto ?? 'lacp',
  ports: a?.ports ?? [],
  primary: a?.ports[0] ?? '',
  lacpPassive: !!a?.lacpPassive,
  lacpFast: !!a?.lacpFast,
});

/** The model's aggregate: failover's main port first, as trunk(4)
 *  takes its first port as the master. */
export function toAggregate(v: AggregateValues): Aggregate {
  const ports = v.mode === 'failover' && v.ports.includes(v.primary) ? [v.primary, ...v.ports.filter((p) => p !== v.primary)] : v.ports;
  if (v.mode === 'lacp') return { ports, ...(v.lacpPassive ? { lacpPassive: true } : {}), ...(v.lacpFast ? { lacpFast: true } : {}) };
  return { ports, proto: v.mode };
}

export const portsError = (ports: string[]) => (ports.length ? null : 'Choose at least one port');

/** The ports and how they're used, for adding an aggregate and editing one. */
export function AggregateFields({ values, set, error, ports }: {
  values: AggregateValues;
  set: <K extends keyof AggregateValues>(k: K, v: AggregateValues[K]) => void;
  error?: React.ReactNode;
  /** The ports it can have, with their link now. */
  ports: InterfaceState[];
}) {
  const modes = values.mode === 'none' ? [...offeredModes, 'none' as const] : offeredModes;
  // Ports chosen that the machine no longer has stay listed.
  const known = new Set(ports.map((p) => p.name));
  const listed = [...ports.map((p) => ({ name: p.name, state: p as InterfaceState | undefined })), ...values.ports.filter((p) => !known.has(p)).map((name) => ({ name, state: undefined }))];
  return (
    <Stack>
      <Select
        label="How it uses the ports"
        description={modeHelp[values.mode]}
        data={modes.map((m) => ({ value: m, label: modeLabel[m] }))}
        allowDeselect={false}
        value={values.mode}
        onChange={(v) => v && set('mode', v as AggregateMode)}
      />
      <Checkbox.Group
        label="Ports"
        description="Each port is used only by this interface: it has no address or rules of its own."
        value={values.ports}
        onChange={(v) => set('ports', listed.map((p) => p.name).filter((n) => v.includes(n)))}
        error={error}
      >
        <Stack gap={6} mt={6}>
          {listed.length === 0 && <Text size="sm" c="dimmed">No free ports: each Ethernet port here is an interface or carries a VLAN already.</Text>}
          {listed.map(({ name, state }) => {
            const link = !state ? 'Not on this system' : !state.up ? 'Down' : state.status === 'no carrier' ? 'No link' : 'Up';
            return (
              <Group key={name} gap="sm" wrap="nowrap">
                <Checkbox value={name} label={<Text span className="mono" size="sm">{name}</Text>} />
                <Text size="xs" c="dimmed">{[state?.mac, mediaLabel(state)].filter(Boolean).join(' · ')}</Text>
                {state && state.up && <StatusDot ok={link === 'Up'} label={link} />}
              </Group>
            );
          })}
        </Stack>
      </Checkbox.Group>
      {listed.filter((p) => values.ports.includes(p.name) && p.state && (p.state.ipv4.length || p.state.ipv6.some((a) => !a.startsWith('fe80')))).map(({ name, state }) => (
        <Alert key={name} color="yellow" variant="light" p="sm" icon={<IconAlertTriangle size={16} />}>
          {name} has {[...state!.ipv4, ...state!.ipv6.filter((a) => !a.startsWith('fe80'))].join(', ')} now, set outside OPF. As a port it has no address of its own, so that goes.
        </Alert>
      ))}
      {values.mode === 'failover' && values.ports.length > 1 && (
        <Select
          label="Main port"
          description="Used while its link is up; the others take over in turn."
          data={values.ports}
          allowDeselect={false}
          value={values.ports.includes(values.primary) ? values.primary : values.ports[0]}
          onChange={(v) => v && set('primary', v)}
        />
      )}
      {values.mode === 'lacp' && (
        <>
          <Switch
            label="Wait for the switch to start LACP"
            description="Passive mode. Leave this off unless the switch is set to active; two passive ends never connect."
            checked={values.lacpPassive}
            onChange={(e) => set('lacpPassive', e.currentTarget.checked)}
          />
          <Switch
            label="Notice a failed port quickly"
            description="Fast timeout: a port that stops answering is dropped after 3 seconds instead of 90. The switch should be set to fast too."
            checked={values.lacpFast}
            onChange={(e) => set('lacpFast', e.currentTarget.checked)}
          />
        </>
      )}
    </Stack>
  );
}
