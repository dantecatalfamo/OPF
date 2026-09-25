import { useEffect } from 'react';
import { Button, Card, Grid, Group, NumberInput, Select, Stack, Switch, Text } from '@mantine/core';
import { useForm } from '@mantine/form';
import { useStore } from '../model/store';
import type { FirewallOptions } from '../model/types';
import { PageHeader, SectionTitle } from '../components/ui';

export function FirewallSettings() {
  const { staged, edit } = useStore();
  const opts = staged.firewall.options;
  const form = useForm<FirewallOptions>({ initialValues: opts });
  useEffect(() => {
    form.setValues(opts);
    form.resetDirty();
  }, [opts]); // form is stable
  const v = form.values;

  return (
    <form onSubmit={form.onSubmit((vals) => edit('firewall', 'Changed firewall settings', (m) => ({ ...m, firewall: { ...m.firewall, options: vals } })))}>
      <PageHeader
        title="Firewall settings"
        description="How pf behaves as a whole. The defaults suit most networks."
        actions={<Button type="submit" disabled={!form.isDirty()}>Save</Button>}
      />
      <Grid gutter="md">
        <Grid.Col span={{ base: 12, lg: 6 }}>
          <Card h="100%">
            <SectionTitle>Blocking</SectionTitle>
            <Stack>
              <Select
                label="Blocked traffic is"
                description="Applies to rules set to Drop and to the default block."
                data={[{ value: 'drop', label: 'Dropped silently' }, { value: 'return', label: 'Refused (TCP reset or ICMP unreachable)' }]}
                allowDeselect={false}
                {...form.getInputProps('blockPolicy')}
              />
              <Switch label="Log traffic blocked by the default rule" description="Useful for troubleshooting; busy on a WAN." {...form.getInputProps('logDefaultBlock', { type: 'checkbox' })} />
            </Stack>
          </Card>
        </Grid.Col>
        <Grid.Col span={{ base: 12, lg: 6 }}>
          <Card h="100%">
            <SectionTitle>Connection tracking</SectionTitle>
            <Stack>
              <Select
                label="Connections are tracked"
                data={[{ value: 'floating', label: 'Across all interfaces (floating)' }, { value: 'if-bound', label: 'Per interface (if-bound, stricter)' }]}
                allowDeselect={false}
                {...form.getInputProps('statePolicy')}
              />
              <Select
                label="Timeouts"
                data={[
                  { value: 'normal', label: 'Normal' },
                  { value: 'high-latency', label: 'High latency (satellite links)' },
                  { value: 'aggressive', label: 'Aggressive (expire idle connections sooner)' },
                  { value: 'conservative', label: 'Conservative (keep idle connections longer)' },
                ]}
                allowDeselect={false}
                {...form.getInputProps('optimization')}
              />
              <NumberInput label="Maximum tracked connections" min={1000} step={10000} thousandSeparator="," {...form.getInputProps('maxStates')} />
              <Select
                label="SYN cookies"
                description="Protect against SYN floods by answering handshakes without keeping state."
                data={[{ value: 'never', label: 'Off' }, { value: 'adaptive', label: 'When the state table is filling up' }, { value: 'always', label: 'Always' }]}
                allowDeselect={false}
                {...form.getInputProps('syncookies')}
              />
            </Stack>
          </Card>
        </Grid.Col>
        <Grid.Col span={12}>
          <Card>
            <SectionTitle right={<Switch label="Enabled" {...form.getInputProps('scrub.enabled', { type: 'checkbox' })} />}>Packet normalization (scrub)</SectionTitle>
            <Group grow align="flex-start">
              <NumberInput label="Clamp TCP MSS to" description="Avoids broken connections over tunnels and PPPoE." placeholder="Off" min={536} max={1460} disabled={!v.scrub.enabled} {...form.getInputProps('scrub.maxMss')} />
              <Stack gap="sm" pt={4}>
                <Switch label="Clear the don’t-fragment bit" disabled={!v.scrub.enabled} {...form.getInputProps('scrub.noDf', { type: 'checkbox' })} />
                <Switch label="Randomize IP identifiers" disabled={!v.scrub.enabled} {...form.getInputProps('scrub.randomId', { type: 'checkbox' })} />
              </Stack>
            </Group>
            <Text size="xs" c="dimmed" mt="md">Applies to incoming traffic on every interface.</Text>
          </Card>
        </Grid.Col>
      </Grid>
    </form>
  );
}
