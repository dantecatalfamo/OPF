import { useEffect, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router';
import {
  Alert, Anchor, Breadcrumbs, Button, Card, Group, NumberInput, SegmentedControl, Select, Stack, Switch, Text, TextInput,
} from '@mantine/core';
import { useForm } from '@mantine/form';
import { IconInfoCircle } from '@tabler/icons-react';
import { useStore } from '../model/store';
import type { Iface } from '../model/types';
import { isIPv4, inSubnet } from '../lib/ip';
import { PageHeader, SectionTitle } from '../components/ui';
import { formatBits } from '../lib/format';
import { HistoryCard } from '../components/HistoryChart';

import { DeleteInterface } from '../components/DeleteInterface';

interface Values {
  name: string;
  enabled: boolean;
  mode: Iface['ipv4']['mode'];
  address: string;
  prefix: string;
  gateway: string;
  ipv6: Iface['ipv6'];
  mtu: number | string;
  blockPrivate: boolean;
  blockBogons: boolean;
  antispoof: boolean;
}

function toValues(i: Iface): Values {
  return {
    name: i.name,
    enabled: i.enabled,
    mode: i.ipv4.mode,
    address: i.ipv4.address ?? '',
    prefix: String(i.ipv4.prefix ?? 24),
    gateway: i.ipv4.gateway ?? '',
    ipv6: i.ipv6,
    mtu: i.mtu ?? '',
    blockPrivate: !!i.blockPrivate,
    blockBogons: !!i.blockBogons,
    antispoof: !!i.antispoof,
  };
}

function describe(before: Iface, after: Iface): string {
  const parts: string[] = [];
  if (before.name !== after.name) parts.push(`renamed to “${after.name}”`);
  if (before.enabled !== after.enabled) parts.push(after.enabled ? 'enabled' : 'disabled');
  if (JSON.stringify(before.ipv4) !== JSON.stringify(after.ipv4)) {
    parts.push(
      after.ipv4.mode === 'static' ? `address set to ${after.ipv4.address}/${after.ipv4.prefix}` : after.ipv4.mode === 'dhcp' ? 'now gets its address by DHCP' : 'IPv4 turned off',
    );
  }
  if (before.ipv6 !== after.ipv6) parts.push(after.ipv6 === 'slaac' ? 'IPv6 turned on' : 'IPv6 turned off');
  if (before.mtu !== after.mtu) parts.push(`MTU ${after.mtu ?? 'default'}`);
  if (!!before.blockPrivate !== !!after.blockPrivate) parts.push(after.blockPrivate ? 'blocks private networks' : 'allows private networks');
  if (!!before.blockBogons !== !!after.blockBogons) parts.push(after.blockBogons ? 'blocks bogon networks' : 'allows bogon networks');
  if (!!before.antispoof !== !!after.antispoof) parts.push(after.antispoof ? 'blocks spoofed addresses' : 'no longer blocks spoofed addresses');
  return `${before.name}: ${parts.join(', ') || 'updated'}`;
}

export function InterfaceEdit() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { staged, edit } = useStore();
  const [deleting, setDeleting] = useState(false);
  const iface = staged.interfaces.find((i) => i.id === id);

  const form = useForm<Values>({
    initialValues: iface ? toValues(iface) : toValues(staged.interfaces[0]),
    validate: {
      name: (v) => (v.trim() ? null : 'Name can’t be empty'),
      address: (v, vals) => (vals.mode !== 'static' || isIPv4(v) ? null : 'Enter an IPv4 address like 192.168.1.1'),
      gateway: (v, vals) => {
        if (vals.mode !== 'static' || iface?.role !== 'wan' || !v) return null;
        if (!isIPv4(v)) return 'Enter an IPv4 address';
        return inSubnet(v, vals.address, Number(vals.prefix)) ? null : 'The gateway must be inside this network';
      },
      mtu: (v) => (v === '' || (Number(v) >= 576 && Number(v) <= 9000) ? null : 'Use 576 to 9000, or leave empty'),
    },
  });

  useEffect(() => {
    if (iface) form.setValues(toValues(iface));
  }, [id]); // only when switching interfaces

  if (!iface) {
    return (
      <Text>
        No such interface. <Anchor component={Link} to="/interfaces">Back to interfaces</Anchor>
      </Text>
    );
  }

  const isWan = iface.role === 'wan';
  const lockout = iface.role === 'lan' && (form.values.mode !== 'static' || form.values.address !== iface.ipv4.address);

  const submit = form.onSubmit((v) => {
    const next: Iface = {
      ...iface,
      name: v.name.trim(),
      enabled: v.enabled,
      ipv4: v.mode === 'static'
        ? { mode: 'static', address: v.address, prefix: Number(v.prefix), ...(isWan && v.gateway ? { gateway: v.gateway } : {}) }
        : { mode: v.mode },
      ipv6: v.ipv6,
      mtu: v.mtu === '' ? undefined : Number(v.mtu),
      ...(isWan ? { blockPrivate: v.blockPrivate, blockBogons: v.blockBogons } : {}),
      // Antispoof needs a fixed address (pf expands it when it loads).
      antispoof: v.mode === 'static' && v.antispoof ? true : undefined,
    };
    if (next.antispoof === undefined) delete next.antispoof;
    if (JSON.stringify(next) === JSON.stringify(iface)) {
      navigate('/interfaces');
      return;
    }
    edit('interfaces', describe(iface, next), (m) => ({
      ...m,
      interfaces: m.interfaces.map((i) => (i.id === iface.id ? next : i)),
    }));
    navigate('/interfaces');
  });

  return (
    <form onSubmit={submit}>
      <Breadcrumbs mb="xs" fz="sm">
        <Anchor component={Link} to="/interfaces">Interfaces</Anchor>
        <Text size="sm">{iface.name}</Text>
      </Breadcrumbs>
      <PageHeader
        title={iface.name}
        description={
          iface.wireguard ? (
            <>
              WireGuard tunnel {iface.device} ·{' '}
              <Anchor component={Link} to={`/services/wireguard/${iface.id}`} size="sm">Its keys, port and devices are on WireGuard VPN</Anchor>
            </>
          ) : iface.vlan ? `VLAN ${iface.vlan.tag} on ${iface.vlan.parent}` : `Port ${iface.device}`
        }
        actions={
          <>
            {iface.vlan && (
              <Button variant="subtle" color="red" onClick={() => setDeleting(true)}>
                Delete VLAN
              </Button>
            )}
            <Button variant="default" component={Link} to="/interfaces">
              Cancel
            </Button>
            <Button type="submit">Save</Button>
          </>
        }
      />
      <Stack gap="md" maw={760}>
        <Card>
          <SectionTitle>General</SectionTitle>
          <Stack>
            <TextInput label="Name" description="Shown throughout OPF, for example in firewall rules." {...form.getInputProps('name')} />
            <Switch
              label="Enabled"
              description={isWan ? 'Turning this off disconnects OPF from the internet.' : undefined}
              {...form.getInputProps('enabled', { type: 'checkbox' })}
            />
          </Stack>
        </Card>

        <Card>
          <SectionTitle>IPv4 address</SectionTitle>
          <Stack>
            <SegmentedControl
              data={[
                { value: 'dhcp', label: isWan ? 'From my provider (DHCP)' : 'DHCP' },
                { value: 'static', label: 'Fixed address' },
                { value: 'none', label: 'None' },
              ]}
              {...form.getInputProps('mode')}
              fullWidth
            />
            {form.values.mode === 'static' && (
              <>
                <Group grow align="flex-start">
                  <TextInput label="Address" placeholder="192.168.1.1" {...form.getInputProps('address')} />
                  <Select
                    label="Network size"
                    data={[
                      { value: '24', label: '/24 · 254 devices' },
                      { value: '23', label: '/23 · 510 devices' },
                      { value: '22', label: '/22 · 1,022 devices' },
                      { value: '25', label: '/25 · 126 devices' },
                      { value: '26', label: '/26 · 62 devices' },
                      { value: '28', label: '/28 · 14 devices' },
                      { value: '30', label: '/30 · 2 devices' },
                    ]}
                    allowDeselect={false}
                    {...form.getInputProps('prefix')}
                  />
                </Group>
                {isWan && <TextInput label="Gateway" placeholder="Provided by your ISP" {...form.getInputProps('gateway')} />}
              </>
            )}
            {lockout && (
              <Alert color="yellow" variant="light" icon={<IconInfoCircle size={18} />}>
                Devices on this network, including the one you’re using, will need a new address. OPF will ask you to
                confirm you can still connect after applying, and undo the change if you can’t.
              </Alert>
            )}
          </Stack>
        </Card>

        <Card>
          <SectionTitle>Advanced</SectionTitle>
          <Stack>
            <Select
              label="IPv6"
              data={[
                { value: 'slaac', label: 'Automatic (SLAAC)' },
                { value: 'none', label: 'Off' },
              ]}
              allowDeselect={false}
              {...form.getInputProps('ipv6')}
            />
            <NumberInput label="MTU" description="Leave empty unless your provider tells you otherwise." placeholder="1500" min={576} max={9000} {...form.getInputProps('mtu')} />
          </Stack>
        </Card>

        <Card>
          <SectionTitle>Protection</SectionTitle>
          <Stack>
            <Switch
              label="Block spoofed addresses"
              description={form.values.mode === 'static'
                ? `Drop traffic that claims to come from ${iface.name}’s network but arrives on another interface (pf’s antispoof).`
                : 'Needs a fixed address: pf would keep guarding the old network after the address changed.'}
              disabled={form.values.mode !== 'static'}
              {...form.getInputProps('antispoof', { type: 'checkbox' })}
            />
            {isWan && (
              <>
              <Switch
                label="Block private networks"
                description="Drop traffic from the internet that claims to come from a private address such as 192.168.0.0/16."
                {...form.getInputProps('blockPrivate', { type: 'checkbox' })}
              />
              <Switch
                label="Block bogon networks"
                description="Drop traffic from addresses that should never appear on the internet."
                {...form.getInputProps('blockBogons', { type: 'checkbox' })}
              />
              </>
            )}
          </Stack>
        </Card>
        <Card>
          <HistoryCard
            title="Traffic"
            series={[{ key: `if.${iface.device}.rx`, label: 'In', color: 'harbor.6' }, { key: `if.${iface.device}.tx`, label: 'Out', color: 'amber.6' }]}
            format={formatBits}
            area
            peaks
            markSubjects={[iface.id]}
          />
        </Card>
      </Stack>
      {iface.vlan && <DeleteInterface iface={iface} kind="VLAN network" opened={deleting} onClose={() => setDeleting(false)} onDeleted={() => navigate('/interfaces')} />}
    </form>
  );
}
