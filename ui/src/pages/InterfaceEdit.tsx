import { useEffect, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router';
import {
  Alert, Anchor, Breadcrumbs, Button, Card, Group, NumberInput, SegmentedControl, Select, Stack, Switch, Text, TextInput,
} from '@mantine/core';
import { useForm } from '@mantine/form';
import { IconInfoCircle } from '@tabler/icons-react';
import { useStore } from '../model/store';
import type { Gateway, Iface, Model } from '../model/types';
import { isIPv4, inSubnet } from '../lib/ip';
import { PageHeader, SectionTitle } from '../components/ui';
import { formatBits } from '../lib/format';
import { HistoryCard } from '../components/HistoryChart';

import { DeleteInterface } from '../components/DeleteInterface';
import { FileLink } from './ConfigFiles';

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
  masquerade: boolean;
  /** The WAN's VLAN, for providers that tag theirs; '' for none. */
  vlanTag: number | '';
}

// The gateway the WAN page edits: the default one when it's on this
// interface, else the first that is. /etc/mygate comes from Routing,
// so the page's Gateway field is that gateway's address.
function ownGateway(m: Model, id: string): Gateway | undefined {
  const own = m.routing.gateways.filter((g) => g.iface === id);
  return own.find((g) => g.id === m.routing.defaultGateway) ?? own[0];
}

/** The model with this interface's gateway following its address: the
 * one given for a fixed address, the lease's for DHCP. */
function withGateway(m: Model, i: Iface, address: string): Model {
  const gw = ownGateway(m, i.id);
  const fixed = address !== 'dhcp';
  // Its name says where it comes from when OPF named it so.
  const rename = (n: string) => (fixed ? n.replace(/_DHCP$/, '_GW') : n.replace(/_GW$/, '_DHCP'));
  if (gw) {
    if (gw.address === address) return m;
    const next = { ...gw, address, name: rename(gw.name) };
    return { ...m, routing: { ...m.routing, gateways: m.routing.gateways.map((g) => (g.id === gw.id ? next : g)) } };
  }
  let gid = `gw_${i.id}`;
  for (let n = 2; m.routing.gateways.some((g) => g.id === gid); n++) gid = `gw_${i.id}${n}`;
  const name = `${i.name.toUpperCase().replace(/[^A-Z0-9]+/g, '_').replace(/^_+|_+$/g, '') || 'WAN'}_${fixed ? 'GW' : 'DHCP'}`;
  const added: Gateway = { id: gid, name, iface: i.id, address, description: '' };
  return { ...m, routing: { ...m.routing, gateways: [...m.routing.gateways, added], defaultGateway: m.routing.defaultGateway || gid } };
}

function toValues(i: Iface, m: Model): Values {
  const gw = ownGateway(m, i.id);
  return {
    name: i.name,
    enabled: i.enabled,
    mode: i.ipv4.mode,
    address: i.ipv4.address ?? '',
    prefix: String(i.ipv4.prefix ?? 24),
    gateway: gw && gw.address !== 'dhcp' ? gw.address : '',
    ipv6: i.ipv6,
    mtu: i.mtu ?? '',
    blockPrivate: !!i.blockPrivate,
    blockBogons: !!i.blockBogons,
    antispoof: !!i.antispoof,
    masquerade: !!i.masquerade,
    vlanTag: i.role === 'wan' && i.vlan ? i.vlan.tag : '',
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
  if (!!before.masquerade !== !!after.masquerade) parts.push(after.masquerade ? 'shares its address with OPF’s other networks' : 'no longer shares its address');
  if (before.vlan?.tag !== after.vlan?.tag) parts.push(after.vlan ? `tagged as VLAN ${after.vlan.tag} on ${after.vlan.parent}` : `no longer tagged, on ${after.device}`);
  return `${before.name}: ${parts.join(', ') || 'updated'}`;
}

export function InterfaceEdit() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { staged, edit } = useStore();
  const [deleting, setDeleting] = useState(false);
  const iface = staged.interfaces.find((i) => i.id === id);

  const form = useForm<Values>({
    initialValues: toValues(iface ?? staged.interfaces[0], staged),
    validate: {
      name: (v) => (v.trim() ? null : 'Name can’t be empty'),
      address: (v, vals) => (vals.mode !== 'static' || isIPv4(v) ? null : 'Enter an IPv4 address like 192.168.1.1'),
      gateway: (v, vals) => {
        if (vals.mode !== 'static' || iface?.role !== 'wan') return null;
        // The default route needs it; another gateway can be the default.
        const gw = ownGateway(staged, iface.id);
        const isDefault = !staged.routing.defaultGateway || gw?.id === staged.routing.defaultGateway;
        if (!v) return isDefault ? 'Enter the gateway your ISP gave with the address: it’s the firewall’s way to the internet' : null;
        if (!isIPv4(v)) return 'Enter an IPv4 address';
        return inSubnet(v, vals.address, Number(vals.prefix)) ? null : 'The gateway must be inside this network';
      },
      mtu: (v) => (v === '' || (Number(v) >= 576 && Number(v) <= 9000) ? null : 'Use 576 to 9000, or leave empty'),
      vlanTag: (v) => {
        if (v === '') return null;
        if (!Number.isInteger(v) || v < 1 || v > 4094) return 'VLAN IDs are 1 to 4094';
        const other = staged.interfaces.find((i) => i.id !== iface?.id && i.device === `vlan${v}`);
        return other ? `${other.name} already uses VLAN ${v}` : null;
      },
    },
  });

  useEffect(() => {
    if (iface) form.setValues(toValues(iface, staged));
  }, [id]); // only when switching interfaces

  if (!iface) {
    return (
      <Text>
        No such interface. <Anchor component={Link} to="/interfaces">Back to interfaces</Anchor>
      </Text>
    );
  }

  const isWan = iface.role === 'wan';
  const inside = iface.role === 'lan' || iface.role === 'opt';
  const lockout = iface.role === 'lan' && (form.values.mode !== 'static' || form.values.address !== iface.ipv4.address);

  const submit = form.onSubmit((v) => {
    const next: Iface = {
      ...iface,
      name: v.name.trim(),
      enabled: v.enabled,
      ipv4: v.mode === 'static'
        ? { mode: 'static', address: v.address, prefix: Number(v.prefix) }
        : { mode: v.mode },
      ipv6: v.ipv6,
      mtu: v.mtu === '' ? undefined : Number(v.mtu),
      ...(isWan ? { blockPrivate: v.blockPrivate, blockBogons: v.blockBogons } : {}),
      // Antispoof needs a fixed address (pf expands it when it loads).
      antispoof: v.mode === 'static' && v.antispoof ? true : undefined,
      masquerade: inside && v.mode !== 'none' && v.masquerade ? true : undefined,
    };
    if (isWan) {
      // Tagged, the WAN is a VLAN on its port; untagged, the port itself.
      const port = iface.vlan?.parent ?? iface.device;
      if (v.vlanTag === '') {
        next.device = port;
        delete next.vlan;
      } else {
        next.device = `vlan${v.vlanTag}`;
        next.vlan = { parent: port, tag: v.vlanTag };
      }
    }
    if (next.antispoof === undefined) delete next.antispoof;
    if (next.masquerade === undefined) delete next.masquerade;
    // The WAN's gateway is kept under Routing, where mygate comes from.
    const gateway = isWan && v.mode === 'static' && v.gateway ? v.gateway : isWan && v.mode === 'dhcp' ? 'dhcp' : undefined;
    const gwBefore = ownGateway(staged, iface.id);
    const gwAfter = gateway ? ownGateway(withGateway(staged, next, gateway), iface.id) : gwBefore;
    if (JSON.stringify(next) !== JSON.stringify(iface)) {
      edit('interfaces', describe(iface, next), (m) => ({ ...m, interfaces: m.interfaces.map((i) => (i.id === iface.id ? next : i)) }));
    }
    if (gateway && gwAfter && JSON.stringify(gwAfter) !== JSON.stringify(gwBefore)) {
      edit('routing', gwAfter.address === 'dhcp' ? `${gwAfter.name}: from ${next.name}’s DHCP lease` : `${gwAfter.name}: ${gwAfter.address}${gwBefore ? '' : ', added'} on ${next.name}`, (m) => withGateway(m, next, gateway));
    }
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
          <>
            {iface.wireguard ? (
              <>
                WireGuard tunnel {iface.device} ·{' '}
                <Anchor component={Link} to={`/services/wireguard/${iface.id}`} size="sm">Its keys, port and devices are on WireGuard VPN</Anchor>
              </>
            ) : iface.vlan ? `VLAN ${iface.vlan.tag} on ${iface.vlan.parent}` : `Port ${iface.device}`}
            {' · '}<FileLink path={`/etc/hostname.${iface.device}`} />
          </>
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
            {isWan && (
              <NumberInput
                label="VLAN ID" placeholder="None" min={1} max={4094} allowDecimal={false}
                description={`Only if your provider tags its traffic: some fibre services do (VLAN 35, 10 or 7, say), and their instructions say which. OPF then carries the WAN as that VLAN on ${iface.vlan?.parent ?? iface.device}.`}
                {...form.getInputProps('vlanTag')}
              />
            )}
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
            {inside && (
              <Switch
                label="Share this address with OPF’s other networks"
                description={`Traffic from OPF’s other networks (VPN devices, other LANs) leaving through ${iface.name} takes its address, so this network’s router needn’t know about them. For OPF behind an existing router, such as a VPN server reached through a port forward.`}
                disabled={form.values.mode === 'none'}
                {...form.getInputProps('masquerade', { type: 'checkbox' })}
              />
            )}
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
