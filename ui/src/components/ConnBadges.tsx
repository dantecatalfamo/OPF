// How the connection pages show a connection's protocol and direction,
// the same everywhere: each protocol its own colour, and the direction
// an arrow in a colour no protocol has.
import { Badge, Group, Text, useComputedColorScheme } from '@mantine/core';
import { IconArrowDownLeft, IconArrowUpRight } from '@tabler/icons-react';

const protoColor: Record<string, string> = { tcp: 'blue.7', udp: 'grape.7', icmp: 'orange.8' };

/** A protocol: TCP blue, UDP violet, ICMP orange, the rest grey. */
export function ProtoBadge({ proto }: { proto: string }) {
  const p = proto === 'ipv6-icmp' ? 'icmp' : proto;
  return <Badge size="sm" variant="filled" color={protoColor[p] ?? 'gray'} w={52}>{p.toUpperCase()}</Badge>;
}

/** Which way: in, arriving (an arrow down and in, yellow), or out,
 *  leaving (an arrow up and out, teal); words says it, "In on LAN" or "To". */
export function DirLabel({ dir, children }: { dir: 'in' | 'out'; children: React.ReactNode }) {
  const In = dir === 'in';
  const Arrow = In ? IconArrowDownLeft : IconArrowUpRight;
  // Light shades read on a dark background, dark ones on a light one.
  const dark = useComputedColorScheme('light') === 'dark';
  const color = In ? `var(--mantine-color-yellow-${dark ? 5 : 9})` : `var(--mantine-color-teal-${dark ? 5 : 8})`;
  return (
    <Group gap={4} wrap="nowrap">
      <Arrow size={16} stroke={2.2} color={color} style={{ flexShrink: 0 }} />
      <Text size="sm" fw={500} style={{ whiteSpace: 'nowrap', color }}>{children}</Text>
    </Group>
  );
}
