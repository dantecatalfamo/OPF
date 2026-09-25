import { Group, Text } from '@mantine/core';

// A small pufferfish mark, after OpenBSD's Puffy.
export function BrandMark({ size = 28 }: { size?: number }) {
  // Spikes around the body, leaving a gap on the left for the tail.
  const spikes = Array.from({ length: 7 }, (_, i) => {
    const a = -Math.PI * 0.7 + (i / 6) * Math.PI * 1.4;
    return { x1: 18 + Math.cos(a) * 7, y1: 16 + Math.sin(a) * 7, x2: 18 + Math.cos(a) * 10.5, y2: 16 + Math.sin(a) * 10.5 };
  });
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden="true">
      <rect width="32" height="32" rx="8" fill="var(--mantine-color-harbor-8)" />
      {spikes.map((s, i) => (
        <line key={i} {...s} stroke="var(--mantine-color-amber-5)" strokeWidth="2" strokeLinecap="round" />
      ))}
      <path d="M5 10.5 L11.5 16 L5 21.5 Z" fill="var(--mantine-color-amber-5)" />
      <circle cx="18" cy="16" r="7" fill="var(--mantine-color-amber-5)" />
      <circle cx="21" cy="14" r="1.5" fill="var(--mantine-color-harbor-9)" />
    </svg>
  );
}

export function Brand() {
  return (
    <Group gap={10} wrap="nowrap">
      <BrandMark />
      <Text fw={600} size="lg" lh={1}>
        OPF
      </Text>
    </Group>
  );
}
