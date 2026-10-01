import { IconBell, IconArrowsSplit2, IconNetwork, IconRouter, IconServer2, IconSettings, IconShieldHalf, IconWorldWww } from '@tabler/icons-react';
import type { Section } from '../model/types';

export const sectionIcon: Record<Section, typeof IconNetwork> = {
  system: IconSettings,
  interfaces: IconNetwork,
  routing: IconArrowsSplit2,
  firewall: IconShieldHalf,
  dhcp: IconRouter,
  dns: IconWorldWww,
  wireguard: IconServer2,
  notifications: IconBell,
};
