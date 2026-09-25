import { IconNetwork, IconRouter, IconServer2, IconSettings, IconShieldHalf, IconWorldWww } from '@tabler/icons-react';
import type { Section } from '../model/types';

export const sectionIcon: Record<Section, typeof IconNetwork> = {
  system: IconSettings,
  interfaces: IconNetwork,
  firewall: IconShieldHalf,
  dhcp: IconRouter,
  dns: IconWorldWww,
  wireguard: IconServer2,
};
