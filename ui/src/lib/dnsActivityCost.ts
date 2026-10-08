// What keeping DNS activity costs, for its setting: memory and disk from
// the worst case package activity measures (TestStoreWorstDaySize,
// TestStoreWorstDayMemory: memory is about what's saved), and whether
// the machine looks small or slow for it.
import type { SystemResource } from './api';
import { DEFAULT_ACTIVITY_DEVICES, type DnsActivitySettings } from '../model/types';

// A worst-case day, in bytes: every list full, every name asked for in
// every hour by its full ten devices.
const NETWORK_DAY = 65 * 1024; // the counts and the network's top names
const DETAIL_DAY = 307 * 1024; // their when and who
const DEVICE_DAY = 5705; // each device's counts and top names

export interface ActivityCost {
  /** Bytes at most, in memory and about as much on disk. */
  bytes: number;
  network: number;
  detail: number;
  devices: number;
}

/** The most the settings can take, with devices devices on the network. */
export function activityCost(a: Pick<DnsActivitySettings, 'days' | 'devices' | 'deviceDays' | 'detailDays' | 'maxDevices'>, devices: number): ActivityCost {
  const days = a.days;
  const devDays = Math.min(a.deviceDays || days, days);
  const detailDays = Math.min(a.detailDays || days, days);
  const n = Math.min(Math.max(devices, 1), a.maxDevices || DEFAULT_ACTIVITY_DEVICES);
  const network = NETWORK_DAY * days;
  const detail = DETAIL_DAY * detailDays;
  const devs = a.devices ? DEVICE_DAY * n * devDays : 0;
  return { bytes: network + detail + devs, network, detail, devices: devs };
}

export type CostLevel = 'ok' | 'note' | 'warn';

export interface CostAdvice {
  level: CostLevel;
  /** Why, a sentence each. */
  reasons: string[];
}

// CPUs that are slow for logging and counting every answer on a busy
// network: the low-power x86 and ARM boards firewalls often run on.
// Names end where they end; model numbers run into what follows them
// (the APU's "AMD GX-412TC").
const lowPowerCPU = /\b(atom|celeron|geode|cortex|arm|arm64|armv\d|aarch64)\b|\bpentium\s+[jn]|\bgx-\d|\bamd g-|\b[jn]\d{4}\b/i;

/** Advice for a machine: memory against its RAM, disk against /var's free space, and a low-power CPU. */
export function costAdvice(cost: ActivityCost, sys?: SystemResource): CostAdvice {
  const reasons: string[] = [];
  let level: CostLevel = 'ok';
  const raise = (l: CostLevel) => { if (l === 'warn' || (l === 'note' && level === 'ok')) level = l; };
  const ram = sys?.memory?.total;
  if (ram) {
    const share = cost.bytes / ram;
    if (share > 0.1) {
      raise('warn');
      reasons.push(`That’s ${Math.round(share * 100)}% of this machine’s memory: keep devices or the names’ when and who for fewer days, or keep only the network’s counts.`);
    } else if (share > 0.03) {
      raise('note');
      reasons.push(`That’s ${(share * 100).toFixed(1)}% of this machine’s memory.`);
    }
    if (ram <= 1 << 30) {
      raise('note');
      reasons.push('This machine has 1 GB of memory or less, which the resolver’s cache and blocklists share with this: shorter is safer.');
    }
  }
  const varDisk = sys?.disks.find((d) => d.mount === '/var') ?? sys?.disks.find((d) => d.mount === '/');
  if (varDisk && varDisk.available < cost.bytes * 4) {
    raise('warn');
    reasons.push(`${varDisk.mount} has little room left for it (it’s saved there every few minutes, beside the last copy).`);
  }
  const model = `${sys?.cpuModel ?? ''} ${sys?.machine ?? ''}`;
  const work = 'the resolver writes a line for every answer and OPF reads each one, which on a busy network can slow the resolver down. Watch the DNS page’s lookup times after turning it on.';
  if (sys && lowPowerCPU.test(model)) {
    raise('note');
    reasons.push(`This looks like a low-power machine (${sys.cpuModel || sys.machine}, ${sys.cpus} CPU${sys.cpus === 1 ? '' : 's'}): ${work}`);
  } else if (sys && sys.cpus <= 2) {
    raise('note');
    reasons.push(`This machine has ${sys.cpus === 1 ? 'one CPU' : 'two CPUs'}, which the resolver, OPF and the firewall share: ${work}`);
  }
  return { level, reasons };
}
