const octet = '(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)';
const ipv4RE = new RegExp(`^${octet}(\\.${octet}){3}$`);

export const isIPv4 = (s: string) => ipv4RE.test(s.trim());

export function isCIDR(s: string): boolean {
  const [addr, prefix, extra] = s.trim().split('/');
  if (extra !== undefined || prefix === undefined) return false;
  const p = Number(prefix);
  return isIPv4(addr) && Number.isInteger(p) && p >= 0 && p <= 32;
}

export const isMAC = (s: string) => /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(s.trim());

export function isPortSpec(s: string): boolean {
  const m = s.trim().match(/^(\d+)(-(\d+))?$/);
  if (!m) return false;
  const a = Number(m[1]);
  const b = m[3] ? Number(m[3]) : a;
  return a >= 1 && b <= 65535 && a <= b;
}

export function toInt(ip: string): number {
  return ip.split('.').reduce((acc, o) => (acc << 8) + Number(o), 0) >>> 0;
}

export function fromInt(n: number): string {
  return [24, 16, 8, 0].map((s) => (n >>> s) & 255).join('.');
}

export function netmask(prefix: number): string {
  return fromInt(prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0);
}

export function network(address: string, prefix: number): string {
  return fromInt((toInt(address) & toInt(netmask(prefix))) >>> 0);
}

export function inSubnet(ip: string, address: string, prefix: number): boolean {
  return isIPv4(ip) && network(ip, prefix) === network(address, prefix);
}
