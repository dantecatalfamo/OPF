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

const isPort = (s: string) => /^\d+$/.test(s) && Number(s) >= 1 && Number(s) <= 65535;

// A single port or range: "443", "8000-8080", "8000:8080".
export function isPortSpec(s: string): boolean {
  const m = s.trim().match(/^(\d+)([-:](\d+))?$/);
  if (!m) return false;
  return isPort(m[1]) && (!m[3] || (isPort(m[3]) && Number(m[1]) <= Number(m[3])));
}

// Anything pf accepts after "port": the above, a comma list, or an
// operator form such as "> 1023", "!= 22", "1024 >< 2048".
export function isPfPortExpr(s: string): boolean {
  const t = s.trim();
  if (t.includes(',')) return t.split(',').every((x) => isPortSpec(x));
  if (isPortSpec(t)) return true;
  const un = t.match(/^(=|!=|<|<=|>|>=)\s*(\d+)$/);
  if (un) return isPort(un[2]);
  const bin = t.match(/^(\d+)\s*(<>|><)\s*(\d+)$/);
  return !!bin && isPort(bin[1]) && isPort(bin[3]);
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
