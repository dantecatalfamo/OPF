import type { Model } from '../model/types';

/** Where this page will be once a change is applied, when the change moves
 *  the address it's on. */
export interface Move {
  /** The name of the interface whose address the page is on. */
  name: string;
  /** The page's address after the change, or undefined when the interface
   *  will get one by DHCP (dhcp), which OPF can't know in advance, or none. */
  url?: string;
  dhcp?: boolean;
}

/** moving says whether applying `after` over `before` moves the address
 *  this page was loaded from (`location`): the browser then can't reach OPF
 *  where it is, and keeping the change has to happen at the new address.
 *  A page reached by name isn't moved: the name follows the address. */
export function moving(before: Model, after: Model, location: { protocol: string; hostname: string; port: string }): Move | null {
  const host = location.hostname;
  const was = before.interfaces.find((i) => i.enabled && i.ipv4.mode === 'static' && i.ipv4.address === host);
  if (!was) return null;
  const now = after.interfaces.find((i) => i.id === was.id);
  if (now?.enabled && now.ipv4.mode === 'static' && now.ipv4.address === host) return null;
  // Still on another interface, as long as it's there with this address.
  if (after.interfaces.some((i) => i.enabled && i.ipv4.mode === 'static' && i.ipv4.address === host)) return null;
  const port = location.port ? `:${location.port}` : '';
  return {
    name: (now ?? was).name,
    url: now?.enabled && now.ipv4.mode === 'static' && now.ipv4.address ? `${location.protocol}//${now.ipv4.address}${port}/` : undefined,
    ...(now?.enabled && now.ipv4.mode === 'dhcp' ? { dhcp: true } : {}),
  };
}
