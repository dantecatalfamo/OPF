// ICMP and ICMPv6 type definitions for the rule form.
// Reference: https://www.openbsd.org/faq/pf/filter.html
// https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml
// https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml

export interface ICMPCode {
  name: string;
  number: number;
  description: string;
}

export interface ICMPType {
  name: string;
  number: number;
  description: string;
  codes?: ICMPCode[];
}

// ICMP (IPv4) types commonly used in firewall rules
export const icmpTypes: ICMPType[] = [
  {
    name: 'echoreq',
    number: 8,
    description: 'Echo request (ping)',
  },
  {
    name: 'echorep',
    number: 0,
    description: 'Echo reply',
  },
  {
    name: 'unreach',
    number: 3,
    description: 'Destination unreachable',
    codes: [
      { name: 'net-unr', number: 0, description: 'Network unreachable' },
      { name: 'host-unr', number: 1, description: 'Host unreachable' },
      { name: 'proto-unr', number: 2, description: 'Protocol unreachable' },
      { name: 'port-unr', number: 3, description: 'Port unreachable' },
      { name: 'needfrag', number: 4, description: 'Fragmentation needed but DF set' },
      { name: 'srcfail', number: 5, description: 'Source route failed' },
      { name: 'net-unk', number: 6, description: 'Network unknown' },
      { name: 'host-unk', number: 7, description: 'Host unknown' },
      { name: 'isolate', number: 8, description: 'Source host isolated' },
      { name: 'net-prohib', number: 9, description: 'Network administratively prohibited' },
      { name: 'host-prohib', number: 10, description: 'Host administratively prohibited' },
      { name: 'net-tos', number: 11, description: 'Network unreachable for TOS' },
      { name: 'host-tos', number: 12, description: 'Host unreachable for TOS' },
      { name: 'filter-prohib', number: 13, description: 'Communication administratively prohibited' },
      { name: 'host-preced', number: 14, description: 'Host precedence violation' },
      { name: 'preced-cutoff', number: 15, description: 'Precedence cutoff in effect' },
    ],
  },
  {
    name: 'squench',
    number: 4,
    description: 'Source quench (deprecated)',
  },
  {
    name: 'redir',
    number: 5,
    description: 'Redirect',
    codes: [
      { name: 'redir-net', number: 0, description: 'Redirect for network' },
      { name: 'redir-host', number: 1, description: 'Redirect for host' },
      { name: 'redir-tos-net', number: 2, description: 'Redirect for TOS and network' },
      { name: 'redir-tos-host', number: 3, description: 'Redirect for TOS and host' },
    ],
  },
  {
    name: 'althost',
    number: 6,
    description: 'Alternate host address',
  },
  {
    name: 'routeradv',
    number: 9,
    description: 'Router advertisement',
  },
  {
    name: 'routersol',
    number: 10,
    description: 'Router solicitation',
  },
  {
    name: 'timex',
    number: 11,
    description: 'Time exceeded',
    codes: [
      { name: 'transit', number: 0, description: 'TTL exceeded in transit' },
      { name: 'reassemb', number: 1, description: 'Fragment reassembly time exceeded' },
    ],
  },
  {
    name: 'paramprob',
    number: 12,
    description: 'Parameter problem',
    codes: [
      { name: 'badhead', number: 0, description: 'Pointer indicates error' },
      { name: 'optmiss', number: 1, description: 'Missing required option' },
      { name: 'badlen', number: 2, description: 'Bad length' },
    ],
  },
  {
    name: 'timereq',
    number: 13,
    description: 'Timestamp request',
  },
  {
    name: 'timerep',
    number: 14,
    description: 'Timestamp reply',
  },
  {
    name: 'inforeq',
    number: 15,
    description: 'Information request (deprecated)',
  },
  {
    name: 'inforep',
    number: 16,
    description: 'Information reply (deprecated)',
  },
  {
    name: 'maskreq',
    number: 17,
    description: 'Address mask request',
  },
  {
    name: 'maskrep',
    number: 18,
    description: 'Address mask reply',
  },
  {
    name: 'trace',
    number: 30,
    description: 'Traceroute',
  },
  {
    name: 'dataconv',
    number: 31,
    description: 'Datagram conversion error',
  },
  {
    name: 'mobredir',
    number: 32,
    description: 'Mobile host redirect',
  },
  {
    name: 'ipv6-where',
    number: 33,
    description: 'IPv6 where-are-you',
  },
  {
    name: 'ipv6-here',
    number: 34,
    description: 'IPv6 I-am-here',
  },
  {
    name: 'mobregreq',
    number: 35,
    description: 'Mobile registration request',
  },
  {
    name: 'mobregrep',
    number: 36,
    description: 'Mobile registration reply',
  },
  {
    name: 'skip',
    number: 39,
    description: 'SKIP',
  },
  {
    name: 'photuris',
    number: 40,
    description: 'Photuris',
  },
];

// ICMPv6 types commonly used in firewall rules
export const icmp6Types: ICMPType[] = [
  {
    name: 'unreach',
    number: 1,
    description: 'Destination unreachable',
    codes: [
      { name: 'noroute', number: 0, description: 'No route to destination' },
      { name: 'admin-prohib', number: 1, description: 'Administratively prohibited' },
      { name: 'beyond-scope', number: 2, description: 'Beyond scope of source address' },
      { name: 'addr-unr', number: 3, description: 'Address unreachable' },
      { name: 'port-unr', number: 4, description: 'Port unreachable' },
      { name: 'src-fail', number: 5, description: 'Source address failed policy' },
      { name: 'rej-route', number: 6, description: 'Reject route to destination' },
    ],
  },
  {
    name: 'toobig',
    number: 2,
    description: 'Packet too big',
  },
  {
    name: 'timex',
    number: 3,
    description: 'Time exceeded',
    codes: [
      { name: 'transit', number: 0, description: 'Hop limit exceeded in transit' },
      { name: 'reassemb', number: 1, description: 'Fragment reassembly time exceeded' },
    ],
  },
  {
    name: 'paramprob',
    number: 4,
    description: 'Parameter problem',
    codes: [
      { name: 'badhead', number: 0, description: 'Erroneous header field' },
      { name: 'nxthdr', number: 1, description: 'Unrecognized next header' },
      { name: 'badoption', number: 2, description: 'Unrecognized IPv6 option' },
    ],
  },
  {
    name: 'echoreq',
    number: 128,
    description: 'Echo request (ping6)',
  },
  {
    name: 'echorep',
    number: 129,
    description: 'Echo reply',
  },
  {
    name: 'groupqry',
    number: 130,
    description: 'Multicast listener query',
  },
  {
    name: 'listqry',
    number: 130,
    description: 'Multicast listener query (alias)',
  },
  {
    name: 'grouprep',
    number: 131,
    description: 'Multicast listener report',
  },
  {
    name: 'listenrep',
    number: 131,
    description: 'Multicast listener report (alias)',
  },
  {
    name: 'groupterm',
    number: 132,
    description: 'Multicast listener done',
  },
  {
    name: 'listendone',
    number: 132,
    description: 'Multicast listener done (alias)',
  },
  {
    name: 'routersol',
    number: 133,
    description: 'Router solicitation',
  },
  {
    name: 'routeradv',
    number: 134,
    description: 'Router advertisement',
  },
  {
    name: 'neighbrsol',
    number: 135,
    description: 'Neighbor solicitation',
  },
  {
    name: 'neighbradv',
    number: 136,
    description: 'Neighbor advertisement',
  },
  {
    name: 'redir',
    number: 137,
    description: 'Redirect',
  },
  {
    name: 'routerrenum',
    number: 138,
    description: 'Router renumbering',
  },
  {
    name: 'nireq',
    number: 139,
    description: 'Node information query',
  },
  {
    name: 'nirep',
    number: 140,
    description: 'Node information response',
  },
  {
    name: 'invrtrreq',
    number: 141,
    description: 'Inverse neighbor discovery solicitation',
  },
  {
    name: 'invrtrrep',
    number: 142,
    description: 'Inverse neighbor discovery advertisement',
  },
  {
    name: 'mtraceresp',
    number: 200,
    description: 'Multicast traceroute response',
  },
  {
    name: 'mtrace',
    number: 201,
    description: 'Multicast traceroute',
  },
];

// Commonly used ICMP types for quick selection
export const commonIcmpTypes = ['echoreq', 'echorep', 'unreach', 'timex', 'paramprob', 'redir'];
export const commonIcmp6Types = ['echoreq', 'echorep', 'unreach', 'toobig', 'timex', 'neighbrsol', 'neighbradv', 'routersol', 'routeradv'];

/**
 * Get ICMP type by name.
 */
export function getIcmpType(name: string, isV6: boolean = false): ICMPType | undefined {
  const types = isV6 ? icmp6Types : icmpTypes;
  return types.find((t) => t.name === name);
}

/**
 * Get ICMP type options for a Select component.
 */
export function getIcmpTypeOptions(isV6: boolean = false): Array<{ value: string; label: string; description: string }> {
  const types = isV6 ? icmp6Types : icmpTypes;
  return types.map((t) => ({
    value: t.name,
    label: `${t.name} (${t.number})`,
    description: t.description,
  }));
}

/**
 * Get ICMP code options for a Select component.
 */
export function getIcmpCodeOptions(typeName: string, isV6: boolean = false): Array<{ value: string; label: string; description: string }> {
  const icmpType = getIcmpType(typeName, isV6);
  if (!icmpType?.codes) {
    return [];
  }
  return icmpType.codes.map((c) => ({
    value: c.name,
    label: `${c.name} (${c.number})`,
    description: c.description,
  }));
}

// ICMP codes for block return-icmp
export const returnIcmpCodes = [
  { value: 'net-unr', label: 'net-unr', description: 'Network unreachable' },
  { value: 'host-unr', label: 'host-unr', description: 'Host unreachable' },
  { value: 'port-unr', label: 'port-unr', description: 'Port unreachable (default)' },
  { value: 'proto-unr', label: 'proto-unr', description: 'Protocol unreachable' },
  { value: 'needfrag', label: 'needfrag', description: 'Fragmentation needed' },
  { value: 'filter-prohib', label: 'filter-prohib', description: 'Communication administratively prohibited' },
];

export const returnIcmp6Codes = [
  { value: 'noroute', label: 'noroute', description: 'No route to destination' },
  { value: 'admin-prohib', label: 'admin-prohib', description: 'Administratively prohibited' },
  { value: 'addr-unr', label: 'addr-unr', description: 'Address unreachable' },
  { value: 'port-unr', label: 'port-unr', description: 'Port unreachable (default)' },
];
