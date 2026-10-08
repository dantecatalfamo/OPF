// pf's connections (states) as pages show them.

export const protoGroup = (p: string) => (p === 'ipv6-icmp' ? 'icmp' : p);

// pf's state names for each side ("ESTABLISHED:FIN_WAIT_2") as one word
// for the table; the raw pair is in the tooltip.
export function stateLabel(state: string): string {
  const sides = state.split(':');
  if (sides.every((x) => x === 'ESTABLISHED')) return 'Open';
  if (sides.some((x) => /FIN_WAIT|CLOSING|TIME_WAIT|CLOSED/.test(x))) return 'Closing';
  if (sides.some((x) => /SYN_SENT|SYN_RCVD|LISTEN/.test(x))) return 'Opening';
  if (sides.some((x) => x === 'MULTIPLE')) return 'Active';
  if (sides.some((x) => x === 'SINGLE')) return 'One-way';
  if (sides.some((x) => x === 'NO_TRAFFIC')) return 'Waiting';
  return state;
}
