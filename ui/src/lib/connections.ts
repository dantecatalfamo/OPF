import type { StateKind } from './api';
// pf's connections (states) as pages show them.

export const protoGroup = (p: string) => (p === 'ipv6-icmp' ? 'icmp' : p);

// pf's state names for each side ("ESTABLISHED:FIN_WAIT_2") as one word
// for the table; the raw pair is in the tooltip.
export function stateLabel(state: string): string {
  const sides = state.split(':');
  if (sides.every((x) => x === 'ESTABLISHED')) return 'Open';
  if (sides.some((x) => /FIN_WAIT|CLOSING|CLOSE_WAIT|LAST_ACK|TIME_WAIT|CLOSED/.test(x))) return 'Closing';
  if (sides.some((x) => /SYN_SENT|SYN_RCVD|LISTEN/.test(x))) return 'Opening';
  if (sides.some((x) => x === 'MULTIPLE')) return 'Active';
  if (sides.some((x) => x === 'SINGLE')) return 'One-way';
  if (sides.some((x) => x === 'NO_TRAFFIC')) return 'Waiting';
  return state;
}

// What each end's pf state means, as the rest of a sentence about it.
const sidePhrase: Record<string, string> = {
  // TCP
  SYN_SENT: 'has asked to open it',
  SYN_RCVD: 'is answering the request to open it',
  LISTEN: 'is waiting for it to open',
  ESTABLISHED: 'has it open',
  CLOSE_WAIT: 'has been told the other end is done, and is finishing',
  FIN_WAIT_1: 'has started closing it',
  FIN_WAIT_2: 'has finished sending and is closing',
  CLOSING: 'is closing it',
  LAST_ACK: 'is closing it, waiting for the last acknowledgement',
  TIME_WAIT: 'has closed it; pf keeps it a little while for late packets',
  CLOSED: 'has closed it',
  // UDP and other protocols without a connection
  NO_TRAFFIC: 'hasn’t sent anything',
  SINGLE: 'has sent, with no reply yet when it did',
  MULTIPLE: 'has sent, with traffic going both ways',
};

// What a pair of states adds up to, for the common ones.
function pairSummary(a: string, b: string): string | undefined {
  if (a === 'ESTABLISHED' && b === 'ESTABLISHED') return 'Open both ways.';
  if (a === 'SINGLE' && b === 'NO_TRAFFIC') return 'Sent, with no reply yet: a request waiting for an answer, or something that doesn’t answer.';
  if (a === 'MULTIPLE' && b === 'SINGLE') return 'Answered once.';
  if (a === 'MULTIPLE' && b === 'MULTIPLE') return 'Traffic going both ways.';
  if (a === 'TIME_WAIT' && b === 'TIME_WAIT') return 'Finished; pf forgets it shortly.';
  if (/SYN/.test(a) || /SYN/.test(b)) return 'Still opening.';
  if (/FIN_WAIT|CLOSING|LAST_ACK|CLOSE_WAIT|TIME_WAIT|CLOSED/.test(a + b)) return 'Closing.';
  return undefined;
}

/** pf's state pair in words. pfctl prints the pair in the order it
 *  prints the addresses: for a connection out (->) the end that opened
 *  it first, for one in (<-) the end it was opened to (tried on the
 *  test VM: a lookup in, answered once, is SINGLE:MULTIPLE). opener and
 *  other name the two ends: "This device" and "the other end" on a
 *  device's page, say. */
export function stateExplain(state: string, direction: 'in' | 'out', opener = 'The end that opened it', other = 'the other end'): string {
  let [a, b] = state.split(':');
  if (b === undefined) return state;
  if (direction === 'in') [a, b] = [b, a];
  const phrase = (s: string) => sidePhrase[s] ?? `is ${s}`;
  const summary = pairSummary(a, b);
  return `${summary ? summary + ' ' : ''}${opener} ${phrase(a)}; ${other} ${phrase(b)}.`;
}

/** The kinds of state, in the filter's order, as pages name them. */
export const stateKinds: { value: StateKind; label: string; help: string }[] = [
  { value: 'open', label: 'Open', help: 'TCP, open both ways' },
  { value: 'active', label: 'Active', help: 'Without a connection (UDP), traffic both ways' },
  { value: 'opening', label: 'Opening', help: 'TCP, the handshake not finished' },
  { value: 'closing', label: 'Closing', help: 'TCP, either end closing, or closed and about to go' },
  { value: 'one-way', label: 'One-way', help: 'Sent, with no answer' },
  { value: 'waiting', label: 'Waiting', help: 'Nothing sent yet' },
  { value: 'other', label: 'Other', help: 'ICMP and the like' },
];

/** A state's word: the server's kind when it sent one. */
export function stateWord(state: string, kind?: string): string {
  return stateKinds.find((k) => k.value === kind)?.label ?? stateLabel(state);
}
