// What each of pf's timeouts is for (pf.conf(5)'s set timeout), for
// Firewall › Statistics and the timeouts in Firewall › Settings.
export const timeoutHelp: Record<string, string> = {
  'tcp.first': 'A TCP connection after its first packet',
  'tcp.opening': 'Before the other end has answered',
  'tcp.established': 'An open TCP connection, idle',
  'tcp.closing': 'After the first FIN',
  'tcp.finwait': 'After both ends have sent FIN',
  'tcp.closed': 'After a reset',
  'tcp.tsdiff': 'How far a TCP timestamp may be off',
  'udp.first': 'UDP after the first packet',
  'udp.single': 'UDP when only one end has sent',
  'udp.multiple': 'UDP when both ends have sent',
  'icmp.first': 'ICMP after the first packet',
  'icmp.error': 'After an ICMP error',
  'other.first': 'Other protocols after the first packet',
  'other.single': 'Other protocols when only one end has sent',
  'other.multiple': 'Other protocols when both ends have sent',
  frag: 'How long a fragment waits for the rest',
  interval: 'How often pf purges expired states',
  'adaptive.start': 'States at which timeouts start shrinking',
  'adaptive.end': 'States at which timeouts reach zero',
  'src.track': 'How long a source node lasts after its last state',
};
