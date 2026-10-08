package pf

import (
	"strings"
)

// /etc/hosts is shared like sysctl.conf: OPF adds the firewall's own
// name, with its address on each inside network, so its own programs
// find it. resolv.conf sends their lookups to the WAN's DNS servers
// (resolvd), which don't know OPF's domain, and "lookup file bind"
// reads this file first, even while the resolver is down. Each of OPF's
// lines ends in hostsMark, so a merge finds them wherever they are,
// after a rename too; every other line is the system's, kept as it is.

// HostsPath is where the hosts file lives.
const HostsPath = "/etc/hosts"

// hostsMark ends each of OPF's lines.
const hostsMark = "# set by OPF"

// hostsDefault is a stock OpenBSD /etc/hosts, for a system that has none.
const hostsDefault = "127.0.0.1\tlocalhost\n::1\t\tlocalhost\n"

// HostsLines are OPF's lines: the firewall's name and short name on
// each inside network with a fixed address, the first network first.
// None when it has no name.
func HostsLines(m *Model) []string {
	name := firewallName(m)
	if name == "" {
		return nil
	}
	var lines []string
	for _, i := range staticIfaces(m) {
		if i.Role == RoleWAN || (i.WireGuard != nil && i.WireGuard.Exit != nil) {
			continue // the internet's side, or a VPN provider's
		}
		lines = append(lines, i.IPv4.Address+"\t"+name+" "+m.System.Hostname+"\t"+hostsMark)
	}
	return lines
}

func isHostsLine(l string) bool { return strings.HasSuffix(strings.TrimRight(l, " \t"), hostsMark) }

// MergeHosts returns an existing hosts file with OPF's lines as the
// model has them: every line of OPF's is taken out wherever it is, and
// the model's go at the end.
func MergeHosts(existing string, m *Model) string {
	if strings.TrimSpace(existing) == "" {
		existing = hostsDefault
	}
	var kept []string
	for _, line := range strings.Split(strings.TrimSuffix(existing, "\n"), "\n") {
		if !isHostsLine(line) {
			kept = append(kept, line)
		}
	}
	for len(kept) > 0 && strings.TrimSpace(kept[len(kept)-1]) == "" {
		kept = kept[:len(kept)-1]
	}
	var b strings.Builder
	for _, line := range append(kept, HostsLines(m)...) {
		b.WriteString(line + "\n")
	}
	return b.String()
}

// HostsValues are OPF's lines in a hosts file, for telling whether
// someone changed them; the rest isn't OPF's.
func HostsValues(content string) []string {
	var out []string
	for _, line := range strings.Split(content, "\n") {
		if isHostsLine(line) {
			out = append(out, strings.Join(strings.Fields(line), " "))
		}
	}
	return out
}

// GenerateHosts is the hosts file on a system that has none. The
// appliance merges into the live file instead.
func GenerateHosts(m *Model) string { return MergeHosts("", m) }
