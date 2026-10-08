package pf

import "fmt"

// DhcpleasedPath is dhcpleased's configuration. OPF writes it only to
// keep the WAN's DNS servers out of the firewall's own lookups
// (SystemDNS.Only): dhcpleased then proposes none to resolvd, and
// withdraws those it did when it's told to reload (SIGHUP); without
// the file it proposes them again at once (seen on 7.9).
const DhcpleasedPath = "/etc/dhcpleased.conf"

// IgnoresLeaseDNS says whether the model keeps the leases' DNS servers
// out, and so has a dhcpleased.conf.
func IgnoresLeaseDNS(m *Model) bool {
	d := SystemDNSOf(m)
	return d.Only && d.Mode != SystemDNSWAN && len(dhcpIfaces(m)) > 0
}

func dhcpIfaces(m *Model) []Iface {
	var out []Iface
	for _, i := range m.Interfaces {
		if i.Enabled && i.IPv4.Mode == IPv4DHCP {
			out = append(out, i)
		}
	}
	return out
}

// GenerateDhcpleasedConf is dhcpleased.conf: every interface that takes
// its address by DHCP ignores the DNS servers its lease brings.
func GenerateDhcpleasedConf(m *Model) string {
	out := header + "\n"
	for _, i := range dhcpIfaces(m) {
		out += fmt.Sprintf("\n# %s: the firewall asks only the DNS servers set on System › General.\ninterface %s {\n\tignore dns\n}\n", i.Name, i.Device)
	}
	return out
}
