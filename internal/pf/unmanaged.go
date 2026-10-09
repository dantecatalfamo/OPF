package pf

import "slices"

// Areas OPF can leave as they're configured by hand. A machine taken
// over from read-only mode (appliance's import) often has a DHCP
// server, resolver or time sources set up in ways OPF's model doesn't
// cover; rather than rewrite them on the first commit, OPF leaves the
// area's file and daemon alone until the admin hands it over. While an
// area is left alone:
//
//   - its file isn't generated, so a commit neither writes nor removes it;
//   - its daemon's rc.conf.local variable is the admin's, so OPF neither
//     sets it nor starts, stops or restarts the daemon (RcReconcile);
//   - the model's own settings for it are off (Validate): DHCP scopes
//     disabled, the resolver off. They're kept, so handing the area over
//     starts from what the import understood.
//
// The firewall and the interfaces are what OPF is for, so they're never
// left alone; an interface the import can't model is simply not in the
// model, and OPF doesn't touch a hostname.if for a device it doesn't
// know.

// Area names, in System.Unmanaged.
const (
	AreaDHCP = "dhcp" // /etc/dhcpd.conf and dhcpd
	AreaDNS  = "dns"  // unbound.conf and unbound
	AreaNTP  = "ntp"  // /etc/ntpd.conf and ntpd
)

// Areas are the areas that can be left alone, in the order pages list
// them.
var Areas = []string{AreaDHCP, AreaDNS, AreaNTP}

// Paths of the files each area's generator writes.
const (
	DHCPdConfPath   = "/etc/dhcpd.conf"
	UnboundConfPath = "/var/unbound/etc/unbound.conf"
	NTPdConfPath    = "/etc/ntpd.conf"
)

// Unmanaged says whether the model leaves an area as it's configured by
// hand.
func Unmanaged(m *Model, area string) bool {
	return slices.Contains(m.System.Unmanaged, area)
}

// UnmanagedPaths are the files OPF leaves alone because their area is:
// a commit doesn't write them, and doesn't remove them either, though an
// earlier model generated them.
func UnmanagedPaths(m *Model) []string {
	var out []string
	if Unmanaged(m, AreaDHCP) {
		out = append(out, DHCPdConfPath)
	}
	if Unmanaged(m, AreaDNS) {
		out = append(out, UnboundConfPath, OwnZonePath)
	}
	if Unmanaged(m, AreaNTP) {
		out = append(out, NTPdConfPath)
	}
	return out
}

// areaService is the daemon whose rc.conf.local variable belongs to
// the admin while its area is left alone.
var areaService = map[string]string{AreaDHCP: "dhcpd_flags", AreaDNS: "unbound_flags"}

// rcNames are the rc.conf.local variables OPF sets for this model:
// RcNames, but for the areas it leaves alone.
func rcNames(m *Model) []string {
	var out []string
	for _, n := range RcNames {
		left := false
		for area, v := range areaService {
			if v == n && Unmanaged(m, area) {
				left = true
			}
		}
		if !left {
			out = append(out, n)
		}
	}
	return out
}
