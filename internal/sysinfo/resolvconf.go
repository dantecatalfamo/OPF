package sysinfo

import "strings"

// ResolvConf is what /etc/resolv.conf tells the firewall's own programs:
// the servers they ask, in order, and where to look first.
type ResolvConf struct {
	Servers []Nameserver `json:"servers"`
	// Lookup is the lookup line's sources, "file" (/etc/hosts) and "bind"
	// (DNS); OpenBSD's default when there's none is both, in that order.
	Lookup []string `json:"lookup"`
}

// Nameserver is one nameserver line.
type Nameserver struct {
	Address string `json:"address"`
	// From is where resolvd learned it (its comment: "resolvd: vio0" is
	// vio0); empty for a line resolvd didn't write.
	From string `json:"from,omitempty"`
	// Unused: the C library reads only the first three.
	Unused bool `json:"unused,omitempty"`
}

// ParseResolvConf reads a resolv.conf.
func ParseResolvConf(content string) ResolvConf {
	rc := ResolvConf{Servers: []Nameserver{}, Lookup: []string{"file", "bind"}}
	for _, l := range lines(content) {
		body, comment, _ := strings.Cut(l, "#")
		f := strings.Fields(body)
		if len(f) == 0 {
			continue
		}
		switch f[0] {
		case "nameserver":
			if len(f) < 2 {
				continue
			}
			ns := Nameserver{Address: f[1], Unused: len(rc.Servers) >= 3}
			if from, ok := strings.CutPrefix(strings.TrimSpace(comment), "resolvd:"); ok {
				ns.From = strings.TrimSpace(from)
			}
			rc.Servers = append(rc.Servers, ns)
		case "lookup":
			rc.Lookup = f[1:]
		}
	}
	return rc
}
