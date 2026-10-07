package pf

import (
	"fmt"
	"regexp"
	"strings"
)

// Upgrade brings a model written by an older OPF up to date, in place.
// Every model read from disk or given to stage goes through it, so the
// rest of OPF only ever sees the current shape.
//
// An interface's ipv4.gateway used to be where the WAN page kept a
// fixed gateway, but nothing generated from it: /etc/mygate comes from
// Routing. It moves to the interface's gateway there.
func Upgrade(m *Model) {
	for i := range m.Interfaces {
		f := &m.Interfaces[i]
		g := f.IPv4.Gateway
		f.IPv4.Gateway = ""
		if g == "" || f.IPv4.Mode != IPv4Static {
			continue
		}
		moveGateway(m, f, g)
	}
}

var gatewayNameRE = regexp.MustCompile(`[^A-Z0-9]+`)

// moveGateway gives an interface's gateway in Routing the address: the
// default gateway if it's on the interface, else the first that is, or a
// new one. One Routing already gives a fixed address wins.
func moveGateway(m *Model, f *Iface, addr string) {
	own := -1
	for i, g := range m.Routing.Gateways {
		if g.Iface != f.ID {
			continue
		}
		if own < 0 || g.ID == m.Routing.DefaultGateway {
			own = i
		}
	}
	if own >= 0 {
		if g := &m.Routing.Gateways[own]; g.Address == "dhcp" {
			g.Address = addr
			// Its name says where it comes from when OPF named it so.
			if n, ok := strings.CutSuffix(g.Name, "_DHCP"); ok {
				g.Name = n + "_GW"
			}
		}
		return
	}
	base := "gw_" + f.ID
	id := base
	for n := 2; gatewayExists(m, id); n++ {
		id = fmt.Sprintf("%s%d", base, n)
	}
	name := strings.Trim(gatewayNameRE.ReplaceAllString(strings.ToUpper(f.Name), "_"), "_")
	if name == "" {
		name = "WAN"
	}
	if len(name) > 60 {
		name = name[:60]
	}
	m.Routing.Gateways = append(m.Routing.Gateways, Gateway{ID: id, Name: name + "_GW", Iface: f.ID, Address: addr})
	if m.Routing.DefaultGateway == "" {
		m.Routing.DefaultGateway = id
	}
}

func gatewayExists(m *Model, id string) bool {
	for _, g := range m.Routing.Gateways {
		if g.ID == id {
			return true
		}
	}
	return false
}
