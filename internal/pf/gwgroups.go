package pf

import (
	"slices"
	"strings"
)

// Gateways a rule sends through by a table rather than an address: a
// gateway group, whose gateways in use change with their health, and a
// DHCP gateway, whose address comes with the lease. pf.conf declares
// each table empty and persist, so a reload keeps what OPF put in it
// (appliance's gateway watch), and a rule sends through it with
// route-to <table> round-robin.

// gatewayTablePrefix starts each such table's name.
const gatewayTablePrefix = "opf_gw_"

// GatewayTable is the table a group's or a DHCP gateway's addresses are
// in, by its id.
func GatewayTable(id string) string { return gatewayTablePrefix + id }

// maxTabledID is the longest id that still makes a table name pf takes
// (31 characters, PF_TABLE_NAME_SIZE less one).
const maxTabledID = 31 - len(gatewayTablePrefix)

// FindGroup is the gateway group with an id, or nil.
func FindGroup(m *Model, id string) *GatewayGroup {
	for i := range m.Routing.Groups {
		if m.Routing.Groups[i].ID == id {
			return &m.Routing.Groups[i]
		}
	}
	return nil
}

// FindGateway is the gateway with an id, or nil.
func FindGateway(m *Model, id string) *Gateway {
	for i := range m.Routing.Gateways {
		if m.Routing.Gateways[i].ID == id {
			return &m.Routing.Gateways[i]
		}
	}
	return nil
}

// tabled says whether a rule naming id sends through a table: a group,
// or a DHCP gateway.
func tabled(m *Model, id string) bool {
	if FindGroup(m, id) != nil {
		return true
	}
	g := FindGateway(m, id)
	return g != nil && g.Address == "dhcp"
}

// GatewayTables are the ids of the groups and DHCP gateways the
// enabled rules send through, each once, in name order: the tables
// pf.conf declares and OPF fills.
func GatewayTables(m *Model) []string {
	var out []string
	for _, r := range m.Firewall.Rules {
		if !r.Enabled || !r.IsForm() {
			continue
		}
		for _, id := range []string{r.Gateway, r.ReplyTo} {
			if id != "" && tabled(m, id) && !slices.Contains(out, id) {
				out = append(out, id)
			}
		}
	}
	slices.Sort(out)
	return out
}

// routeTarget is what a rule's route-to or reply-to names: a gateway's
// address, or its table with the pool options a table needs ("" when
// there's no such gateway).
func routeTarget(id string, m *Model) string {
	if !tabled(m, id) {
		return gatewayAddr(id, m)
	}
	s := "<" + GatewayTable(id) + "> round-robin"
	if g := FindGroup(m, id); g != nil && g.Sticky {
		s += " sticky-address"
	}
	return s
}

// GroupInUse is which of a group's gateways are in use, given which
// answer (up, by id): those that answer in the first tier where any
// does; when none does, all of the first tier, which is still the best
// guess.
func GroupInUse(g GatewayGroup, up func(id string) bool) []string {
	tiers := map[int][]string{}
	var order []int
	for _, mb := range g.Members {
		if _, ok := tiers[mb.Tier]; !ok {
			order = append(order, mb.Tier)
		}
		tiers[mb.Tier] = append(tiers[mb.Tier], mb.Gateway)
	}
	slices.Sort(order)
	for _, t := range order {
		var ok []string
		for _, id := range tiers[t] {
			if up(id) {
				ok = append(ok, id)
			}
		}
		if len(ok) > 0 {
			return ok
		}
	}
	if len(order) == 0 {
		return nil
	}
	return tiers[order[0]]
}

// TierOf is the tier a gateway is in, in a group (0: it isn't).
func (g GatewayGroup) TierOf(id string) int {
	for _, mb := range g.Members {
		if mb.Gateway == id {
			return mb.Tier
		}
	}
	return 0
}

// GatewayNames joins gateways' names for a sentence: "WAN and Backup".
func GatewayNames(m *Model, ids []string) string {
	names := make([]string, len(ids))
	for i, id := range ids {
		names[i] = id
		if g := FindGateway(m, id); g != nil {
			names[i] = g.Name
		}
	}
	if len(names) <= 1 {
		return strings.Join(names, "")
	}
	return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
}
