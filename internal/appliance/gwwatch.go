package appliance

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/dantecatalfamo/OPF/internal/pf"
)

// The gateway watch: after each look at the gateways (the collector's,
// every CollectInterval), which of each group's gateways are in use,
// and the addresses pf sends to through each group's or DHCP gateway's
// table (pf.GatewayTables), put in with pfctl when they change. pf.conf
// declares the tables empty and persist, so a reload keeps them; after
// a commit, which may add a table, they're all put in again.

// A gateway is down after gwDownAfter looks in a row get no answer, and
// up again after gwUpAfter answer: one lost look doesn't move a group,
// and a gateway that's back stays a while before traffic returns to it.
const (
	gwDownAfter = 2
	gwUpAfter   = 3
)

type gwWatch struct {
	mu sync.Mutex
	// up, and how many looks in a row disagreed with it, by gateway.
	up     map[string]bool
	streak map[string]int
	// applied is what each table was last given; inUse each group's
	// gateways in use, for the status and the event log.
	applied map[string][]string
	inUse   map[string][]string
	version string // the live configuration the tables were put in for
}

func (m *Manager) gwWatcher() *gwWatch {
	m.gwOnce.Do(func() {
		m.gw = &gwWatch{up: map[string]bool{}, streak: map[string]int{}, applied: map[string][]string{}, inUse: map[string][]string{}}
	})
	return m.gw
}

// GroupStatus is a gateway group's gateways in use.
type GroupStatus struct {
	// InUse are the gateways pf sends the group's traffic to, by id.
	InUse []string `json:"inUse"`
	// Tier is their tier; 0 before the first look.
	Tier int `json:"tier"`
}

// watchGateways takes a look at the gateways (gws) into account: their
// health, with hysteresis, then each table.
func (m *Manager) watchGateways(model *pf.Model, version string, gws *GatewaysStatus, now time.Time) {
	if model == nil || m.ReadOnly() {
		return
	}
	w := m.gwWatcher()
	w.mu.Lock()
	defer w.mu.Unlock()
	if gws != nil {
		for _, g := range model.Routing.Gateways {
			h, ok := gws.Gateways[g.ID]
			if !ok || h.Address == "" {
				continue // nothing to ask yet
			}
			was, seen := w.up[g.ID]
			switch {
			case !seen:
				w.up[g.ID], w.streak[g.ID] = h.Online, 0
			case h.Online == was:
				w.streak[g.ID] = 0
			default:
				w.streak[g.ID]++
				if need := map[bool]int{true: gwUpAfter, false: gwDownAfter}[h.Online]; w.streak[g.ID] >= need {
					w.up[g.ID], w.streak[g.ID] = h.Online, 0
				}
			}
		}
	}
	m.putGatewayTables(w, model, version, now)
}

// putGatewayTables puts each table's addresses in when they changed, or
// all of them for a configuration not seen yet. w is locked.
func (m *Manager) putGatewayTables(w *gwWatch, model *pf.Model, version string, now time.Time) {
	force := version != w.version
	w.version = version
	var routes []RouteEntry
	for _, g := range model.Routing.Gateways {
		if g.Address == "dhcp" {
			if t, err := m.RoutingTable(); err == nil {
				routes = append(t.IPv4, t.IPv6...)
			}
			break
		}
	}
	addrOf := func(id string) (netip.Addr, bool) {
		g := pf.FindGateway(model, id)
		if g == nil {
			return netip.Addr{}, false
		}
		a := gatewayHop(*g, model, routes)
		return a, a.IsValid()
	}
	// A gateway never looked at counts as up: the first look decides.
	up := func(id string) bool {
		u, seen := w.up[id]
		return u || !seen
	}
	for _, id := range pf.GatewayTables(model) {
		ids := []string{id}
		if g := pf.FindGroup(model, id); g != nil {
			if ids = pf.GroupInUse(*g, up); len(ids) == 0 {
				continue // validation: a group has a gateway
			}
			// A move, or a first choice that isn't the first tier.
			if before, ok := w.inUse[id]; ok && !slices.Equal(before, ids) || !ok && g.TierOf(ids[0]) > 1 {
				m.eventLog().record(Event{Time: now, Kind: EventGateway, Subject: id, Warning: g.TierOf(ids[0]) > 1,
					Message: fmt.Sprintf("Gateway group %s: now sending through %s (tier %d)", g.Name, pf.GatewayNames(model, ids), g.TierOf(ids[0]))})
			}
			w.inUse[id] = ids
		}
		var addrs []string
		for _, gid := range ids {
			if a, ok := addrOf(gid); ok && !slices.Contains(addrs, a.String()) {
				addrs = append(addrs, a.String())
			}
		}
		// No address yet (a lease to come): what's there stays.
		if len(addrs) == 0 || (!force && slices.Equal(addrs, w.applied[id])) {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), readTimeout)
		out, err := m.actions().Run(ctx, append([]string{"pfctl", "-t", pf.GatewayTable(id), "-T", "replace"}, addrs...)...)
		cancel()
		if err != nil {
			log.Printf("gateway table %s: %v: %s", pf.GatewayTable(id), err, firstLine(string(out)))
			delete(w.applied, id) // tried again at the next look
			continue
		}
		w.applied[id] = addrs
	}
}

// gatewayTablesNow puts the tables in for the configuration just
// applied, from what the last looks saw, rather than wait for the next.
func (m *Manager) gatewayTablesNow() {
	model, version, err := m.live()
	if err != nil || model == nil || m.ReadOnly() {
		return
	}
	w := m.gwWatcher()
	w.mu.Lock()
	defer w.mu.Unlock()
	m.putGatewayTables(w, model, version, time.Now())
}

// groupStatuses are the groups' gateways in use, for the status.
func (m *Manager) groupStatuses(model *pf.Model) map[string]GroupStatus {
	w := m.gwWatcher()
	w.mu.Lock()
	defer w.mu.Unlock()
	out := map[string]GroupStatus{}
	for _, g := range model.Routing.Groups {
		st := GroupStatus{InUse: []string{}}
		if ids, ok := w.inUse[g.ID]; ok && len(ids) > 0 {
			st.InUse, st.Tier = ids, g.TierOf(ids[0])
		}
		out[g.ID] = st
	}
	return out
}

// gatewayHop is the address traffic sent through a gateway goes to:
// its own, or for a DHCP gateway the default route the lease installed
// on its interface. (gatewayTarget is what's pinged, which may be a
// monitor address beyond it.)
func gatewayHop(g pf.Gateway, m *pf.Model, routes []RouteEntry) netip.Addr {
	g.Monitor = ""
	return gatewayTarget(g, m, routes)
}
