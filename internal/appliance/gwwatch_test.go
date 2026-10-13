package appliance

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/dantecatalfamo/OPF/internal/pf"
)

// pfctlRecorder keeps the commands the gateway watch runs.
type pfctlRecorder struct{ ran []string }

func (p *pfctlRecorder) Run(_ context.Context, argv ...string) ([]byte, error) {
	p.ran = append(p.ran, strings.Join(argv, " "))
	return nil, nil
}

// A group's table follows its gateways' health: the second tier only
// after the first misses two looks, and back after three answers; a
// configuration not seen yet puts it in again.
func TestGatewayWatch(t *testing.T) {
	e := newEnv(t, time.Minute)
	rec := &pfctlRecorder{}
	e.m.Actions = rec
	m := pf.EmptyModel()
	m.Interfaces = []pf.Iface{
		{ID: "wan", Name: "WAN", Device: "em0", Role: pf.RoleWAN, Enabled: true, IPv4: pf.IPv4Config{Mode: pf.IPv4Static, Address: "203.0.113.2", Prefix: ptrTo(24)}},
		{ID: "wan2", Name: "WAN2", Device: "em1", Role: pf.RoleWAN, Enabled: true, IPv4: pf.IPv4Config{Mode: pf.IPv4Static, Address: "198.51.100.2", Prefix: ptrTo(24)}},
	}
	m.Routing.Gateways = []pf.Gateway{
		{ID: "a", Name: "Fibre", Iface: "wan", Address: "203.0.113.1"},
		{ID: "b", Name: "Cable", Iface: "wan2", Address: "198.51.100.1"},
	}
	m.Routing.Groups = []pf.GatewayGroup{{ID: "both", Name: "Both", Members: []pf.GroupMember{{Gateway: "a", Tier: 1}, {Gateway: "b", Tier: 2}}}}
	m.Firewall.Rules = []pf.Rule{{ID: "r", Kind: "form", Enabled: true, Family: pf.FamilyInet, Gateway: "both"}}
	look := func(aUp, bUp bool) []string {
		rec.ran = nil
		e.m.watchGateways(m, "v1", &GatewaysStatus{Gateways: map[string]GatewayHealth{
			"a": {Address: "203.0.113.1", Online: aUp}, "b": {Address: "198.51.100.1", Online: bUp},
		}}, time.Now())
		return rec.ran
	}
	want := func(step string, got []string, addrs string) {
		t.Helper()
		if addrs == "" && len(got) != 0 || addrs != "" && (len(got) != 1 || got[0] != "pfctl -t opf_gw_both -T replace "+addrs) {
			t.Errorf("%s: ran %q, want %q", step, got, addrs)
		}
	}
	want("first look", look(true, true), "203.0.113.1")
	want("unchanged", look(true, true), "")
	want("one miss", look(false, true), "")
	want("two misses", look(false, true), "198.51.100.1")
	if st := e.m.groupStatuses(m)["both"]; st.Tier != 2 || st.InUse[0] != "b" {
		t.Errorf("status %+v", st)
	}
	want("back once", look(true, true), "")
	want("back twice", look(true, true), "")
	want("back three times", look(true, true), "203.0.113.1")
	// A commit: put in again, though nothing changed.
	rec.ran = nil
	e.m.watchGateways(m, "v2", nil, time.Now())
	want("new configuration", rec.ran, "203.0.113.1")
	// Both down: the first tier, the best guess.
	look(false, false)
	want("both down", look(false, false), "")
	var moved int
	for _, ev := range e.m.eventLog().events {
		if ev.Kind == EventGateway && strings.HasPrefix(ev.Message, "Gateway group Both: now sending through") {
			moved++
		}
	}
	if moved != 2 {
		t.Errorf("%d group events", moved)
	}
}
