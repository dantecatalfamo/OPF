package conformance

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dantecatalfamo/OPF/internal/appliance"
)

// TestGatewayGroups: the everything model's group "both" sends through
// a table, which OPF fills from its gateways' health. The edge gateway
// (tier 1) never answers, so after two looks the client (tier 2), which
// does, is in use: in pf's table, OPF's status and the event log.
func TestGatewayGroups(t *testing.T) {
	a := configured(t)
	if rules, _ := run("pfctl", "-sr"); !strings.Contains(rules, "route-to <opf_gw_both> round-robin sticky-address") {
		t.Errorf("no rule sends through the group's table:\n%s", rules)
	}
	var st appliance.GatewaysStatus
	table := ""
	for i := 0; i < 24 && table != clientAddr; i++ { // two minutes
		time.Sleep(5 * time.Second)
		out, _ := run("pfctl", "-t", "opf_gw_both", "-T", "show")
		table = strings.TrimSpace(out)
	}
	a.get(t, "/api/network/gateways", &st)
	if table != clientAddr {
		logs, _ := run("sh", "-c", "grep -h -i 'gateway' /var/log/daemon /var/log/messages | tail -n 20")
		t.Fatalf("after two minutes the group's table holds %q, not the client %s; OPF's status: %+v; its log:\n%s", table, clientAddr, st, logs)
	}
	if g := st.Groups["both"]; g.Tier != 2 || !slices.Equal(g.InUse, []string{"gw_client"}) {
		t.Errorf("the group's status: %+v", g)
	}
	if h := st.Gateways["gw_edge"]; h.Online {
		t.Errorf("the edge gateway answers: %+v", h)
	}
	var events struct {
		Events []appliance.Event `json:"events"`
	}
	a.get(t, "/api/events", &events)
	if !slices.ContainsFunc(events.Events, func(e appliance.Event) bool {
		return strings.HasPrefix(e.Message, "Gateway group Both WANs: now sending through Client (tier 2)")
	}) {
		t.Errorf("no event for the group's move: %+v", events.Events)
	}
	// A commit keeps what's in the table (it's persist), and OPF puts it
	// in again anyway.
	if out, _ := run("pfctl", "-f", "/etc/pf.conf"); out != "" {
		t.Errorf("reloading pf.conf: %s", out)
	}
	if out, _ := run("pfctl", "-t", "opf_gw_both", "-T", "show"); strings.TrimSpace(out) != clientAddr {
		t.Errorf("after a reload, the table holds %q", out)
	}
}
