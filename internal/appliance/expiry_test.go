package appliance

import (
	"strings"
	"testing"
	"time"

	"github.com/dantecatalfamo/OPF/internal/pf"
)

func TestExpireTables(t *testing.T) {
	e := newEnv(t, time.Minute)
	m := e.live().Model
	for i := range m.Firewall.Aliases {
		if m.Firewall.Aliases[i].Name == "bruteforce" {
			n := 90
			m.Firewall.Aliases[i].ExpireMinutes = &n
		}
	}
	expires := func() []string {
		var out []string
		for _, c := range e.run.commands() {
			if strings.Contains(c, "-T expire") {
				out = append(out, c)
			}
		}
		return out
	}
	t0 := time.Now()
	e.m.expireTables(m, t0)
	if got := expires(); len(got) != 1 || got[0] != "pfctl -t bruteforce -T expire 5400" {
		t.Fatalf("expired %q", got)
	}
	// Not again within the minute, then again after it.
	e.m.expireTables(m, t0.Add(10*time.Second))
	if got := expires(); len(got) != 1 {
		t.Errorf("again within a minute: %q", got)
	}
	e.m.expireTables(m, t0.Add(expireEvery))
	if got := expires(); len(got) != 2 {
		t.Errorf("after a minute: %q", got)
	}
	// A table without the setting keeps its addresses.
	m.Firewall.Aliases = slicesWithout(m.Firewall.Aliases)
	e.m.expireTables(m, t0.Add(3*expireEvery))
	if got := expires(); len(got) != 2 {
		t.Errorf("a table that doesn't expire: %q", got)
	}
}

// slicesWithout is the aliases with no table's expiry set.
func slicesWithout(as []pf.Alias) []pf.Alias {
	out := make([]pf.Alias, len(as))
	copy(out, as)
	for i := range out {
		out[i].ExpireMinutes = nil
	}
	return out
}
