package appliance

import (
	"context"
	"log"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/dantecatalfamo/OPF/internal/pf"
	"github.com/dantecatalfamo/OPF/internal/sysinfo"
)

// The firewall's own DNS servers (pf.SystemDNS). resolvd writes
// resolv.conf from proposals: dhcpleased's for the WAN's lease, and
// any sent with route(8). OPF's go on lo0, which resolvd puts first
// with the WAN's after them, so they never replace what the lease
// brings (a proposal on the WAN's interface would, and withdrawing it
// would leave none until the lease renews; seen on 7.9). Nothing keeps
// a proposal sent by hand: resolvd forgets it when it restarts, and
// there's none after a boot, so OPF puts it back whenever resolv.conf
// doesn't have it, every collector tick and after every change.

// proposalIface is where OPF's proposal goes.
const proposalIface = "lo0"

// SystemDNSWants is what OPF proposes for a model: nothing for the WAN's
// servers (and its own withdrawn), else the servers to ask first.
func SystemDNSWants(m *pf.Model) []string {
	d := pf.SystemDNSOf(m)
	switch d.Mode {
	case pf.SystemDNSSelf:
		return append([]string{"127.0.0.1"}, d.Servers...)
	case pf.SystemDNSServers:
		return slices.Clone(d.Servers)
	}
	return nil
}

// proposed are the servers resolv.conf has from OPF's proposal.
func proposed(rc sysinfo.ResolvConf) []string {
	var out []string
	for _, s := range rc.Servers {
		if s.From == proposalIface {
			out = append(out, s.Address)
		}
	}
	return out
}

type systemDNSState struct {
	mu   sync.Mutex
	last []string // what was last sent, for the log
	sent bool
}

// applySystemDNS sends the model's proposal when resolv.conf doesn't
// have it.
func (m *Manager) applySystemDNS(model *pf.Model) {
	if model == nil {
		return
	}
	want := SystemDNSWants(model)
	out, err := m.read("cat", "/etc/resolv.conf")
	if err != nil {
		return // resolvd makes it; nothing to compare with yet
	}
	have := proposed(sysinfo.ParseResolvConf(out))
	if slices.Equal(have, want) {
		return
	}
	st := &m.systemDNS
	st.mu.Lock()
	defer st.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// No addresses withdraws OPF's proposal.
	if _, err := m.actions().Run(ctx, append([]string{"route", "nameserver", proposalIface}, want...)...); err != nil {
		log.Printf("setting the firewall's DNS servers: %v", err)
		return
	}
	if !st.sent || !slices.Equal(st.last, want) {
		if len(want) == 0 {
			log.Printf("the firewall's own lookups go to the WAN's DNS servers")
		} else {
			log.Printf("the firewall's own lookups go to %s first", strings.Join(want, ", "))
		}
	}
	st.sent, st.last = true, want
}
