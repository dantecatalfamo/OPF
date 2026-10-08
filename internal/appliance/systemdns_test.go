package appliance

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/dantecatalfamo/OPF/internal/pf"
)

// fakeResolvd is resolvd as seen on 7.9: lo0's proposal first, the
// lease's after; a restart forgets lo0's.
type fakeResolvd struct {
	mu    sync.Mutex
	lease []string
	lo0   []string
	sent  []string
}

func (r *fakeResolvd) Run(_ context.Context, argv ...string) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch {
	case slices.Equal(argv, []string{"cat", "/etc/resolv.conf"}):
		var b strings.Builder
		for _, s := range r.lo0 {
			fmt.Fprintf(&b, "nameserver %s # resolvd: lo0\n", s)
		}
		for _, s := range r.lease {
			fmt.Fprintf(&b, "nameserver %s # resolvd: vio0\n", s)
		}
		b.WriteString("lookup file bind\n")
		return []byte(b.String()), nil
	case len(argv) >= 3 && argv[0] == "route" && argv[1] == "nameserver":
		r.sent = append(r.sent, strings.Join(argv, " "))
		if argv[2] == "lo0" {
			r.lo0 = slices.Clone(argv[3:])
		}
		return nil, nil
	}
	return nil, fmt.Errorf("unexpected %v", argv)
}

func (r *fakeResolvd) restart() { r.mu.Lock(); r.lo0 = nil; r.mu.Unlock() }

func TestSystemDNS(t *testing.T) {
	r := &fakeResolvd{lease: []string{"100.64.1.2"}}
	m := &Manager{Runner: r}
	model := sample(t)

	// The WAN's: nothing to send.
	m.applySystemDNS(model)
	if len(r.sent) != 0 {
		t.Errorf("sent for the WAN's: %v", r.sent)
	}
	// Its own resolver, a fallback, then the WAN's lease after them.
	model.System.DNS = &pf.SystemDNS{Mode: pf.SystemDNSSelf, Servers: []string{"9.9.9.9"}}
	m.applySystemDNS(model)
	if want := []string{"route nameserver lo0 127.0.0.1 9.9.9.9"}; !slices.Equal(r.sent, want) {
		t.Errorf("sent %v, want %v", r.sent, want)
	}
	// In place: nothing again; resolvd restarted: put back.
	m.applySystemDNS(model)
	r.restart()
	m.applySystemDNS(model)
	if len(r.sent) != 2 {
		t.Errorf("after a restart: %v", r.sent)
	}
	// Back to the WAN's: withdrawn, never the lease's.
	model.System.DNS = &pf.SystemDNS{Mode: pf.SystemDNSWAN}
	m.applySystemDNS(model)
	if r.sent[len(r.sent)-1] != "route nameserver lo0" || len(r.lo0) != 0 || !slices.Equal(r.lease, []string{"100.64.1.2"}) {
		t.Errorf("withdrawn: %v, lo0 %v", r.sent, r.lo0)
	}
	for _, s := range r.sent {
		if strings.Contains(s, "vio0") {
			t.Errorf("a proposal on the WAN's interface, which replaces its lease's: %s", s)
		}
	}
}

func TestSystemDNSValidation(t *testing.T) {
	for name, tc := range map[string]struct {
		d     pf.SystemDNS
		dnsOn bool
		ok    bool
	}{
		"the WAN's":                 {pf.SystemDNS{Mode: pf.SystemDNSWAN}, true, true},
		"servers given for the WAN": {pf.SystemDNS{Mode: pf.SystemDNSWAN, Servers: []string{"9.9.9.9"}}, true, false},
		"its own resolver":          {pf.SystemDNS{Mode: pf.SystemDNSSelf, Servers: []string{"9.9.9.9", "2620:fe::fe"}}, true, true},
		"its own, resolver off":     {pf.SystemDNS{Mode: pf.SystemDNSSelf}, false, false},
		"its own and three more":    {pf.SystemDNS{Mode: pf.SystemDNSSelf, Servers: []string{"9.9.9.9", "1.1.1.1", "8.8.8.8"}}, true, false},
		"servers":                   {pf.SystemDNS{Mode: pf.SystemDNSServers, Servers: []string{"9.9.9.9", "1.1.1.1", "8.8.8.8"}}, false, true},
		"no servers":                {pf.SystemDNS{Mode: pf.SystemDNSServers}, true, false},
		"four servers":              {pf.SystemDNS{Mode: pf.SystemDNSServers, Servers: []string{"9.9.9.9", "1.1.1.1", "8.8.8.8", "8.8.4.4"}}, true, false},
		"not an address":            {pf.SystemDNS{Mode: pf.SystemDNSServers, Servers: []string{"dns.quad9.net"}}, true, false},
		"loopback":                  {pf.SystemDNS{Mode: pf.SystemDNSServers, Servers: []string{"127.0.0.1"}}, true, false},
		"twice":                     {pf.SystemDNS{Mode: pf.SystemDNSServers, Servers: []string{"9.9.9.9", "9.9.9.9"}}, true, false},
		"no mode":                   {pf.SystemDNS{Mode: "magic"}, true, false},
	} {
		m := sample(t)
		m.DNS.Enabled = tc.dnsOn
		d := tc.d
		m.System.DNS = &d
		bad := false
		for _, e := range pf.Validate(m) {
			bad = bad || strings.HasPrefix(e.Path, "system.dns")
		}
		if bad == tc.ok {
			t.Errorf("%s: valid %v, want %v (%v)", name, !bad, tc.ok, pf.Validate(m))
		}
	}
}
