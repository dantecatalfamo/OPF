package appliance

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

// getentRunner answers getent hosts as OpenBSD's does: a line an
// address, exit 2 and nothing printed for no such name.
type getentRunner struct{ ran []string }

func (g *getentRunner) Run(ctx context.Context, argv ...string) ([]byte, error) {
	g.ran = append(g.ran, strings.Join(argv, " "))
	switch argv[len(argv)-1] {
	case "vpn.example.net":
		return []byte("192.0.2.81                              vpn.example.net\n2001:db8::81                            vpn.example.net\n192.0.2.81                              vpn.example.net\n"), nil
	case "slow.example.net":
		<-ctx.Done()
		return nil, errors.New("signal: killed")
	case "odd.example.net":
		return []byte("getent: something else\n"), errors.New("exit status 1")
	}
	return nil, errors.New("exit status 2")
}

func TestLookupHost(t *testing.T) {
	e := newEnv(t, time.Minute)
	g := &getentRunner{}
	e.m.Runner = g

	r, err := e.m.LookupHost(HostLookupRequest{Name: " VPN.example.net. "})
	if err != nil || !slices.Equal(r.Addresses, []string{"192.0.2.81", "2001:db8::81"}) || r.Error != "" {
		t.Fatalf("a name: %+v %v", r, err)
	}
	if g.ran[0] != "getent hosts vpn.example.net" {
		t.Errorf("ran %q", g.ran[0])
	}
	if r, err := e.m.LookupHost(HostLookupRequest{Name: "gone.example.net"}); err != nil || len(r.Addresses) != 0 || r.Error != "" {
		t.Errorf("no such name: %+v %v", r, err)
	}
	if r, err := e.m.LookupHost(HostLookupRequest{Name: "odd.example.net"}); err != nil || r.Error != "getent: something else" {
		t.Errorf("another failure: %+v %v", r, err)
	}
	for _, bad := range []string{"", "192.0.2.1", "2001:db8::1", "-x", "a b", "*.example.net", "a;b"} {
		if _, err := e.m.LookupHost(HostLookupRequest{Name: bad}); err == nil {
			t.Errorf("%q: looked up", bad)
		}
	}
	if len(g.ran) != 3 {
		t.Errorf("ran %v", g.ran)
	}
}

func TestLookupHostTimesOut(t *testing.T) {
	defer func(d time.Duration) { hostLookupTimeout = d }(hostLookupTimeout)
	hostLookupTimeout = 100 * time.Millisecond
	e := newEnv(t, time.Minute)
	e.m.Runner = &getentRunner{}
	r, err := e.m.LookupHost(HostLookupRequest{Name: "slow.example.net"})
	if err != nil || r.Error == "" || len(r.Addresses) != 0 || r.Seconds < hostLookupTimeout.Seconds()-0.5 {
		t.Errorf("%+v %v", r, err)
	}
}
