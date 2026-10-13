package config

import (
	"slices"
	"strings"
	"testing"
)

func TestUnboundRestarts(t *testing.T) {
	conf := func(lines ...string) []byte {
		return []byte("server:\n\tinterface: 127.0.0.1\n" + strings.Join(lines, "") + "\tcontrol-interface: /var/run/unbound.sock\n")
	}
	lan, wg := "\tinterface: 192.168.50.1\n", "\tinterface: 10.8.0.1\n"
	for _, c := range []struct {
		name          string
		before, after []byte
		want          bool
	}{
		{"an address added", conf(lan), conf(lan, wg), true},
		{"an address taken away", conf(lan, wg), conf(lan), true},
		{"the same addresses in another order", conf(lan, wg), conf(wg, lan), false},
		{"another change", conf(lan), conf(lan, "\thide-version: yes\n"), false},
		{"its own log", conf(lan), conf(lan, unboundOwnLog), true},
	} {
		if got := unboundRestarts(c.before, c.after); got != c.want {
			t.Errorf("%s: restart = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestNetstartOrder applies hostname.if files in netstart's order: its
// first pass by name (vether and bridges with the ports), then the held
// back kinds one kind after another, whatever their names.
func TestNetstartOrder(t *testing.T) {
	names := []string{"wg0", "gif0", "tun1", "vlan10", "svlan2", "carp0", "trunk0", "aggr0", "pppoe0", "vether0", "bridge0", "veb0", "vport0", "tpmr0", "em1", "em0"}
	slices.SortFunc(names, func(a, b string) int {
		if d := netstartOrder("hostname."+a) - netstartOrder("hostname."+b); d != 0 {
			return d
		}
		return strings.Compare(a, b)
	})
	want := []string{"bridge0", "em0", "em1", "tpmr0", "veb0", "vether0", "vport0", "aggr0", "trunk0", "svlan2", "vlan10", "carp0", "pppoe0", "tun1", "gif0", "wg0"}
	if !slices.Equal(names, want) {
		t.Errorf("got %v\nwant %v", names, want)
	}
}
