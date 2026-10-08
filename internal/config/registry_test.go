package config

import (
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
