package appliance

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/dantecatalfamo/OPF/internal/leases"
	"github.com/dantecatalfamo/OPF/internal/pf"
)

func TestLeaseNames(t *testing.T) {
	m := &Manager{}
	if n, err := m.LeaseNames(); err != nil || n.Enabled || n.Registered == nil || n.Refused == nil {
		t.Fatalf("without a watcher: %+v, %v", n, err) // lists are [] in JSON, not null
	}

	model := sample(t)
	now := time.Now()
	var b strings.Builder
	lease := func(ip, name string) {
		fmt.Fprintf(&b, "lease %s {\n\tends %d %s UTC;\n\tclient-hostname \"%s\";\n}\n", ip,
			now.Add(time.Hour).UTC().Weekday(), now.Add(time.Hour).UTC().Format("2006/01/02 15:04:05"), name)
	}
	lease("192.168.1.101", "laptop")
	lease("192.168.1.102", "\u202egpj.exe") // bidi override: reads as "exe.jpg"
	lease("192.168.1.103", "bell\x07")      // control character
	lease("192.168.1.104", "caf\xe9")       // invalid UTF-8
	lease("192.168.1.105", strings.Repeat("x", 500))
	// More refused leases than are reported, each on its own address
	// (only the last lease for an address counts), sorting after the
	// ones above: the lists are in address order and cut at the end.
	for i := range MaxLeaseNames + 10 {
		lease(fmt.Sprintf("198.51.%d.%d", i/250, i%250+1), fmt.Sprintf("bad name %d", i))
	}
	file := filepath.Join(t.TempDir(), "dhcpd.leases")
	if err := os.WriteFile(file, []byte(b.String()), 0644); err != nil {
		t.Fatal(err)
	}
	w := &leases.Watcher{File: file, Model: func() (*pf.Model, error) { return model, nil }, Resolver: &leases.Memory{}}
	if err := w.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	m.SetLeaseWatcher(w)
	n, err := m.LeaseNames()
	if err != nil || !n.Enabled || n.Checked == nil || n.Error != "" {
		t.Fatalf("%+v, %v", n, err)
	}
	// With sanitization, invalid hostnames are now cleaned up and registered.
	// The bidi override, control char, and invalid UTF-8 get stripped, leaving valid labels.
	regByIP := map[string]string{}
	for _, r := range n.Registered {
		regByIP[r.IP] = r.Name
	}
	for ip, want := range map[string]string{
		"192.168.1.101": "laptop.office.arpa",
		"192.168.1.102": "gpjexe.office.arpa",                                           // bidi char stripped
		"192.168.1.103": "bell.office.arpa",                                             // control char stripped
		"192.168.1.104": "caf.office.arpa",                                              // invalid UTF-8 stripped
		"192.168.1.105": strings.Repeat("x", 63) + ".office.arpa",                       // truncated to 63
	} {
		if regByIP[ip] != want {
			t.Errorf("%s: registered %q, want %q", ip, regByIP[ip], want)
		}
	}
	if len(n.Registered) != 5 {
		t.Errorf("registered %d names, want 5: %+v", len(n.Registered), n.Registered)
	}

	// The bad names (with spaces) in other ranges are still refused.
	byIP := map[string]string{}
	for _, r := range n.Refused {
		if !utf8.ValidString(r.Hostname) || strings.ContainsFunc(r.Hostname, func(c rune) bool { return !unicode.IsPrint(c) && c != utf8.RuneError }) {
			t.Errorf("hostname %q isn't safe to show", r.Hostname)
		}
		byIP[r.IP] = r.Hostname
	}
	if len(n.Refused) != MaxLeaseNames || !n.Truncated {
		t.Errorf("%d refused, truncated %v; want %d and true", len(n.Refused), n.Truncated, MaxLeaseNames)
	}
}

func TestDHCPLeases(t *testing.T) {
	m := &Manager{}
	if l, err := m.DHCPLeases(); err != nil || l.Leases == nil || len(l.Leases) != 0 {
		t.Fatalf("without a watcher: %+v, %v", l, err)
	}

	e := newEnv(t, time.Minute) // a Manager with the sample model live
	now := time.Now().UTC()
	stamp := func(t time.Time) string {
		return fmt.Sprintf("%d %s UTC", t.Weekday(), t.Format("2006/01/02 15:04:05"))
	}
	file := filepath.Join(t.TempDir(), "dhcpd.leases")
	write := func(s string) {
		if err := os.WriteFile(file, []byte(s), 0644); err != nil {
			t.Fatal(err)
		}
	}
	w := &leases.Watcher{File: file, Model: func() (*pf.Model, error) { c, err := e.m.Live(); return c.Model, err }, Resolver: &leases.Memory{}}
	e.m.SetLeaseWatcher(w)

	// No file yet: no leases, no error.
	if l, err := e.m.DHCPLeases(); err != nil || len(l.Leases) != 0 || l.Error != "" {
		t.Fatalf("no file: %+v, %v", l, err)
	}

	ends := stamp(now.Add(time.Hour))
	write(fmt.Sprintf(`lease 192.168.20.117 { starts %[1]s; ends %[2]s; hardware ethernet D8:F1:5B:8E:22:90; client-hostname "tv-lobby"; }
lease 192.168.1.112 { starts %[1]s; ends %[2]s; hardware ethernet 3c:22:fb:91:04:7d; client-hostname "Priya's iPad"; }
lease 192.168.1.113 { starts %[1]s; ends never; hardware ethernet 3c:22:fb:91:04:7e; }
lease 192.168.1.114 { starts %[1]s; ends %[3]s; client-hostname "gone"; }
lease 10.99.0.1 { ends %[2]s; client-hostname "%[4]s"; }
`, stamp(now.Add(-time.Hour)), ends, stamp(now.Add(-time.Minute)), "elsewhere\u202e"))
	if err := w.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	l, err := e.m.DHCPLeases()
	if err != nil || l.Error != "" {
		t.Fatalf("%+v, %v", l, err)
	}
	got := map[string]DHCPLease{}
	var order []string
	for _, d := range l.Leases {
		got[d.IP] = d
		order = append(order, d.IP)
	}
	if strings.Join(order, " ") != "10.99.0.1 192.168.1.112 192.168.1.113 192.168.20.117" {
		t.Errorf("leases %v: want current ones, by address", order) // .114 has ended
	}
	if d := got["192.168.20.117"]; d.Iface != "iot" || d.MAC != "d8:f1:5b:8e:22:90" || d.DNSName != "tv-lobby.office.arpa" || d.Ends == nil || d.Starts == nil {
		t.Errorf("tv-lobby: %+v", d)
	}
	// "Priya's iPad" gets sanitized to "priyas-ipad" and registered.
	if d := got["192.168.1.112"]; d.Iface != "lan" || d.Hostname != "Priya's iPad" || d.DNSName != "priyas-ipad.office.arpa" || d.DNSRefused != "" {
		t.Errorf("Priya's iPad: %+v", d)
	}
	if d := got["192.168.1.113"]; d.Ends != nil || d.Hostname != "" || d.DNSName != "" || d.DNSRefused != "" {
		t.Errorf("unnamed, never-ending lease: %+v", d)
	}
	if d := got["10.99.0.1"]; d.Iface != "" || d.Hostname != "elsewhere\ufffd" {
		t.Errorf("lease outside any range: %+v", d)
	}

	// A damaged file is reported without its details.
	write(`lease 192.168.1.112 { client-hostname "unterminated`)
	if l, err := e.m.DHCPLeases(); err != nil || l.Error != "dhcpd’s leases file couldn’t be read" || len(l.Leases) != 0 {
		t.Errorf("damaged file: %+v, %v", l, err)
	}
}
