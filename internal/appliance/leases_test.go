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
	lease("192.168.1.102", "‮gpj.exe") // bidi override: reads as "exe.jpg"
	lease("192.168.1.103", "bell\x07") // control character
	lease("192.168.1.104", "caf\xe9")  // invalid UTF-8
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
	if len(n.Registered) != 1 || n.Registered[0] != (LeaseName{"laptop.office.arpa", "192.168.1.101"}) {
		t.Errorf("registered %+v", n.Registered)
	}
	byIP := map[string]string{}
	for _, r := range n.Refused {
		if !utf8.ValidString(r.Hostname) || strings.ContainsFunc(r.Hostname, func(c rune) bool { return !unicode.IsPrint(c) && c != utf8.RuneError }) {
			t.Errorf("hostname %q isn't safe to show", r.Hostname)
		}
		byIP[r.IP] = r.Hostname
	}
	for ip, want := range map[string]string{
		"192.168.1.102": "�gpj.exe",
		"192.168.1.103": "bell�",
		"192.168.1.104": "caf�",
		"192.168.1.105": strings.Repeat("x", MaxHostnameRunes) + "…",
	} {
		if byIP[ip] != want {
			t.Errorf("%s: hostname %q, want %q", ip, byIP[ip], want)
		}
	}
	if len(n.Refused) != MaxLeaseNames || !n.Truncated {
		t.Errorf("%d refused, truncated %v; want %d and true", len(n.Refused), n.Truncated, MaxLeaseNames)
	}
}
