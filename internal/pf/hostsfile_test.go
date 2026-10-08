package pf

import (
	"strings"
	"testing"
)

func TestMergeHosts(t *testing.T) {
	m, _ := loadSampleModel(t)
	name := m.System.Hostname + "." + m.System.Domain
	lines := HostsLines(m)
	if len(lines) < 2 || !strings.HasPrefix(lines[0], "192.168.1.1\t"+name+" "+m.System.Hostname+"\t") {
		t.Fatalf("lines %q", lines)
	}
	for _, l := range lines {
		// Not the WAN's address, nor a VPN provider's.
		if strings.HasPrefix(l, "203.0.113.") {
			t.Errorf("the WAN: %q", l)
		}
	}

	// The system's lines stay as they are, in order; OPF's old ones go,
	// wherever they were, and the model's are at the end.
	existing := "127.0.0.1\tlocalhost\n::1\t\tlocalhost\n10.0.0.9   oldgw.office.arpa oldgw   # set by OPF\n192.0.2.7 nas.example nas  # mine\n\n"
	got := MergeHosts(existing, m)
	want := "127.0.0.1\tlocalhost\n::1\t\tlocalhost\n192.0.2.7 nas.example nas  # mine\n" + strings.Join(lines, "\n") + "\n"
	if got != want {
		t.Errorf("merged\n%s\nwant\n%s", got, want)
	}
	// Merging again changes nothing.
	if again := MergeHosts(got, m); again != got {
		t.Errorf("not stable:\n%s", again)
	}
	// No file: OpenBSD's localhost lines and OPF's.
	if g := GenerateHosts(m); !strings.HasPrefix(g, hostsDefault) || !strings.Contains(g, name) {
		t.Errorf("from nothing:\n%s", g)
	}
	// No name, no lines of OPF's; the system's stay.
	m.System.Hostname = ""
	if g := MergeHosts(existing, m); strings.Contains(g, hostsMark) || !strings.Contains(g, "nas.example") {
		t.Errorf("without a name:\n%s", g)
	}
	// Only OPF's lines count as OPF's.
	if v := HostsValues(existing); len(v) != 1 || v[0] != "10.0.0.9 oldgw.office.arpa oldgw # set by OPF" {
		t.Errorf("values %q", v)
	}
}
