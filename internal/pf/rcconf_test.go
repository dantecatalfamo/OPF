package pf

import (
	"strings"
	"testing"
)

const existingRc = `# local additions
pkg_scripts="postgresql nginx"
dhcpd_flags=NO
ntpd_flags="-s"
  unbound_flags=""   # set by rcctl
postgresql_flags="-D /var/postgresql/data"

`

func TestMergeRcConfLocal(t *testing.T) {
	m, _ := loadSampleModel(t)
	got, err := MergeRcConfLocal(existingRc, m)
	if err != nil {
		t.Fatal(err)
	}
	want := `# local additions
pkg_scripts="postgresql nginx"
ntpd_flags="-s"
postgresql_flags="-D /var/postgresql/data"

` + rcMarker + `
dhcpd_flags="em1 vlan20"
unbound_flags=""
`
	if got != want {
		t.Errorf("merged:\n%s\nwant:\n%s", got, want)
	}
	// Merging again changes nothing.
	if again, _ := MergeRcConfLocal(got, m); again != got {
		t.Errorf("not idempotent:\n%s", again)
	}
	// Turning DHCP off only changes OPF's line.
	for i := range m.DHCP {
		m.DHCP[i].Enabled = false
	}
	off, _ := MergeRcConfLocal(got, m)
	if !strings.Contains(off, "\ndhcpd_flags=\"NO\"\n") || !strings.Contains(off, `pkg_scripts="postgresql nginx"`) {
		t.Errorf("off:\n%s", off)
	}
	// Commented-out assignments are someone's note, not OPF's.
	if got, _ := MergeRcConfLocal("#dhcpd_flags=em9\n", m); !strings.HasPrefix(got, "#dhcpd_flags=em9\n") {
		t.Errorf("comment dropped:\n%s", got)
	}
	// A system with none gets only OPF's block.
	if got := GenerateRcConfLocal(m); !strings.HasPrefix(got, rcMarker+"\n") {
		t.Errorf("empty:\n%s", got)
	}
}

func TestMergeRcConfLocalRefusesMultiLine(t *testing.T) {
	m, _ := loadSampleModel(t)
	for _, in := range []string{
		"dhcpd_flags=\"em1 \\\nem2\"\n",
		"dhcpd_flags=\"em1\nem2\"\n",
		"unbound_flags='-v\n'\n",
	} {
		if got, err := MergeRcConfLocal(in, m); err == nil {
			t.Errorf("%q merged into\n%s", in, got)
		}
	}
}

func TestRcValues(t *testing.T) {
	if got := RcValues(existingRc); got["dhcpd_flags"] != "NO" || got["unbound_flags"] != "" {
		t.Errorf("values %v", got)
	}
	if got := RcValues(""); got["dhcpd_flags"] != "NO" || got["unbound_flags"] != "NO" {
		t.Errorf("defaults %v", got)
	}
	if got := RcValues("dhcpd_flags=em1\ndhcpd_flags=\"em1 em2\"\n"); got["dhcpd_flags"] != "em1 em2" {
		t.Errorf("last assignment should win: %v", got)
	}
}
