package pf

import (
	"strings"
	"testing"
)

func genFile(m *Model, path string) (string, bool) {
	for _, f := range GenerateFiles(m) {
		if f.Path == path {
			return f.Content, true
		}
	}
	return "", false
}

// A VLAN is carried on a physical port, an enabled one if OPF manages
// it; never a tunnel, another VLAN or itself.
func TestVLANParent(t *testing.T) {
	for name, tc := range map[string]struct {
		parent string
		edit   func(m *Model)
		ok     bool
	}{
		"a model port":            {"em1", nil, true},
		"a port OPF doesn't have": {"em2", nil, true},
		"a tunnel":                {"wg0", nil, false},
		"another VLAN":            {"vlan30", nil, false},
		"itself":                  {"vlan20", nil, false},
		"a port turned off":       {"em1", func(m *Model) { m.Interfaces[1].Enabled = false }, false},
	} {
		m, _ := loadSampleModel(t)
		m.Interfaces[2].VLAN.Parent = tc.parent // IoT, vlan20
		if tc.edit != nil {
			tc.edit(m)
		}
		bad := false
		for _, e := range Validate(m) {
			bad = bad || e.Path == "interfaces[2].vlan.parent"
		}
		if bad == tc.ok {
			t.Errorf("%s: %v", name, Validate(m))
		}
	}
}

// A port that only carries VLANs is brought up, and says so; one an
// interface already is, or one only disabled VLANs use, isn't.
func TestBareParents(t *testing.T) {
	m, _ := loadSampleModel(t)
	if _, ok := genFile(m, "/etc/hostname.em2"); ok {
		t.Fatal("em2 written with nothing on it")
	}
	m.Interfaces[2].VLAN.Parent = "em2"
	extra := m.Interfaces[2]
	extra.ID, extra.Name, extra.Device, extra.VLAN = "guest", "Guest", "vlan31", &VLANConfig{Parent: "em2", Tag: 31}
	extra.IPv4 = IPv4Config{Mode: IPv4Static, Address: "192.168.31.1", Prefix: extra.IPv4.Prefix}
	m.Interfaces = append(m.Interfaces, extra)
	if errs := Validate(m); len(errs) > 0 {
		t.Fatal(errs)
	}
	got, ok := genFile(m, "/etc/hostname.em2")
	if !ok || !strings.Contains(got, "description \"Carries VLANs 20, 31\"\nup\n") || strings.Contains(got, "inet") {
		t.Errorf("hostname.em2:\n%s", got)
	}
	m.Interfaces[2].Enabled, m.Interfaces[len(m.Interfaces)-1].Enabled = false, false
	if _, ok := genFile(m, "/etc/hostname.em2"); ok {
		t.Error("em2 still written with only disabled VLANs on it")
	}
}

// A WAN can be a VLAN, for providers that tag theirs: its port is
// brought up bare, and pf names the VLAN.
func TestWANAsVLAN(t *testing.T) {
	m, _ := loadSampleModel(t)
	m.Interfaces[0].Device, m.Interfaces[0].VLAN = "vlan35", &VLANConfig{Parent: "em0", Tag: 35}
	if errs := Validate(m); len(errs) > 0 {
		t.Fatal(errs)
	}
	if got, _ := genFile(m, "/etc/hostname.vlan35"); !strings.Contains(got, "vnetid 35 parent em0") || !strings.Contains(got, "inet autoconf") {
		t.Errorf("hostname.vlan35:\n%s", got)
	}
	if got, ok := genFile(m, "/etc/hostname.em0"); !ok || !strings.Contains(got, "Carries VLAN 35") {
		t.Errorf("hostname.em0:\n%s", got)
	}
	if conf := GeneratePfConf(m); !strings.Contains(conf, "wan = \"vlan35\"") {
		t.Error("pf doesn't name the WAN's VLAN")
	}
}
