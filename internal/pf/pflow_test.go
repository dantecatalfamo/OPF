package pf

import (
	"strings"
	"testing"
)

func TestGenerateHostnamePflow(t *testing.T) {
	for _, tt := range []struct {
		name string
		e    FlowExport
		want string
	}{
		{"IPFIX from a fixed address", FlowExport{Name: "Lab collector", Enabled: true, Device: "pflow0", Collector: "192.168.1.5", Port: 4739, Source: "lan", Version: FlowIPFIX},
			"description \"Lab collector\"\nflowsrc 192.168.1.1 flowdst 192.168.1.5:4739 pflowproto 10\nup\n"},
		// -flowsrc takes away a source an earlier file set.
		{"NetFlow v5 to IPv6, turned off", FlowExport{Name: "Old", Device: "pflow1", Collector: "2001:db8::5", Port: 2055, Version: FlowNetFlow5},
			"description \"Old\"\n-flowsrc flowdst [2001:db8::5]:2055 pflowproto 5\ndown\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			m, _ := loadSampleModel(t)
			if got := GenerateHostnamePflow(&tt.e, m); got != header+"\n"+tt.want {
				t.Errorf("got\n%s\nwant\n%s", got, tt.want)
			}
		})
	}
}

func TestGenerateFilesPflow(t *testing.T) {
	m, _ := loadSampleModel(t)
	for _, f := range GenerateFiles(m) {
		if f.Path == "/etc/hostname.pflow0" {
			return
		}
	}
	t.Error("no /etc/hostname.pflow0 for the sample model's flow export")
}

func TestValidateFlowExports(t *testing.T) {
	for _, tt := range []struct {
		name   string
		path   string
		break_ func(e *FlowExport, m *Model)
	}{
		{"name with a quote (description)", "name", func(e *FlowExport, _ *Model) { e.Name = `x" up` }},
		{"device that isn't pflow", "device", func(e *FlowExport, _ *Model) { e.Device = "em1" }},
		{"device an interface has", "device", func(e *FlowExport, m *Model) { m.Interfaces[1].Device = "pflow0" }},
		{"device twice", "device", func(e *FlowExport, m *Model) {
			m.Firewall.FlowExports = append(m.Firewall.FlowExports, FlowExport{ID: "b", Name: "B", Device: "pflow0", Collector: "192.0.2.1", Port: 1, Version: 10})
		}},
		{"collector with a port in it", "collector", func(e *FlowExport, _ *Model) { e.Collector = "192.168.1.5:2055" }},
		{"collector with extra words", "collector", func(e *FlowExport, _ *Model) { e.Collector = "192.168.1.5 up" }},
		{"collector with a zone", "collector", func(e *FlowExport, _ *Model) { e.Collector = "fe80::1%em1" }},
		{"collector unspecified", "collector", func(e *FlowExport, _ *Model) { e.Collector = "0.0.0.0" }},
		{"port zero", "port", func(e *FlowExport, _ *Model) { e.Port = 0 }},
		{"port too big", "port", func(e *FlowExport, _ *Model) { e.Port = 65536 }},
		{"version pflow doesn't have", "version", func(e *FlowExport, _ *Model) { e.Version = 9 }},
		{"source that isn't an interface", "source", func(e *FlowExport, _ *Model) { e.Source = "nope" }},
		{"source without a fixed address", "source", func(e *FlowExport, _ *Model) { e.Source = "wan" }},
		{"source on a turned off interface", "source", func(e *FlowExport, m *Model) { m.Interfaces[1].Enabled = false }},
		{"source with an IPv6 collector", "source", func(e *FlowExport, _ *Model) { e.Collector = "2001:db8::5" }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			m, _ := loadSampleModel(t)
			tt.break_(&m.Firewall.FlowExports[0], m)
			want := "firewall.flowExports[0]." + tt.path
			if tt.name == "device twice" {
				want = "firewall.flowExports[1].device"
			}
			errs := Validate(m)
			for _, e := range errs {
				if e.Path == want {
					return
				}
			}
			t.Errorf("no error at %s; got %v", want, errs)
		})
	}
	m, _ := loadSampleModel(t)
	m.Firewall.FlowExports[0].Source = ""
	m.Firewall.FlowExports[0].Collector = "2001:db8::5"
	if errs := Validate(m); len(errs) > 0 {
		t.Errorf("an IPv6 collector without a source: %v", errs)
	}
}

func TestImportFlowExports(t *testing.T) {
	lan := "inet 192.168.1.1/24\nup\n"
	src := ImportSources{Files: map[string]string{
		"/etc/hostname.em1": lan,
		// As OPF writes it: the same export back.
		"/etc/hostname.pflow0": header + "\n" + `description "Lab collector"` + "\nflowsrc 192.168.1.1 flowdst 192.168.1.5:4739 pflowproto 10\nup\n",
		// The way pflow(4) has it, over two lines; pflow's own default
		// is NetFlow v5.
		"/etc/hostname.pflow1": "flowdst [2001:db8::5]:2055\ndown # for now\n",
		"/etc/hostname.pflow2": "flowsrc 192.168.1.1\n",                                       // no collector
		"/etc/hostname.pflow3": "flowsrc 10.0.0.1 flowdst 10.0.0.2:2055\n",                    // not the firewall's address
		"/etc/hostname.pflow4": "flowdst 10.0.0.2:2055 mtu 9000\n",                            // a setting OPF doesn't have
		"/etc/hostname.pflow5": "description \"a, b\"\nflowdst 10.0.0.2:2055 pflowproto 10\n", // a name OPF can't write
	}}
	res := Import(src, ImportOptions{})
	got := res.Model.Firewall.FlowExports
	want := []FlowExport{
		{ID: "pflow0", Name: "Lab collector", Enabled: true, Device: "pflow0", Collector: "192.168.1.5", Port: 4739, Source: "em1", Version: 10},
		{ID: "pflow1", Name: "pflow1", Device: "pflow1", Collector: "2001:db8::5", Port: 2055, Version: 5},
		{ID: "pflow5", Name: "pflow5", Enabled: true, Device: "pflow5", Collector: "10.0.0.2", Port: 2055, Version: 10},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("export %d: got %+v, want %+v", i, got[i], want[i])
		}
	}
	notes := map[string]string{}
	for _, n := range res.Notes {
		if strings.Contains(n.File, "pflow") {
			notes[n.File] += n.Kind + " "
		}
	}
	for f, kinds := range map[string]string{
		"/etc/hostname.pflow0": "model ", "/etc/hostname.pflow1": "model ", "/etc/hostname.pflow2": "left ",
		"/etc/hostname.pflow3": "left ", "/etc/hostname.pflow4": "left ", "/etc/hostname.pflow5": "lost model ",
	} {
		if notes[f] != kinds {
			t.Errorf("%s: notes %q, want %q", f, notes[f], kinds)
		}
	}
	if errs := Validate(res.Model); len(errs) > 0 {
		t.Errorf("imported model has problems: %v", errs)
	}
	// What OPF writes for them reads back the same.
	for _, e := range got {
		again, ok := parseHostnamePflow(GenerateHostnamePflow(&e, res.Model))
		again.ID, again.Device, again.Name = e.ID, e.Device, e.Name
		if again.Source != "" {
			again.Source = "em1" // its address, 192.168.1.1
		}
		if !ok || again != e {
			t.Errorf("%s doesn't read back: %+v", e.Device, again)
		}
	}
}
