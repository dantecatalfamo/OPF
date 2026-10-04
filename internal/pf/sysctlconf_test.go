package pf

import (
	"strings"
	"testing"
)

func TestMergeSysctlConf(t *testing.T) {
	m, _ := loadSampleModel(t)
	existing := "# tuning\nkern.maxfiles=20000\nnet.inet.ip.forwarding=0\t# off for now\n#net.inet.ip.forwarding=1\n\n"
	got := MergeSysctlConf(existing, m)
	want := "# tuning\nkern.maxfiles=20000\n#net.inet.ip.forwarding=1\n\n" + sysctlMarker + "\nnet.inet.ip.forwarding=1\n"
	if got != want {
		t.Errorf("merged:\n%s\nwant:\n%s", got, want)
	}
	if again := MergeSysctlConf(got, m); again != got {
		t.Errorf("not idempotent:\n%s", again)
	}
	if v := SysctlValues(existing); v["net.inet.ip.forwarding"] != "0" {
		t.Errorf("values %v", v)
	}
	if v := SysctlValues("kern.maxfiles=1\n"); v["net.inet.ip.forwarding"] != "" {
		t.Errorf("unset: %v", v)
	}
	// One interface: nothing to forward between.
	m.Interfaces = m.Interfaces[:1]
	if got := GenerateSysctlConf(m); !strings.HasSuffix(got, "\nnet.inet.ip.forwarding=0\n") {
		t.Errorf("one interface:\n%s", got)
	}
}
