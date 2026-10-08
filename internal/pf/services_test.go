package pf

import (
	"strings"
	"testing"
)

func ptrTo[T any](v T) *T { return &v }

func TestServiceSettings(t *testing.T) {
	m, _ := loadSampleModel(t)
	m.System.Services = []ServiceSetting{
		{Name: "ntpd", Enabled: true, Flags: ptrTo("-s"), Timeout: ptrTo(60)},
		{Name: "smtpd", Enabled: false},
		{Name: "accounting", Enabled: true},
	}
	if errs := Validate(m); len(errs) != 0 {
		t.Fatalf("invalid: %v", errs)
	}
	// The admin's lines are kept, but not theirs for what OPF now sets;
	// OPF's go at the end, marked, and are found again after rcctl has
	// sorted the file.
	admin := "pkg_scripts=opf\nntpd_flags=-v\nsndiod_flags=NO\n"
	got, err := MergeRcConfLocal(admin, m)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"pkg_scripts=opf\nsndiod_flags=NO\n", `accounting="YES" # set by OPF`, `ntpd_flags="-s" # set by OPF`, `ntpd_timeout="60" # set by OPF`, `smtpd_flags="NO" # set by OPF`} {
		if !strings.Contains(got, want) {
			t.Errorf("merged lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "ntpd_flags=-v") {
		t.Errorf("the admin's ntpd_flags kept:\n%s", got)
	}
	sorted := strings.Join(sortedLines(got), "\n") + "\n" // as rcctl leaves it
	// (The blank line the sort moves to the top is the admin's, kept.)
	if again, _ := MergeRcConfLocal(sorted, m); strings.TrimLeft(again, "\n") != got {
		t.Errorf("after rcctl's sort:\n%s\nwant\n%s", again, got)
	}
	// Taken out: OPF's lines for it go.
	m.System.Services = m.System.Services[1:]
	if again, _ := MergeRcConfLocal(got, m); strings.Contains(again, "ntpd_") {
		t.Errorf("ntpd's lines after its setting went:\n%s", again)
	}
	if v := RcServiceValues(got); len(v) != 4 {
		t.Errorf("values %v", v)
	}
}

func sortedLines(s string) []string {
	ls := strings.Split(strings.TrimSuffix(s, "\n"), "\n")
	for i := range ls {
		for j := i + 1; j < len(ls); j++ {
			if ls[j] < ls[i] {
				ls[i], ls[j] = ls[j], ls[i]
			}
		}
	}
	return ls
}

func TestValidateServiceSettings(t *testing.T) {
	for _, tc := range []struct {
		name string
		s    ServiceSetting
		path string
	}{
		{"not a base service", ServiceSetting{Name: "nginx", Enabled: true}, "system.services[0].name"},
		{"one OPF sets up", ServiceSetting{Name: "unbound", Enabled: false}, "system.services[0].name"},
		{"pf", ServiceSetting{Name: "pf", Enabled: false}, "system.services[0].name"},
		{"OPF itself", ServiceSetting{Name: "opf", Enabled: false}, "system.services[0].name"},
		{"a quote in flags", ServiceSetting{Name: "ntpd", Enabled: true, Flags: ptrTo(`-s" ; reboot "`)}, "system.services[0].flags"},
		{"a $ in flags", ServiceSetting{Name: "ntpd", Enabled: true, Flags: ptrTo("$(reboot)")}, "system.services[0].flags"},
		{"flags when off", ServiceSetting{Name: "ntpd", Enabled: false, Flags: ptrTo("-s")}, "system.services[0].flags"},
		{"flags on a boot setting", ServiceSetting{Name: "accounting", Enabled: true, Flags: ptrTo("-x")}, "system.services[0]"},
		{"rtable 256", ServiceSetting{Name: "ntpd", Enabled: true, RTable: ptrTo(256)}, "system.services[0].rtable"},
	} {
		m, _ := loadSampleModel(t)
		m.System.Services = []ServiceSetting{tc.s}
		if !slicesContainsPath(Validate(m), tc.path) {
			t.Errorf("%s: no error at %s: %v", tc.name, tc.path, Validate(m))
		}
	}
}
