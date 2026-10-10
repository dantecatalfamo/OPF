package conformance

import (
	"os"
	"strings"
	"testing"
)

// TestZCoverage runs last and fails for every command the registry
// declares that the suite didn't run on this release: a declaration
// without a check. Commands that need the internet are listed as not
// run when the guest has none, and fail only with
// OPF_CONFORMANCE_INTERNET=1.
func TestZCoverage(t *testing.T) {
	owns(t)
	if t.Failed() {
		return
	}
	var report []string
	for _, c := range Commands {
		tmpl := strings.Join(c.Argv, " ")
		by := ran.m[tmpl]
		switch {
		case by == "":
			t.Errorf("never ran on %s: %s (%s; registry Test %s)", release(), tmpl, c.Where, c.Test)
		case strings.HasPrefix(by, "NOT RUN"):
			report = append(report, tmpl+": "+by)
			if os.Getenv("OPF_CONFORMANCE_INTERNET") == "1" {
				t.Errorf("%s: %s", tmpl, by)
			}
		default:
			report = append(report, tmpl+": "+by)
		}
	}
	save(t, "coverage.txt", strings.Join(report, "\n")+"\n")
}
