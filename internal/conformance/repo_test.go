package conformance

import (
	"os"
	"testing"
)

// inRepo skips a test that reads the repository (OPF's source, the UI,
// sysinfo's captures) where it isn't: on the disposable guest, which has
// only the test binary. Those tests run with the ordinary go test.
func inRepo(t *testing.T) {
	t.Helper()
	if _, err := os.Stat("../../go.mod"); err != nil {
		t.Skip("needs the repository; it runs with go test on the development machine")
	}
}
