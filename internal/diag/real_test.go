package diag

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dantecatalfamo/OPF/internal/run"
)

// TestRealTools runs every tool for real, through the same code the
// parent uses, to check the commands Build makes against the system's
// ping, traceroute, dig and nc. It needs the network, so it only runs
// with OPF_REAL_TOOLS=1 (on OpenBSD: go test -c, then run it there).
func TestRealTools(t *testing.T) {
	if os.Getenv("OPF_REAL_TOOLS") != "1" {
		t.Skip("set OPF_REAL_TOOLS=1 to run the tools for real")
	}
	for _, tc := range []struct {
		req      Request
		exit     int
		contains string
	}{
		{Request{Tool: "ping", Host: "9.9.9.9", Count: 2}, 0, "2 packets received"},
		{Request{Tool: "ping", Host: "::1", Count: 1}, 0, "1 packets received"},
		{Request{Tool: "ping", Host: "9.9.9.9", Count: 1, Size: 1500, DontFragment: true}, 1, "Message too long"},
		{Request{Tool: "ping", Host: "nonexistent.invalid", Count: 1}, 1, "no address associated with name"},
		{Request{Tool: "traceroute", Host: "9.9.9.9", Protocol: "icmp", MaxHops: 3, ASNumbers: true}, 0, "3 hops max"},
		{Request{Tool: "traceroute", Host: "::1", MaxHops: 2}, 0, "traceroute6 to ::1"},
		{Request{Tool: "dns", Name: "example.com", Server: "9.9.9.9"}, 0, "status: NOERROR"},
		{Request{Tool: "dns", Name: "9.9.9.9", Server: "9.9.9.9"}, 0, "quad9"},
		{Request{Tool: "dns", Name: "_sip._tcp.nonexistent.invalid", Type: "SRV", Server: "9.9.9.9", DNSSEC: true}, 0, "status: NXDOMAIN"},
		{Request{Tool: "port", Host: "9.9.9.9", Port: 443}, 0, "succeeded"},
		{Request{Tool: "port", Host: "9.9.9.9", Port: 53, Protocol: "udp"}, 0, "succeeded"},
	} {
		rs := &Runs{Runner: run.Exec{}}
		r, err := rs.Start(tc.req)
		if err != nil {
			t.Errorf("%+v: %v", tc.req, err)
			continue
		}
		var done *Run
		for deadline := time.Now().Add(time.Minute); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
			if done, _ = rs.Get(r.ID, 0); !done.Running {
				break
			}
		}
		out := strings.Join(done.Lines, "\n")
		if done.Running || done.ExitCode == nil || *done.ExitCode != tc.exit || !strings.Contains(out, tc.contains) {
			code := -1
			if done.ExitCode != nil {
				code = *done.ExitCode
			}
			t.Errorf("%s: exit %d (want %d), error %q, want %q in:\n%s", done.Command, code, tc.exit, done.Error, tc.contains, out)
			continue
		}
		t.Logf("%s: ok", done.Command)
	}
}
