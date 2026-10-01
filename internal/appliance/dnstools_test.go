package appliance

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// unboundCtl answers unbound-control as unbound 1.26 would, and
// records what was run.
type unboundCtl struct {
	mu  sync.Mutex
	ran []string
}

func (u *unboundCtl) Run(_ context.Context, argv ...string) ([]byte, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	cmd := strings.Join(argv, " ")
	u.ran = append(u.ran, cmd)
	if !strings.HasPrefix(cmd, "unbound-control -c /var/unbound/etc/unbound.conf ") {
		return nil, errors.New("exit status 1")
	}
	switch argv[3] {
	case "lookup":
		return []byte("The following name servers are used for lookup of " + argv[4] + "\n;rrset 86400 2 0 8 0\ncom.\t86400\tIN\tNS\ta.gtld-servers.net.\n"), nil
	case "dump_cache":
		return []byte("START_RRSET_CACHE\n;rrset 3589 1 0 8 3\nexample.com.\t3589\tIN\tA\t93.184.215.14\n;rrset 3589 1 0 8 3\nwww.example.com.\t3589\tIN\tA\t93.184.215.14\n;rrset 60 1 0 8 3\nnotexample.com.\t60\tIN\tA\t192.0.2.1\nEND_RRSET_CACHE\nSTART_MSG_CACHE\nmsg example.com. IN A 33152 1 3589 3 1 0 0\nmsg other.org. IN A 33152 1 60 3 1 0 0\nEND_MSG_CACHE\nEOF\n"), nil
	case "list_local_zones":
		return []byte("office.arpa. static\n"), nil
	case "list_local_data":
		return []byte("files.office.arpa.\t3600\tIN\tA\t192.168.1.20\n"), nil
	case "flush", "flush_zone", "flush_bogus", "flush_negative":
		return []byte("ok\n"), nil
	}
	return nil, errors.New("exit status 1")
}

func TestDNSTools(t *testing.T) {
	e := newEnv(t, time.Minute)
	u := &unboundCtl{}
	e.m.Runner, e.m.Actions = u, u

	r, err := e.m.DNSTool(DNSToolRequest{Tool: "lookup", Name: "Example.COM."})
	if err != nil || len(r.Lines) != 3 || !strings.Contains(u.ran[len(u.ran)-1], "lookup example.com.") {
		t.Fatalf("lookup: %+v %v %v", r, err, u.ran)
	}
	// The cache: the name and what's under it, not a name that only ends
	// the same way.
	r, _ = e.m.DNSTool(DNSToolRequest{Tool: "cache", Name: "example.com"})
	got := strings.Join(r.Lines, "\n")
	if len(r.Lines) != 3 || strings.Contains(got, "notexample") || strings.Contains(got, "other.org") || !strings.Contains(got, "www.example.com.") {
		t.Errorf("cache:\n%s", got)
	}
	if r, _ := e.m.DNSTool(DNSToolRequest{Tool: "local"}); len(r.Lines) != 2 {
		t.Errorf("local: %v", r.Lines)
	}
	for _, tool := range []string{"flush", "flush_zone"} {
		if r, err := e.m.DNSTool(DNSToolRequest{Tool: tool, Name: "example.com"}); err != nil || r.Lines[0] != "ok" {
			t.Errorf("%s: %+v %v", tool, r, err)
		}
	}
	if _, err := e.m.DNSTool(DNSToolRequest{Tool: "flush_bogus"}); err != nil {
		t.Error(err)
	}
	// Names that aren't one, or could be taken for an option, and tools
	// that aren't.
	for _, bad := range []DNSToolRequest{{Tool: "lookup", Name: "-c/etc/passwd"}, {Tool: "flush", Name: "a b"}, {Tool: "flush_zone", Name: "."}, {Tool: "flush", Name: "*.example.com"}, {Tool: "lookup"}, {Tool: "reload"}, {Tool: "stop"}} {
		if _, err := e.m.DNSTool(bad); err == nil {
			t.Errorf("took %+v", bad)
		}
	}
	for _, c := range u.ran {
		if strings.Contains(c, "passwd") || strings.Contains(c, "reload") || strings.Contains(c, "stop") {
			t.Errorf("ran %q", c)
		}
	}
	// With the resolver off, nothing runs.
	m := e.live().Model
	m.DNS.Enabled = false
	e.m.Runner, e.m.Actions = e.run, e.run
	if err := stageCommit(t, e, m); err != nil {
		t.Fatal(err)
	}
	e.m.Runner, e.m.Actions = u, u
	if _, err := e.m.DNSTool(DNSToolRequest{Tool: "local"}); err == nil {
		t.Error("ran with the resolver off")
	}
}

// Against what 7.9's unbound printed after looking up github.com,
// www.github.com (a CNAME to it) and others.
func TestCacheLinesReal(t *testing.T) {
	dump, err := os.ReadFile("testdata/openbsd-7.9/unbound-control_dump_cache.txt")
	if err != nil {
		t.Fatal(err)
	}
	got := cacheLines(string(dump), "github.com")
	for _, want := range []string{
		"github.com.\t59\tIN\tA\t140.82.114.3\n",
		"www.github.com.\t3599\tIN\tCNAME\tgithub.com.\n",
		"github.com.\t300\tIN\tMX\t0 github-com.mail.protection.outlook.com.\n",
		"github.com.\t86399\tIN\tNS\tns-520.awsdns-01.net.\n",
		"www.github.com. IN A: answer kept, 59 s left\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
	for _, not := range []string{"RRSIG", "IN A 0", "IN CNAME 0", "msg ", "openbsd"} {
		if strings.Contains(got, not) {
			t.Errorf("has %q:\n%s", not, got)
		}
	}
}
