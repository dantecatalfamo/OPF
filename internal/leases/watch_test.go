package leases

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dantecatalfamo/OPF/internal/pf"
)

// fakeRunner records unbound-control invocations and answers them.
type fakeRunner struct {
	calls [][]string
	list  string
	reply string
	err   error
}

func (f *fakeRunner) Run(_ context.Context, argv ...string) ([]byte, error) {
	f.calls = append(f.calls, argv)
	if f.err != nil {
		return []byte("error connecting"), f.err
	}
	if slices.Contains(argv, "list_local_data") {
		return []byte(f.list), nil
	}
	return []byte(f.reply), nil
}

func TestUnbound(t *testing.T) {
	f := &fakeRunner{reply: "ok\n", list: "gw.office.arpa.\t3600\tIN\tA\t192.168.1.1\n" +
		"laptop.office.arpa.\t300\tIN\tA\t192.168.1.101\n" +
		"office.arpa.\t3600\tIN\tNS\tgw.office.arpa.\n" +
		"localhost.\t10800\tIN\tAAAA\t::1\n"}
	u := Unbound{Runner: f, Config: "/var/unbound/etc/unbound.conf"}
	ctx := context.Background()

	got, err := u.List(ctx)
	want := []Record{{"gw.office.arpa.", netip.MustParseAddr("192.168.1.1")}, {"laptop.office.arpa.", netip.MustParseAddr("192.168.1.101")}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("List = %+v, %v", got, err)
	}
	if err := u.Add(ctx, Record{"phone.office.arpa.", netip.MustParseAddr("192.168.1.102")}); err != nil {
		t.Fatal(err)
	}
	if err := u.Remove(ctx, "phone.office.arpa."); err != nil {
		t.Fatal(err)
	}
	wantCalls := [][]string{
		{"unbound-control", "-c", "/var/unbound/etc/unbound.conf", "list_local_data"},
		{"unbound-control", "-c", "/var/unbound/etc/unbound.conf", "local_data", "phone.office.arpa.", "300", "IN", "A", "192.168.1.102"},
		{"unbound-control", "-c", "/var/unbound/etc/unbound.conf", "local_data_remove", "phone.office.arpa."},
	}
	if !reflect.DeepEqual(f.calls, wantCalls) {
		t.Errorf("calls\n%q\nwant\n%q", f.calls, wantCalls)
	}

	// Names that didn't come from Records never reach unbound-control.
	f.calls = nil
	for _, name := range []string{"phone.office.arpa", "a b.office.arpa.", "x.office.arpa.\n", "phone.", ".", "a..b."} {
		if u.Add(ctx, Record{name, netip.MustParseAddr("192.168.1.102")}) == nil || u.Remove(ctx, name) == nil {
			t.Errorf("accepted %q", name)
		}
	}
	if u.Add(ctx, Record{"phone.office.arpa.", netip.MustParseAddr("fe80::1")}) == nil {
		t.Error("accepted an IPv6 address for an A record")
	}
	if len(f.calls) != 0 {
		t.Errorf("ran %q", f.calls)
	}

	f.reply = "error name not in zone\n"
	if err := u.Add(ctx, Record{"phone.office.arpa.", netip.MustParseAddr("192.168.1.102")}); err == nil {
		t.Error("an unexpected reply wasn't an error")
	}
	f.err = errors.New("exit status 1")
	if _, err := u.List(ctx); err == nil || !strings.Contains(err.Error(), "error connecting") {
		t.Errorf("List error = %v", err)
	}
}

type env struct {
	t     *testing.T
	w     *Watcher
	dns   *Memory
	model *pf.Model
}

func newWatcher(t *testing.T) *env {
	e := &env{t: t, dns: &Memory{}, model: testModel()}
	e.w = &Watcher{
		File:     filepath.Join(t.TempDir(), "dhcpd.leases"),
		Model:    func() (*pf.Model, error) { return e.model, nil },
		Resolver: e.dns,
		Now:      func() time.Time { return now },
	}
	return e
}

func (e *env) leases(ls ...string) {
	var b strings.Builder
	for i := 0; i+1 < len(ls); i += 2 {
		fmt.Fprintf(&b, "lease %s {\n\tstarts 1 2026/09/28 11:00:00 UTC;\n\tends 1 2026/09/28 13:00:00 UTC;\n\tclient-hostname %q;\n}\n", ls[i], ls[i+1])
	}
	if err := os.WriteFile(e.w.File, []byte(b.String()), 0644); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) sync() {
	e.t.Helper()
	if err := e.w.Sync(context.Background()); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) records() string {
	rs, _ := e.dns.List(context.Background())
	var out []string
	for _, r := range rs {
		out = append(out, r.Name+"="+r.IP.String())
	}
	slices.Sort(out)
	return strings.Join(out, " ")
}

func (e *env) expect(want string) {
	e.t.Helper()
	if got := e.records(); got != want {
		e.t.Errorf("records\n%s\nwant\n%s", got, want)
	}
}

func TestWatcher(t *testing.T) {
	e := newWatcher(t)
	ctx := context.Background()

	e.sync() // no leases file yet
	e.expect("")

	// Records from the configuration are in unbound too; they're never
	// touched, even when a lease claims the name.
	e.dns.Add(ctx, Record{"gw.office.arpa.", netip.MustParseAddr("192.168.1.1")})
	e.dns.Add(ctx, Record{"wiki.office.arpa.", netip.MustParseAddr("192.168.1.25")})
	// Records in other zones aren't ours either.
	e.dns.Add(ctx, Record{"host.example.com.", netip.MustParseAddr("10.0.0.1")})
	// One left over from before a restart, or added by hand, is.
	e.dns.Add(ctx, Record{"stale.office.arpa.", netip.MustParseAddr("192.168.1.199")})

	e.leases("192.168.1.101", "laptop", "192.168.1.102", "phone", "192.168.1.103", "gw")
	e.sync()
	base := "gw.office.arpa.=192.168.1.1 host.example.com.=10.0.0.1 "
	e.expect(base + "laptop.office.arpa.=192.168.1.101 phone.office.arpa.=192.168.1.102 wiki.office.arpa.=192.168.1.25")

	// Nothing to do: nothing changes.
	before := e.records()
	e.sync()
	e.expect(before)

	// A device moves, another leaves.
	e.leases("192.168.1.151", "laptop")
	e.sync()
	e.expect(base + "laptop.office.arpa.=192.168.1.151 wiki.office.arpa.=192.168.1.25")

	// unbound reloaded and forgot runtime data: it's put back.
	e.dns.Remove(ctx, "laptop.office.arpa.")
	e.sync()
	e.expect(base + "laptop.office.arpa.=192.168.1.151 wiki.office.arpa.=192.168.1.25")

	// A second device asking for the name takes it from neither... and
	// the first loses it until the clash ends.
	e.leases("192.168.1.151", "laptop", "192.168.1.160", "laptop")
	e.sync()
	e.expect(base + "wiki.office.arpa.=192.168.1.25")

	// A damaged file leaves the records alone.
	e.leases("192.168.1.151", "laptop")
	e.sync()
	os.WriteFile(e.w.File, []byte(`lease 192.168.1.151 { client-hostname "laptop`), 0644)
	if err := e.w.Sync(ctx); err == nil {
		t.Error("no error for a damaged leases file")
	}
	e.expect(base + "laptop.office.arpa.=192.168.1.151 wiki.office.arpa.=192.168.1.25")

	// Turned off: hands off (unbound's reload clears the records).
	e.model.DNS.RegisterDynamicLeases = false
	e.leases()
	e.sync()
	e.expect(base + "laptop.office.arpa.=192.168.1.151 wiki.office.arpa.=192.168.1.25")
}

func TestWatcherResolverDown(t *testing.T) {
	e := newWatcher(t)
	e.w.Resolver = Unbound{Runner: &fakeRunner{err: errors.New("exit status 1")}, Config: "unbound.conf"}
	e.leases("192.168.1.101", "laptop")
	if err := e.w.Sync(context.Background()); err == nil {
		t.Error("no error with unbound unreachable")
	}
}

func TestKickDoesntBlock(t *testing.T) {
	var w Watcher
	for range 3 {
		w.Kick()
	}
}
