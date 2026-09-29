package leases

import (
	"net/netip"
	"testing"
	"time"

	"github.com/dantecatalfamo/OPF/internal/pf"
)

var now = time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)

func testModel() *pf.Model {
	return &pf.Model{
		System: pf.SystemSettings{Hostname: "gw", Domain: "Office.arpa"},
		DHCP: []pf.DHCPScope{
			{Iface: "lan", Enabled: true, RangeStart: "192.168.1.100", RangeEnd: "192.168.1.199",
				Reservations: []pf.Reservation{{Hostname: "printer", IP: "192.168.1.40", MAC: "a4:5d:36:0c:81:9e"}, {Hostname: "nas", IP: "192.168.1.150"}}},
			{Iface: "guest", Enabled: false, RangeStart: "192.168.30.100", RangeEnd: "192.168.30.199"},
		},
		DNS: pf.DNS{Enabled: true, RegisterDynamicLeases: true, RewriteInvalidLeaseNames: true,
			Overrides: []pf.HostOverride{{Host: "wiki", Domain: "office.arpa", IP: "192.168.1.25"}}},
	}
}

func lease(ip, name string) Lease {
	return Lease{IP: netip.MustParseAddr(ip), Hostname: name, Starts: now.Add(-time.Hour), Ends: now.Add(time.Hour)}
}

func TestRecords(t *testing.T) {
	ls := []Lease{
		lease("192.168.1.101", "Laptop"),    // registered, lower-cased
		lease("192.168.1.102", "phone"),     // registered
		lease("192.168.1.103", ""),          // no name: silently ignored
		lease("192.168.1.104", "gw"),        // the router
		lease("192.168.1.105", "PRINTER"),   // a reservation, any case
		lease("192.168.1.106", "wiki"),      // a host override
		lease("192.168.1.107", "wpad"),      // proxy auto-discovery
		lease("192.168.1.108", "localhost"), //
		lease("192.168.1.109", "a.b"),       // not a single label
		lease("192.168.1.110", "x y"),       // not a label
		lease("192.168.1.111", "-x"),        //
		lease("192.168.1.112", "twin"),      // two devices, one name
		lease("192.168.1.113", "Twin"),      //
		lease("192.168.1.114", "bad\nname"), //
		lease("10.9.9.9", "outside"),        // not in a range
		lease("192.168.30.120", "guest"),    // disabled scope
		lease("192.168.1.150", "sneaky"),    // a reservation's address
		lease("192.168.1.115", "expired"),   // superseded below
		lease("192.168.1.116", "a23456789012345678901234567890123456789012345678901234567890123"),  // 63: fine
		lease("192.168.1.117", "a234567890123456789012345678901234567890123456789012345678901234"), // 64: too long
	}
	old := lease("192.168.1.115", "expired")
	old.Ends = now.Add(-time.Minute)
	ls = append(ls, old)

	got, skipped := Records(testModel(), ls, now)

	// Names are sanitized: "a.b" → "ab", "x y" → "x-y", "-x" → "x", "bad\nname" → "badname".
	// The 64-char name is truncated to 63, colliding with the already-63-char name.
	want := []Record{
		{Name: "ab.office.arpa.", IP: netip.MustParseAddr("192.168.1.109"), From: "a.b"},
		{Name: "badname.office.arpa.", IP: netip.MustParseAddr("192.168.1.114"), From: "bad\nname"},
		{Name: "laptop.office.arpa.", IP: netip.MustParseAddr("192.168.1.101")},
		{Name: "phone.office.arpa.", IP: netip.MustParseAddr("192.168.1.102")},
		{Name: "x-y.office.arpa.", IP: netip.MustParseAddr("192.168.1.110"), From: "x y"},
		{Name: "x.office.arpa.", IP: netip.MustParseAddr("192.168.1.111"), From: "-x"},
	}

	// The two 63-char names collide and are both skipped.
	gotByName := map[string]Record{}
	for _, r := range got {
		gotByName[r.Name+r.IP.String()] = r
	}
	wantByName := map[string]Record{}
	for _, r := range want {
		wantByName[r.Name+r.IP.String()] = r
	}
	if len(got) != len(want) {
		t.Fatalf("got %d records, want %d:\ngot:  %+v\nwant: %+v", len(got), len(want), got, want)
	}
	for key, w := range wantByName {
		g, ok := gotByName[key]
		if !ok {
			t.Errorf("missing record %+v", w)
		} else if g != w {
			t.Errorf("record %+v != want %+v", g, w)
		}
	}

	reasons := map[string]string{}
	for _, s := range skipped {
		reasons[s.IP.String()] = s.Reason
	}
	// Skipped: reserved names (104-108), twin collision (112, 113),
	// truncation collision (116, 117: both end up as 63-char same label).
	// No longer skipped: sanitized names (109, 110, 111, 114).
	for _, ip := range []string{"104", "105", "106", "107", "108", "112", "113", "116", "117"} {
		if reasons["192.168.1."+ip] == "" {
			t.Errorf("192.168.1.%s wasn't reported as skipped", ip)
		}
	}
	for _, ip := range []string{"10.9.9.9", "192.168.30.120", "192.168.1.150"} {
		if reasons[ip] == "" {
			t.Errorf("%s wasn't reported as skipped", ip)
		}
	}
	if _, ok := reasons["192.168.1.103"]; ok {
		t.Error("a lease without a name was reported")
	}
}

func TestRecordsDisabled(t *testing.T) {
	m := testModel()
	m.DNS.RegisterDynamicLeases = false
	if got, _ := Records(m, []Lease{lease("192.168.1.101", "laptop")}, now); got != nil {
		t.Errorf("registered with the setting off: %+v", got)
	}
	m = testModel()
	m.DNS.Enabled = false
	if got, _ := Records(m, []Lease{lease("192.168.1.101", "laptop")}, now); got != nil {
		t.Errorf("registered with DNS off: %+v", got)
	}
}

// With RewriteInvalidLeaseNames off, a name that isn't already a valid
// label is refused rather than rewritten; valid names are unaffected.
func TestRecordsWithoutRewrite(t *testing.T) {
	m := testModel()
	m.DNS.RewriteInvalidLeaseNames = false
	got, skipped := Records(m, []Lease{
		lease("192.168.1.101", "Laptop"),       // valid, only lower-cased
		lease("192.168.1.102", "Priya's iPad"), // would be rewritten to priyas-ipad
		lease("192.168.1.103", "x y"),
	}, now)
	if len(got) != 1 || got[0].Name != "laptop.office.arpa." || got[0].From != "" {
		t.Errorf("records %+v", got)
	}
	reasons := map[string]string{}
	for _, s := range skipped {
		reasons[s.IP.String()] = s.Reason
	}
	for _, ip := range []string{"192.168.1.102", "192.168.1.103"} {
		if reasons[ip] != "not a valid host name" {
			t.Errorf("%s: reason %q, want it refused as invalid", ip, reasons[ip])
		}
	}

	// On, the same lease is rewritten.
	m.DNS.RewriteInvalidLeaseNames = true
	got, _ = Records(m, []Lease{lease("192.168.1.102", "Priya's iPad")}, now)
	if len(got) != 1 || got[0].Name != "priyas-ipad.office.arpa." || got[0].From != "Priya's iPad" {
		t.Errorf("default: %+v", got)
	}
}
