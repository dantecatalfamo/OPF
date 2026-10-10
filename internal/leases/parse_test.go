package leases

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

const sampleFile = `# written by dhcpd
lease 192.168.1.112 {
	starts 1 2026/09/28 10:00:00 UTC;
	ends 2 2026/09/29 10:00:00 UTC;
	hardware ethernet 3C:22:FB:91:04:7D;
	uid 01:3c:22:fb:91:04:7d;
	client-hostname "priya-mbp";
}
lease 192.168.1.118 {
	starts 1 2026/09/28 09:00:00;
	ends never;
	hardware ethernet f0:18:98:2e:aa:13;
}
lease 192.168.1.131 {
	starts 1 2026/09/28 08:00:00 UTC;
	ends 1 2026/09/28 12:00:00 UTC;
	abandoned;
	client-hostname "plain";
}
lease 192.168.1.112 {
	starts 1 2026/09/28 11:00:00 UTC;
	ends 2 2026/09/29 11:00:00 UTC;
	client-hostname "priya-mbp-2";
}
`

func TestParse(t *testing.T) {
	ls, err := Parse(strings.NewReader(sampleFile))
	if err != nil {
		t.Fatal(err)
	}
	if len(ls) != 4 {
		t.Fatalf("got %d leases", len(ls))
	}
	l := ls[0]
	if l.IP != netip.MustParseAddr("192.168.1.112") || l.Hostname != "priya-mbp" || l.MAC != "3c:22:fb:91:04:7d" ||
		!l.Starts.Equal(time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)) || !l.Ends.Equal(time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC)) {
		t.Errorf("first lease: %+v", l)
	}
	if !ls[1].Ends.IsZero() || ls[1].Hostname != "" {
		t.Errorf("never-ending lease: %+v", ls[1])
	}
	if !ls[2].Abandoned || ls[2].Hostname != "plain" {
		t.Errorf("abandoned lease: %+v", ls[2])
	}

	now := time.Date(2026, 9, 28, 11, 30, 0, 0, time.UTC)
	cur := Current(ls, now)
	if len(cur) != 2 || cur[0].IP.String() != "192.168.1.118" || cur[1].Hostname != "priya-mbp-2" {
		t.Errorf("current: %+v", cur)
	}
	if got := Current(ls, time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)); len(got) != 1 {
		t.Errorf("after expiry: %+v", got)
	}
}

func TestParseSkipsOtherStatements(t *testing.T) {
	ls, err := Parse(strings.NewReader(`authoring-byte-order little-endian;
host thing { hardware ethernet 00:00:00:00:00:01; }
lease 10.0.0.5 {
	ends never;
	client-hostname "x";
	option agent.circuit-id 1;
}
lease nope { ends never; }
}
lease 10.0.0.6 ends never;
`))
	if err != nil || len(ls) != 1 || ls[0].Hostname != "x" || ls[0].Malformed {
		t.Fatalf("%+v, %v", ls, err)
	}
}

// Only a file that ends inside a string or a lease is an error: one
// dhcpd was writing.
func TestParseErrors(t *testing.T) {
	for _, in := range []string{
		"lease 10.0.0.1 {\n\tends never;",         // unterminated block
		"lease 10.0.0.1 {\n\tclient-hostname \"x", // unterminated string
	} {
		if ls, err := Parse(strings.NewReader(in)); err == nil {
			t.Errorf("Parse(%q) = %+v, want an error", in, ls)
		}
	}
}

// A statement Parse can't read spoils only its own lease, which then
// counts as no lease for its address.
func TestParseMalformed(t *testing.T) {
	for _, stmt := range []string{
		"ends 1 2026/13/01 00:00:00;",            // bad date
		"ends soon;",                             // bad time
		`client-hostname a b;`,                   // not a string
		"ends never; { }",                        // more on the line
		"starts 1 2026/09/28 10:00:00 UTC",       // no semicolon
		"client-hostname \"a",                    // a string the line ends in
		`hardware ethernet "00:00:00:00:00:01";`, // a string for a word
	} {
		in := "lease 10.0.0.1 {\n\tends never;\n\tclient-hostname \"old\";\n}\nlease 10.0.0.1 {\n\tends never;\n\t" + stmt + "\n}\n"
		ls, err := Parse(strings.NewReader(in))
		if err != nil || len(ls) != 2 || !ls[1].Malformed || !ls[1].Abandoned {
			t.Errorf("%q: %+v, %v", stmt, ls, err)
			continue
		}
		if cur := Current(ls, time.Now()); len(cur) != 0 {
			t.Errorf("%q: the address still has a current lease: %+v", stmt, cur)
		}
	}
}

// What a client can put in its hostname, written as dhcpd writes it
// (db.c's write_lease: the hostname between quotes, unescaped; only
// bytes below 33 or above 126 are refused), touches nothing but its
// own lease.
func TestParseHostileHostnames(t *testing.T) {
	lease := func(ip, host string) string {
		return "lease " + ip + " {\n\tstarts 1 2026/09/28 10:00:00 UTC;\n\tends 2 2026/09/29 10:00:00 UTC;\n" +
			"\thardware ethernet 00:00:00:00:00:01;\n\tclient-hostname \"" + host + "\";\n}\n"
	}
	now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		host string
		ok   bool // the hostile lease itself still reads, as dhcpd reads it
		name string
	}{
		{`evil\`, true, "evil"}, // the backslash takes the closing quote, which still ends the string
		{`a\b`, true, "ab"},
		{`x";ends"never";client-hostname"y`, false, ""},
		{`x";ends never`, false, ""},
		{`x";}lease"`, false, ""},
		{`x";}junk`, false, ""},
		{`x"y`, false, ""},
		{`x";abandoned;"`, false, ""},
		{`";}`, false, ""},
	} {
		in := lease("10.0.0.1", "victim") + lease("10.0.0.2", tc.host) + lease("10.0.0.3", "after")
		ls, err := Parse(strings.NewReader(in))
		if err != nil {
			t.Errorf("%q: %v", tc.host, err)
			continue
		}
		cur := Current(ls, now)
		names := map[string]string{}
		for _, l := range cur {
			names[l.IP.String()] = l.Hostname
		}
		if names["10.0.0.1"] != "victim" || names["10.0.0.3"] != "after" {
			t.Errorf("%q: the other leases: %v", tc.host, names)
		}
		if got, has := names["10.0.0.2"]; has != tc.ok || got != tc.name {
			t.Errorf("%q: its own lease: %q (%v), want %q (%v)", tc.host, got, has, tc.name, tc.ok)
		}
		for _, l := range cur {
			if !l.Ends.Equal(time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC)) {
				t.Errorf("%q: %s ends %v", tc.host, l.IP, l.Ends)
			}
		}
	}
}

func TestParseWithoutEndIsInactive(t *testing.T) {
	ls, err := Parse(strings.NewReader("lease 10.0.0.1 {\n\tclient-hostname \"x\";\n}\n"))
	if err != nil || len(ls) != 1 || ls[0].Active(time.Now()) {
		t.Fatalf("%+v, %v", ls, err)
	}
}

func TestParseTooLarge(t *testing.T) {
	big := strings.Repeat("# padding\n", maxFile/10+1)
	if _, err := Parse(strings.NewReader(big)); err == nil {
		t.Error("no error for an oversized file")
	}
}

func FuzzParse(f *testing.F) {
	f.Add(sampleFile)
	f.Add("lease 10.0.0.1 {\n\tends never;\n\tclient-hostname \"a\\\";}\";\n}\n")
	f.Fuzz(func(t *testing.T, in string) {
		ls, err := Parse(strings.NewReader(in))
		if err != nil {
			return
		}
		for _, l := range ls {
			if !l.IP.IsValid() {
				t.Fatalf("invalid address in %+v", l)
			}
			if l.Malformed && !l.Abandoned {
				t.Fatalf("a malformed lease counts: %+v", l)
			}
		}
	})
}
