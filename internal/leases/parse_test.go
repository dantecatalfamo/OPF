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
	client-hostname "with \"quote\"";
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
	if !ls[2].Abandoned || ls[2].Hostname != `with "quote"` {
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
lease 10.0.0.5 { ends never; client-hostname "x"; option agent.circuit-id 1; }`))
	if err != nil || len(ls) != 1 || ls[0].Hostname != "x" {
		t.Fatalf("%+v, %v", ls, err)
	}
}

func TestParseErrors(t *testing.T) {
	for _, in := range []string{
		`lease 10.0.0.1 { ends never;`,                             // unterminated block
		`lease 10.0.0.1 { client-hostname "x; }`,                   // unterminated string
		"lease 10.0.0.1 { client-hostname \"a\nb\"; ends never; }", // newline in string
		`lease nope { ends never; }`,                               // not an address
		`lease 10.0.0.1 ends never;`,                               // no block
		`lease 10.0.0.1 { ends 1 2026/13/01 00:00:00; }`,           // bad date
		`lease 10.0.0.1 { ends soon; }`,                            // bad time
		`lease 10.0.0.1 { client-hostname a b; ends never; }`,      // not a string
		`lease 10.0.0.1 { ends never; { } }`,                       // stray block
		`}`,                                                        // stray brace
		`lease 10.0.0.1 { starts 1 2026/09/28 10:00:00 UTC }`,      // missing semicolon
	} {
		if ls, err := Parse(strings.NewReader(in)); err == nil {
			t.Errorf("Parse(%q) = %+v, want an error", in, ls)
		}
	}
}

func TestParseWithoutEndIsInactive(t *testing.T) {
	ls, err := Parse(strings.NewReader(`lease 10.0.0.1 { client-hostname "x"; }`))
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
	f.Add(`lease 10.0.0.1 { ends never; client-hostname "a\"b"; }`)
	f.Fuzz(func(t *testing.T, in string) {
		ls, err := Parse(strings.NewReader(in))
		if err != nil {
			return
		}
		for _, l := range ls {
			if !l.IP.IsValid() {
				t.Fatalf("invalid address in %+v", l)
			}
		}
	})
}
