package pf

import (
	"fmt"
	"strings"
	"testing"
)

func ip(n int) *int { return &n }

func withRecords(t *testing.T, rs ...DNSRecord) *Model {
	m, _ := loadSampleModel(t)
	m.DNS.Records = rs
	return m
}

func TestRecordLines(t *testing.T) {
	m := withRecords(t,
		DNSRecord{ID: "r1", Name: "storage.office.arpa", Type: DNSRecordCNAME, Value: "files.office.arpa"},
		DNSRecord{ID: "r2", Name: "docs.office.arpa", Type: DNSRecordCNAME, Value: "www.openbsd.org", TTL: ip(300)},
		DNSRecord{ID: "r3", Name: "office.arpa", Type: DNSRecordMX, Value: "mail.example.com", Priority: ip(10)},
		DNSRecord{ID: "r4", Name: "office.arpa", Type: DNSRecordTXT, Value: "v=spf1 -all # ; " + strings.Repeat("x", 300)},
		DNSRecord{ID: "r5", Name: "_sip._tcp.office.arpa", Type: DNSRecordSRV, Value: "files.office.arpa", Priority: ip(10), Weight: ip(5), Port: ip(5060)},
		DNSRecord{ID: "r6", Name: "_ldap._tcp.office.arpa", Type: DNSRecordSRV, Value: ".", Priority: ip(0), Weight: ip(0), Port: ip(0)},
		DNSRecord{ID: "r7", Name: "office.arpa", Type: DNSRecordCAA, Tag: "issue", Value: "letsencrypt.org"},
		DNSRecord{ID: "r8", Name: "192.168.1.20", Type: DNSRecordPTR, Value: "files.office.arpa"},
		DNSRecord{ID: "r9", Name: "printer2.office.arpa", Type: DNSRecordCNAME, Value: "printer.office.arpa"},
	)
	m.DNS.Zones = []DNSZone{{Name: "lab.example", Type: DNSZoneTransparent}}
	if errs := Validate(m); len(errs) > 0 {
		t.Fatal(errs)
	}
	conf := GenerateUnboundConf(m)
	for _, want := range []string{
		"\tlocal-zone: \"office.arpa.\" static\n",
		"\tlocal-zone: \"lab.example.\" transparent\n",
		// To a host name: its address, not a CNAME unbound won't follow.
		"\tlocal-data: 'storage.office.arpa. 3600 IN A 192.168.1.20'\n",
		// To a reserved device.
		"\tlocal-data: 'printer2.office.arpa. 3600 IN A 192.168.1.40'\n",
		// Outside: a CNAME in a redirect zone, which unbound follows.
		"\tlocal-zone: \"docs.office.arpa.\" redirect\n\tlocal-data: 'docs.office.arpa. 300 IN CNAME www.openbsd.org.'\n",
		"\tlocal-data: 'office.arpa. 3600 IN MX 10 mail.example.com.'\n",
		"\tlocal-data: 'office.arpa. 3600 IN TXT \"v=spf1 -all # ; " + strings.Repeat("x", 255-16) + "\" \"" + strings.Repeat("x", 61) + "\"'\n",
		"\tlocal-data: '_sip._tcp.office.arpa. 3600 IN SRV 10 5 5060 files.office.arpa.'\n",
		"\tlocal-data: '_ldap._tcp.office.arpa. 3600 IN SRV 0 0 0 .'\n",
		"\tlocal-data: 'office.arpa. 3600 IN CAA 0 issue \"letsencrypt.org\"'\n",
		"\tlocal-data-ptr: \"192.168.1.20 3600 files.office.arpa.\"\n",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("missing %q in\n%s", want, conf)
		}
	}
	if strings.Contains(conf, "storage.office.arpa. 3600 IN CNAME") {
		t.Error("a local alias written as a CNAME")
	}

	// The system's domain can answer the rest from outside.
	m.DNS.Zones = []DNSZone{{Name: "office.arpa", Type: DNSZoneTransparent}}
	if conf := GenerateUnboundConf(m); !strings.Contains(conf, "\tlocal-zone: \"office.arpa.\" transparent\n") || strings.Count(conf, "local-zone: \"office.arpa.\"") != 1 {
		t.Errorf("system zone:\n%s", conf)
	}
}

// An IPv6 host name is an AAAA record, not an A record unbound refuses.
func TestOverrideAAAA(t *testing.T) {
	m, _ := loadSampleModel(t)
	m.DNS.Overrides[0].IP = "2001:db8::20"
	if conf := GenerateUnboundConf(m); !strings.Contains(conf, "\"files.office.arpa. IN AAAA 2001:db8::20\"") {
		t.Error(conf)
	}
}

func TestRecordValidation(t *testing.T) {
	cname := func(name, value string) DNSRecord {
		return DNSRecord{ID: "c", Name: name, Type: DNSRecordCNAME, Value: value}
	}
	txt := func(v string) DNSRecord { return DNSRecord{ID: "t", Name: "office.arpa", Type: DNSRecordTXT, Value: v} }
	for _, tt := range []struct {
		name string
		path string
		rs   []DNSRecord
	}{
		{"TXT with a single quote (ends local-data)", "dns.records[0].value", []DNSRecord{txt("a' IN A 1.2.3.4 '")}},
		{"TXT with a double quote", "dns.records[0].value", []DNSRecord{txt("a\" \"b")}},
		{"TXT with a backslash", "dns.records[0].value", []DNSRecord{txt("a\\034b")}},
		{"TXT with a newline (a new unbound.conf line)", "dns.records[0].value", []DNSRecord{txt("a\n\tlocal-zone: \"com.\" static")}},
		{"TXT with a NUL", "dns.records[0].value", []DNSRecord{txt("a\x00b")}},
		{"TXT with non-ASCII", "dns.records[0].value", []DNSRecord{txt("café")}},
		{"TXT too long", "dns.records[0].value", []DNSRecord{txt(strings.Repeat("x", 2049))}},
		{"empty TXT", "dns.records[0].value", []DNSRecord{txt("")}},
		{"name with a quote", "dns.records[0].name", []DNSRecord{{ID: "t", Name: "a'.office.arpa", Type: DNSRecordTXT, Value: "x"}}},
		{"name with a space", "dns.records[0].name", []DNSRecord{{ID: "t", Name: "a b.office.arpa", Type: DNSRecordTXT, Value: "x"}}},
		{"wildcard name", "dns.records[0].name", []DNSRecord{{ID: "t", Name: "*.office.arpa", Type: DNSRecordTXT, Value: "x"}}},
		{"name with a final dot", "dns.records[0].name", []DNSRecord{{ID: "t", Name: "office.arpa.", Type: DNSRecordTXT, Value: "x"}}},
		{"unknown type", "dns.records[0].type", []DNSRecord{{ID: "t", Name: "office.arpa", Type: "A", Value: "1.2.3.4"}}},
		{"MX without a preference", "dns.records[0].priority", []DNSRecord{{ID: "m", Name: "office.arpa", Type: DNSRecordMX, Value: "mail.example.com"}}},
		{"MX to a name with a space", "dns.records[0].value", []DNSRecord{{ID: "m", Name: "office.arpa", Type: DNSRecordMX, Value: "mail example.com", Priority: ip(1)}}},
		{"SRV port out of range", "dns.records[0].port", []DNSRecord{{ID: "s", Name: "_x._tcp.office.arpa", Type: DNSRecordSRV, Value: "files.office.arpa", Priority: ip(0), Weight: ip(0), Port: ip(65536)}}},
		{"CAA with an unknown tag", "dns.records[0].tag", []DNSRecord{{ID: "a", Name: "office.arpa", Type: DNSRecordCAA, Tag: "issue\" x", Value: "letsencrypt.org"}}},
		{"CAA value with a quote", "dns.records[0].value", []DNSRecord{{ID: "a", Name: "office.arpa", Type: DNSRecordCAA, Tag: "issue", Value: "a\"b"}}},
		{"PTR for something that isn't an address", "dns.records[0].name", []DNSRecord{{ID: "p", Name: "192.168.1.300", Type: DNSRecordPTR, Value: "files.office.arpa"}}},
		{"PTR with a quote in its name", "dns.records[0].value", []DNSRecord{{ID: "p", Name: "192.168.1.9", Type: DNSRecordPTR, Value: "a\" 1 x."}}},
		{"TTL out of range", "dns.records[0].ttl", []DNSRecord{{ID: "t", Name: "office.arpa", Type: DNSRecordTXT, Value: "x", TTL: ip(-1)}}},
		{"two ids the same", "dns.records[1].id", []DNSRecord{txt("a"), txt("b")}},
		{"the same record twice", "dns.records[1]", []DNSRecord{txt("a"), {ID: "t2", Name: "Office.arpa", Type: DNSRecordTXT, Value: "a"}}},
		{"alias at a host name", "dns.records[0].name", []DNSRecord{cname("files.office.arpa", "www.openbsd.org")}},
		{"alias at the firewall's name", "dns.records[0].name", []DNSRecord{cname("gw.office.arpa", "www.openbsd.org")}},
		{"alias at a domain", "dns.records[0].name", []DNSRecord{cname("office.arpa", "www.openbsd.org")}},
		{"alias beside another record", "dns.records[0].name", []DNSRecord{cname("x.office.arpa", "www.openbsd.org"), {ID: "t", Name: "x.office.arpa", Type: DNSRecordTXT, Value: "x"}}},
		{"alias to itself", "dns.records[0].value", []DNSRecord{cname("x.office.arpa", "x.office.arpa")}},
		{"alias to an alias", "dns.records[1].value", []DNSRecord{cname("x.office.arpa", "files.office.arpa"), {ID: "c2", Name: "y.office.arpa", Type: DNSRecordCNAME, Value: "x.office.arpa"}}},
		// A lease's name, or one nobody has: unbound can't follow it.
		{"alias to a name the domain doesn't have", "dns.records[0].value", []DNSRecord{cname("x.office.arpa", "laptop.office.arpa")}},
		{"alias over a host name's domain", "dns.records[0].name", []DNSRecord{cname("arpa", "www.openbsd.org")}},
		{"alias with records under it", "dns.records[0].name", []DNSRecord{cname("x.office.arpa", "www.openbsd.org"), {ID: "t", Name: "a.x.office.arpa", Type: DNSRecordTXT, Value: "x"}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			m := withRecords(t, tt.rs...)
			for _, e := range Validate(m) {
				if e.Path == tt.path {
					return
				}
			}
			t.Errorf("no error at %s; got %v", tt.path, Validate(m))
		})
	}

	for _, tt := range []struct {
		name  string
		path  string
		zones []DNSZone
	}{
		{"zone with a quote", "dns.zones[0].name", []DNSZone{{Name: "lab\" static", Type: DNSZoneStatic}}},
		{"zone over every reverse name", "dns.zones[0].name", []DNSZone{{Name: "in-addr.arpa", Type: DNSZoneStatic}}},
		{"zone type unbound would take differently", "dns.zones[0].type", []DNSZone{{Name: "lab.example", Type: "always_nxdomain"}}},
		{"zone twice", "dns.zones[1].name", []DNSZone{{Name: "lab.example", Type: DNSZoneStatic}, {Name: "LAB.example", Type: DNSZoneStatic}}},
		// It would hide every .com name.
		{"a top-level domain answering only its own names", "dns.zones[0].type", []DNSZone{{Name: "com", Type: DNSZoneStatic}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			m, _ := loadSampleModel(t)
			m.DNS.Zones = tt.zones
			for _, e := range Validate(m) {
				if e.Path == tt.path {
					return
				}
			}
			t.Errorf("no error at %s; got %v", tt.path, Validate(m))
		})
	}
}

func TestFirewallNameAndReverse(t *testing.T) {
	m := withRecords(t, DNSRecord{ID: "p", Name: "192.168.1.25", Type: DNSRecordPTR, Value: "wiki.office.arpa"})
	conf := GenerateUnboundConf(m)
	for _, want := range []string{
		// Each inside network asks its own view, which answers with the
		// firewall's address there.
		"\taccess-control-view: 192.168.1.0/24 opf-net-lan\n",
		"\nview:\n\tname: \"opf-net-lan\"\n\tview-first: yes\n\tlocal-data: \"gw.office.arpa. IN A 192.168.1.1\"\n",
		"\nview:\n\tname: \"opf-net-iot\"\n\tview-first: yes\n\tlocal-data: \"gw.office.arpa. IN A 192.168.20.1\"\n",
		// Reverse names: the firewall's, a host name's, a reserved device's.
		"\tlocal-data-ptr: \"192.168.1.1 gw.office.arpa.\"\n",
		"\tlocal-data-ptr: \"192.168.1.20 files.office.arpa.\"\n",
		"\tlocal-data-ptr: \"192.168.1.40 printer.office.arpa.\"\n",
		// A record wins over a host name (wiki) and a reservation (build).
		"\tlocal-data-ptr: \"192.168.1.25 3600 wiki.office.arpa.\"\n",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("missing %q in\n%s", want, conf)
		}
	}
	// The firewall asking itself, from loopback, gets its address on
	// every network it answers: it had no view, and its own name didn't
	// exist on it (seen on the VM).
	self := "\nview:\n\tname: \"opf-self\"\n\tview-first: yes\n"
	for _, i := range DNSServed(m) {
		self += fmt.Sprintf("\tlocal-data: \"gw.office.arpa. IN A %s\"\n", i.IPv4.Address)
	}
	if !strings.Contains(conf, "\taccess-control-view: 127.0.0.0/8 opf-self\n") || !strings.Contains(conf, self) || len(DNSServed(m)) < 2 {
		t.Errorf("no loopback view %q in\n%s", self, conf)
	}
	if strings.Contains(conf, "opf-net-wan") || strings.Count(conf, "192.168.1.25 ") != 1 || strings.Count(conf, "local-data-ptr: \"192.168.1.20 ") != 1 {
		t.Errorf("a WAN view, or an address with two reverse names:\n%s", conf)
	}
	// Reserved devices' reverse names follow their names into DNS.
	m.DNS.RegisterReservations = false
	if strings.Contains(GenerateUnboundConf(m), "192.168.1.40 printer") {
		t.Error("reverse name for a reservation that isn't in DNS")
	}
}

func TestTopLevelZones(t *testing.T) {
	for _, z := range []DNSZone{{Name: "internal", Type: DNSZoneStatic}, {Name: "lan", Type: DNSZoneStatic}, {Name: "com", Type: DNSZoneTransparent}, {Name: "google.com", Type: DNSZoneStatic}} {
		m, _ := loadSampleModel(t)
		m.DNS.Zones = []DNSZone{z}
		for _, e := range Validate(m) {
			if strings.HasPrefix(e.Path, "dns.zones") {
				t.Errorf("%+v refused: %v", z, e)
			}
		}
	}
}
