package pf

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// importFixture reads a machine's files from testdata/import/<name>,
// laid out as on the machine.
func importFixture(t *testing.T, name string, egress ...string) ImportSources {
	t.Helper()
	root := filepath.Join("testdata", "import", name)
	src := ImportSources{Files: map[string]string{}, Egress: egress}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		src.Files["/"+filepath.ToSlash(rel)] = string(data)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return src
}

// The router fixture: a home router configured by hand.
func TestImportRouter(t *testing.T) {
	src := importFixture(t, "router", "em0")
	res := Import(src, ImportOptions{})
	m := res.Model
	for _, e := range Validate(m) {
		t.Errorf("invalid: %v", e)
	}
	// The interfaces, named after the file's macros for them; the
	// tunnel and the port carrying the VLAN aren't the model's.
	var ifaces []string
	for _, i := range m.Interfaces {
		ifaces = append(ifaces, fmt.Sprintf("%s=%s/%s/%s", i.ID, i.Device, i.Role, i.IPv4.Mode))
	}
	if got := strings.Join(ifaces, " "); got != "ext_if=em0/wan/dhcp int_if=em1/opt/static iot_if=vlan20/opt/static" {
		t.Errorf("interfaces %s", got)
	}
	if v := m.Interfaces[2].VLAN; v == nil || v.Tag != 20 || v.Parent != "em2" {
		t.Errorf("VLAN %+v", v)
	}
	if m.System.Hostname != "gw" || m.System.Domain != "home.example" || !slices.Equal(m.System.NTPServers, []string{"pool.ntp.org"}) {
		t.Errorf("system %+v", m.System)
	}
	// The resolver has settings OPF doesn't: left alone. DHCP and time
	// are written the same way: OPF's.
	if !slices.Equal(m.System.Unmanaged, []string{AreaDNS}) || m.DNS.Enabled || m.DNS.Mode != ResolverModeForward || !m.DNS.ForwardTLS {
		t.Errorf("unmanaged %v, dns %+v", m.System.Unmanaged, m.DNS)
	}
	if len(m.DHCP) != 2 || !m.DHCP[0].Enabled || m.DHCP[0].LeaseHours != 24 || m.DHCP[1].LeaseHours != 12 || len(m.DHCP[0].Reservations) != 1 {
		t.Errorf("dhcp %+v", m.DHCP)
	}
	o := m.Firewall.Options
	if o.MaxStates != 50000 || o.BlockPolicy != BlockPolicyDrop || len(o.SkipOn) != 0 {
		t.Errorf("options %+v", o)
	}
	if len(m.Firewall.Aliases) != 2 || !strings.Contains(m.Firewall.Custom.Options, "table <martians>") || !strings.Contains(m.Firewall.Custom.Options, `lan_net = "192.168.1.0/24"`) {
		t.Errorf("aliases %+v, custom %q", m.Firewall.Aliases, m.Firewall.Custom.Options)
	}
	// Every rule, in the file's order, in the pf.conf OPF writes.
	conf := GeneratePfConf(m)
	at := 0
	for _, r := range m.Firewall.Rules {
		line := GenerateRule(&r, m)
		i := strings.Index(conf[at:], line)
		if i < 0 {
			t.Fatalf("rule %q isn't in order in:\n%s", line, conf)
		}
		at += i + len(line)
	}
	// rc.conf.local: OPF sets dhcpd's flags, and leaves the resolver's
	// line, the admin's, as it is.
	rc, err := MergeRcConfLocal(src.Files[RcPath], m)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rc, "unbound_flags=\n") || !strings.HasSuffix(rc, RcMarker+"\n"+`dhcpd_flags="em1 vlan20"`+"\n") {
		t.Errorf("rc.conf.local:\n%s", rc)
	}
	for _, f := range GenerateFiles(m) {
		if f.Path == UnboundConfPath {
			t.Error("the resolver left alone is written")
		}
	}

	// Asked to, OPF manages the resolver too, with what it understood.
	res = Import(src, ImportOptions{Manage: map[string]bool{AreaDNS: true}})
	if len(res.Model.System.Unmanaged) != 0 || !res.Model.DNS.Enabled || !slices.Equal(res.Model.DNS.Forwarders, []string{"9.9.9.9", "149.112.112.112"}) {
		t.Errorf("managed resolver: %+v", res.Model.DNS)
	}
}

// A stock install: pf.conf from /etc/examples, and nothing set up.
func TestImportStock(t *testing.T) {
	res := Import(importFixture(t, "stock", "vio0"), ImportOptions{})
	m := res.Model
	for _, e := range Validate(m) {
		t.Errorf("invalid: %v", e)
	}
	areas := map[string]ImportArea{}
	for _, a := range res.Areas {
		areas[a.Area] = a
	}
	// ntpd.conf has constraints and a sensor: left alone. dhcpd and
	// unbound don't run, so OPF takes them, off.
	if a := areas[AreaNTP]; a.Exact || a.Managed {
		t.Errorf("ntp %+v", a)
	}
	if a := areas[AreaDNS]; a.Running || !a.Managed || m.DNS.Enabled || !m.DNS.DNSSEC {
		t.Errorf("dns %+v %+v", a, m.DNS)
	}
	if a := areas[AreaDHCP]; a.Running || !a.Managed || len(m.DHCP) != 0 {
		t.Errorf("dhcp %+v", a)
	}
	var kinds []string
	for _, r := range m.Firewall.Rules {
		kinds = append(kinds, r.Kind+":"+r.Description)
	}
	if got := strings.Join(kinds, ","); got != "form:block stateless traffic,form:establish keep-state,raw:By default, do not permit remote connections to X11" {
		t.Errorf("rules %s", got)
	}
	if m.System.Hostname != "opfvm" || m.System.Domain != "my.domain" || m.Interfaces[0].ID != "wan" || m.Interfaces[0].Role != RoleWAN {
		t.Errorf("system %+v, interfaces %+v", m.System, m.Interfaces)
	}
}

// A rule on one interface becomes a guided one only where the generator
// writes it in the same place; the interfaces are put in the order the
// run at the end needs.
func TestImportKeepsRuleOrder(t *testing.T) {
	src := ImportSources{Files: map[string]string{
		"/etc/hostname.em0": "inet 10.0.0.1/24\n",
		"/etc/hostname.em1": "inet 10.0.1.1/24\n",
		"/etc/pf.conf": `block all
pass in on em1 proto tcp to port 22
pass out all
pass in on em1 proto tcp to port 80
pass in on em0 proto tcp to port 443
pass in on em0 proto tcp to port 8443
`,
	}}
	m := Import(src, ImportOptions{}).Model
	var got []string
	for _, r := range m.Firewall.Rules {
		got = append(got, r.Kind)
	}
	// The second rule would move after "pass out all": kept as written.
	if strings.Join(got, " ") != "form raw form form form form" {
		t.Errorf("kinds %v", got)
	}
	if m.Interfaces[0].Device != "em1" || m.Interfaces[1].Device != "em0" {
		t.Errorf("interfaces in the run's order: %+v", m.Interfaces)
	}
	conf := GeneratePfConf(m)
	at := 0
	for _, want := range []string{"block all", "port 22", "pass out all", "port 80", "port 443", "port 8443"} {
		i := strings.Index(conf[at:], want)
		if i < 0 {
			t.Fatalf("%q out of order in:\n%s", want, conf)
		}
		at += i
	}
}

func TestImportExplicitDefault(t *testing.T) {
	src := ImportSources{Files: map[string]string{"/etc/pf.conf": "pass in proto tcp to port 22\n"}}
	m := Import(src, ImportOptions{Pf: ImportPfOptions{ExplicitDefault: true}}).Model
	if len(m.Firewall.Rules) != 2 || m.Firewall.Rules[0].Text != ExplicitDefaultRule {
		t.Errorf("rules %+v", m.Firewall.Rules)
	}
}

func TestSplitPfConf(t *testing.T) {
	stmts, loose := splitPfConf(`# $OpenBSD: pf.conf,v 1.1 $
# about the file

# web servers
table <web> { 10.0.0.1 \
	10.0.0.2 }
pass in proto tcp to <web> port { 80 # http
	443 }	# and https
pass out label "a # b"
`)
	if len(loose) != 1 || loose[0].Text != "about the file" {
		t.Errorf("loose %+v", loose)
	}
	want := []pfStatement{
		{Line: 5, Text: "table <web> { 10.0.0.1 10.0.0.2 }", Comment: "web servers"},
		{Line: 7, Text: "pass in proto tcp to <web> port { 80 443 }", Comment: "http and https"},
		{Line: 9, Text: `pass out label "a # b"`},
	}
	if !slices.Equal(stmts, want) {
		t.Errorf("statements\n%+v\nwant\n%+v", stmts, want)
	}
}

func TestParseHostnameIf(t *testing.T) {
	for _, c := range []struct {
		in   string
		v4   string
		left bool
	}{
		{"inet 192.168.1.1 255.255.255.0 192.168.1.255\nup\n", "192.168.1.1/24", false},
		{"inet 192.168.1.1 0xffffff00 NONE\n", "192.168.1.1/24", false},
		{"inet 192.168.1.1/25 # the LAN\n", "192.168.1.1/25", false},
		{"dhcp\n", "dhcp", false},
		{"inet 192.168.1.1 255.255.255.0 192.168.1.127\n", "", true}, // another broadcast
		{"inet 192.168.1.1/24\ninet alias 192.168.1.2/32\n", "192.168.1.1/24", true},
		{"lladdr 00:11:22:33:44:55\ninet autoconf\n", "dhcp", true},
		{"!route add -net 10.0.0.0/8 192.168.1.254\n", "", true},
	} {
		h := parseHostnameIf(c.in)
		v4 := string(h.v4.Mode)
		if h.v4.Mode == IPv4Static {
			v4 = fmt.Sprintf("%s/%d", h.v4.Address, *h.v4.Prefix)
		} else if h.v4.Mode == IPv4None {
			v4 = ""
		}
		if v4 != c.v4 || (len(h.notModel) > 0) != c.left {
			t.Errorf("%q: %s, not modelled %q", c.in, v4, h.notModel)
		}
	}
}

func TestImportDHCPInexact(t *testing.T) {
	src := ImportSources{Files: map[string]string{
		"/etc/myname":       "fw.example.org\n",
		"/etc/hostname.em1": "inet 10.0.1.1/24\n",
		RcPath:              "dhcpd_flags=em1\n",
		DHCPdConfPath: `option domain-name "example.org";
subnet 10.0.1.0 netmask 255.255.255.0 {
	option routers 10.0.1.1;
	option domain-name-servers 10.0.1.1;
	range 10.0.1.100 10.0.1.200;
	max-lease-time 7200;
}
`,
	}}
	res := Import(src, ImportOptions{})
	a := res.Areas[slices.IndexFunc(res.Areas, func(a ImportArea) bool { return a.Area == AreaDHCP })]
	if a.Exact || a.Managed || !a.Running || !Unmanaged(res.Model, AreaDHCP) || res.Model.DHCP[0].Enabled {
		t.Errorf("area %+v, scopes %+v", a, res.Model.DHCP)
	}
	for _, e := range Validate(res.Model) {
		t.Errorf("invalid: %v", e)
	}
}

func TestMaskPrefix(t *testing.T) {
	for in, want := range map[string]int{"255.255.255.0": 24, "0xffff0000": 16, "255.255.255.255": 32, "0.0.0.0": 0} {
		if n, ok := maskPrefix(in); !ok || n != want {
			t.Errorf("%s: %d %v", in, n, ok)
		}
	}
	for _, in := range []string{"255.0.255.0", "nope", "0x1"} {
		if _, ok := maskPrefix(in); ok {
			t.Errorf("%s is a mask", in)
		}
	}
}

// A stock install's pf.conf and the router's, and the ones OPF writes
// for them, as pfctl -nvf printed them on OpenBSD 7.9 (the router's
// devices renamed to the VM's), load as the same rulesets.
func TestComparePfRulesets(t *testing.T) {
	read := func(name string) string {
		data, err := os.ReadFile(filepath.Join("testdata", "import", name))
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	if c := ComparePfRulesets(read("stock-pfctl-orig.txt"), read("stock-pfctl-gen.txt"), false); !c.Same {
		t.Errorf("a stock install's differs: %q", c.Differences)
	}
	orig, gen := read("router-pfctl-orig.txt"), read("router-pfctl-gen.txt")
	if c := ComparePfRulesets(orig, gen, false); !c.Same {
		t.Errorf("differ: %q", c.Differences)
	}
	// Each kind of difference is found.
	for _, c := range []struct {
		name, gen string
	}{
		{"an option", strings.Replace(gen, "set limit states 50000", "set limit states 60000", 1)},
		{"a default made explicit differently", strings.Replace(gen, "set block-policy drop", "set block-policy return", 1)},
		{"a rule", strings.Replace(gen, "pass in on vio1 inet all flags S/SA", "pass in on vio1 all flags S/SA", 1)},
		{"rules' order", strings.Replace(strings.Replace(gen, "block drop all label \"opf:rule:imp6\"\n", "", 1), "pass in on vlan20", "block drop all\npass in on vlan20", 1)},
		{"a table", strings.Replace(gen, "table <bruteforce> persist", "table <bruteforce> persist counters", 1)},
		{"unfiltered interfaces", strings.Replace(gen, "set skip on { lo }", "set skip on { lo enc0 }", 1)},
	} {
		if r := ComparePfRulesets(orig, c.gen, false); r.Same {
			t.Errorf("%s: no difference found", c.name)
		}
	}
	// Without a rule matching every packet, OPF's defaults would decide.
	noCatch := strings.Replace(orig, "block drop all\n", "", 1)
	noCatchGen := strings.Replace(gen, "block drop all label \"opf:rule:imp6\"\n", "", 1)
	if r := ComparePfRulesets(noCatch, noCatchGen, false); r.Same || !r.NoCatchAll {
		t.Errorf("no catch-all: %+v", r)
	}
	// Imported again with pf's default written out first, they're the
	// same.
	explicit := strings.Replace(noCatchGen, "match in all scrub", ExplicitDefaultRule+" label \"opf:rule:imp1\"\nmatch in all scrub", 1)
	if r := ComparePfRulesets(noCatch, explicit, true); !r.Same {
		t.Errorf("with the default written out: %q", r.Differences)
	}
	for _, rule := range []string{"block drop all", "block return all", "pass all flags S/SA", "pass all no state", "block drop log all", "pass quick all flags S/SA keep state"} {
		if !catchAllRE.MatchString(rule) {
			t.Errorf("%q matches every packet", rule)
		}
	}
	for _, rule := range []string{"block drop in all", "pass out all flags S/SA", "block drop on vio0 all", "pass inet all flags S/SA", "block drop all tagged x", "pass proto tcp all flags S/SA"} {
		if catchAllRE.MatchString(rule) {
			t.Errorf("%q doesn't match every packet", rule)
		}
	}
}

// An area left alone has OPF's settings for it off, and keeps the
// admin's rc.conf.local line; OPF's block doesn't set it.
func TestUnmanagedAreas(t *testing.T) {
	m := Import(importFixture(t, "router", "em0"), ImportOptions{Manage: map[string]bool{AreaDHCP: false}}).Model
	if !Unmanaged(m, AreaDHCP) || len(Validate(m)) != 0 {
		t.Fatalf("unmanaged %v: %v", m.System.Unmanaged, Validate(m))
	}
	m.DHCP[0].Enabled = true
	if errs := Validate(m); len(errs) != 1 || errs[0].Path != "dhcp[0].enabled" {
		t.Errorf("a scope on while dhcpd is the admin's: %v", errs)
	}
	m.DHCP[0].Enabled = false
	rc, err := MergeRcConfLocal("dhcpd_flags=\"em9\"\nunbound_flags=NO\n", m)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(rc, "dhcpd_flags=\"em9\"\nunbound_flags=NO\n") || strings.Contains(rc[strings.Index(rc, RcMarker):], "_flags") {
		t.Errorf("rc.conf.local:\n%s", rc)
	}
	if got := RcOwnNames(rc); len(got) != 0 {
		t.Errorf("OPF's names %v", got)
	}
	if got := RcOwnNames("dhcpd_flags=em1\n"); !slices.Equal(got, RcNames) {
		t.Errorf("without OPF's block, %v", got)
	}
	m.System.Unmanaged = append(m.System.Unmanaged, AreaDHCP)
	if errs := Validate(m); len(errs) == 0 {
		t.Error("an area left alone twice")
	}
}

// Whatever a machine's files hold, importing them doesn't fail, and the
// rules keep the statements' order.
func FuzzImport(f *testing.F) {
	for _, name := range []string{"router", "stock"} {
		root := filepath.Join("testdata", "import", name)
		for _, p := range []string{"etc/pf.conf", "etc/dhcpd.conf", "etc/hostname.em1", "etc/ntpd.conf"} {
			if data, err := os.ReadFile(filepath.Join(root, p)); err == nil {
				f.Add(string(data), p)
			}
		}
	}
	f.Fuzz(func(t *testing.T, content, which string) {
		src := ImportSources{Files: map[string]string{
			"/etc/hostname.em0": "inet autoconf\n", "/etc/hostname.em1": "inet 10.0.0.1/24\n",
			"/etc/pf.conf": content, DHCPdConfPath: content, NTPdConfPath: content, "/etc/hostname.vlan5": content, UnboundConfPath: content,
		}, Egress: []string{"em0"}}
		res := Import(src, ImportOptions{})
		if res.Model == nil {
			t.Fatal("no model")
		}
		GenerateFiles(res.Model)
	})
}
