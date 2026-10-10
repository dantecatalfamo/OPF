package conformance

// The commands that change the system, run for real, with what OPF
// expects each one to do checked on the system afterwards.

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dantecatalfamo/OPF/internal/appliance"
	"github.com/dantecatalfamo/OPF/internal/config"
	"github.com/dantecatalfamo/OPF/internal/diag"
	"github.com/dantecatalfamo/OPF/internal/pf"
	oprun "github.com/dantecatalfamo/OPF/internal/run"
	"github.com/dantecatalfamo/OPF/internal/sysinfo"
)

// step runs one instance of a registry template, which must exit with
// one of codes (0 when none are given), checks its output against the
// template's Format when there is one, and records it as run.
func step(t *testing.T, tmpl string, argv []string, codes ...int) string {
	t.Helper()
	if !slices.ContainsFunc(Commands, func(c Command) bool { return strings.Join(c.Argv, " ") == tmpl }) {
		t.Fatalf("%q isn't a registry template", tmpl)
	}
	if !match(strings.Fields(tmpl), argv) && !strings.HasPrefix(tmpl, "sh -c") {
		t.Errorf("%s doesn't fit its template %q", strings.Join(argv, " "), tmpl)
	}
	out, code := run(argv...)
	if len(codes) == 0 {
		codes = []int{0}
	}
	if !slices.Contains(codes, code) {
		t.Errorf("%s: exit %d, want %v:\n%s", strings.Join(argv, " "), code, codes, out)
	}
	if _, ok := Formats[tmpl]; ok {
		checkOutput(t, tmpl, out)
	}
	markRan(tmpl, t.Name())
	return out
}

// TestPfTables: tables' contents, changed by hand, from a file, by
// expiry, and the traffic table's counters, directly and through OPF.
func TestPfTables(t *testing.T) {
	a := configured(t)
	const tbl = "conform"
	step(t, "pfctl -t * -T * ...", []string{"pfctl", "-t", tbl, "-T", "add", "192.0.2.1", "192.0.2.8/29", "!192.0.2.9"})
	show := step(t, "pfctl -t * -T show", []string{"pfctl", "-t", tbl, "-T", "show"})
	for _, want := range []string{"192.0.2.1", "192.0.2.8/29", "!192.0.2.9"} {
		if !strings.Contains(show, want) {
			t.Errorf("pfctl -T show doesn't list %s:\n%s", want, show)
		}
	}
	step(t, "pfctl -t * -T show -v", []string{"pfctl", "-t", tbl, "-T", "show", "-v"})
	list := filepath.Join(t.TempDir(), "list")
	os.WriteFile(list, []byte("# Downloaded by OPF from https://example.com/list at 2026-01-01T00:00:00Z\n198.51.100.0/24\n198.51.100.7\n"), 0644)
	step(t, "pfctl -t * -T replace -f *", []string{"pfctl", "-t", tbl, "-T", "replace", "-f", list})
	if show := must(t, "pfctl", "-t", tbl, "-T", "show"); strings.Contains(show, "192.0.2.1") || !strings.Contains(show, "198.51.100.0/24") {
		t.Errorf("replace left:\n%s", show)
	}
	exp := step(t, "pfctl -t * -T expire *", []string{"pfctl", "-t", tbl, "-T", "expire", "0"})
	if !regexp.MustCompile(`(\d+)/\d+ addresses? expired`).MatchString(exp) {
		t.Errorf("expire printed %q, which expiry.go doesn't read", exp)
	}
	step(t, "pfctl -t * -T * ...", []string{"pfctl", "-t", tbl, "-T", "delete", "198.51.100.7"})
	step(t, "pfctl -t * -T * ...", []string{"pfctl", "-t", tbl, "-T", "flush"})
	run("pfctl", "-t", tbl, "-T", "kill") // cleaning up: OPF never kills an alias's table

	// The traffic table, when the model counts traffic per device.
	if _, code := run("pfctl", "-t", pf.TrafficTable, "-T", "show"); code == 0 {
		// An address in it first, so show -v has its counters to print.
		step(t, "pfctl -t opf_hosts -T * ...", []string{"pfctl", "-t", "opf_hosts", "-T", "add", "192.0.2.77"})
		// The client, busy just now, has its counters, and OPF reads them.
		// OPF adds the devices it sees on its collector's tick (10 s).
		var hosts string
		for i := 0; i < 6; i++ {
			run("route", "-T"+clientRdom, "exec", "ping", "-c", "3", "-i", "0.2", clientRoute)
			hosts = step(t, "pfctl -t opf_hosts -T show -v", []string{"pfctl", "-t", "opf_hosts", "-T", "show", "-v"})
			if _, ok := sysinfo.ParsePfTableCounters(hosts)[clientAddr]; ok {
				break
			}
			time.Sleep(10 * time.Second)
		}
		if c, ok := sysinfo.ParsePfTableCounters(hosts)[clientAddr]; !ok {
			t.Errorf("the client %s isn't in <%s>:\n%s", clientAddr, pf.TrafficTable, hosts)
		} else if c.SentPackets == 0 || c.ReceivedPackets == 0 || !strings.Contains(hosts, "In/Pass:") {
			t.Errorf("the client's counters, after its pings: %+v:\n%s", c, hosts)
		}
		step(t, "pfctl -t opf_hosts -T * ...", []string{"pfctl", "-t", "opf_hosts", "-T", "delete", "192.0.2.77"})
	} else {
		t.Errorf("the everything model doesn't count traffic per device: %s isn't loaded", pf.TrafficTable)
	}

	// Through OPF: a table an alias made.
	var body struct {
		Tables []map[string]any `json:"tables"`
	}
	if err := a.do("GET", "/api/firewall/tables", nil, &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Tables) == 0 {
		t.Error("OPF lists no downloaded lists")
	}
	// One that takes addresses by hand: abusers, a dynamic table (a
	// downloaded list refuses them, rightly).
	const name = "abusers"
	for _, op := range []string{"add", "delete"} {
		if err := a.do("POST", "/api/firewall/tables/"+name+"/entries", appliance.TableChangeRequest{Table: name, Op: op, Addresses: []string{"192.0.2.55"}}, nil); err != nil {
			t.Errorf("%s 192.0.2.55 in %s through OPF: %v", op, name, err)
		}
	}
	apiGet(t, a, "/api/firewall/tables/"+name+"/entries")

	// Last, as OPF does when traffic per device is turned off: the
	// table goes until the rules are loaded again.
	step(t, "pfctl -t opf_hosts -T kill", []string{"pfctl", "-t", "opf_hosts", "-T", "kill"})
}

// TestPfKillState: closing one connection by its id, which pfctl -k id
// takes with the creator id in hex, as -vv -s states prints it.
func TestPfKillState(t *testing.T) {
	a := configured(t)
	// A connection from the client that stays open: SSH to the firewall.
	ssh := exec.Command("route", "-T"+clientRdom, "exec", "nc", clientRoute, "22")
	ssh.Stdin = nil
	if err := ssh.Start(); err != nil {
		t.Fatal(err)
	}
	defer ssh.Process.Kill()
	time.Sleep(time.Second)
	states, _ := sysinfo.ParsePfStates(must(t, "pfctl", "-vv", "-s", "states"), 100000)
	var st *sysinfo.PfState
	for i := range states {
		if strings.Contains(states[i].Source+states[i].Destination, clientAddr) && strings.HasSuffix(states[i].Destination, ":22") {
			st = &states[i]
			break
		}
	}
	if st == nil {
		t.Fatalf("no state for the client's SSH connection in:\n%s", captured(t, "pfctl_-vv_-s_states.txt"))
	}
	out := step(t, "pfctl -k id -k *", []string{"pfctl", "-k", "id", "-k", st.ID + "/" + st.CreatorID})
	if !strings.Contains(out, "killed 1 states") {
		t.Errorf("pfctl -k id -k %s/%s: %q, want killed 1 states", st.ID, st.CreatorID, out)
	}
	if strings.Contains(must(t, "pfctl", "-vv", "-s", "states"), "id: "+st.ID) {
		t.Errorf("state %s is still there", st.ID)
	}
	// Through OPF: one of the client's connections out.
	run("route", "-T"+clientRdom, "exec", "ping", "-c", "1", clientRoute)
	states, _ = sysinfo.ParsePfStates(must(t, "pfctl", "-vv", "-s", "states"), 100000)
	for _, s := range states {
		if strings.Contains(s.Source+s.Destination, clientAddr) {
			if err := a.do("POST", "/api/pf/states/kill", appliance.KillStateRequest{ID: s.ID, CreatorID: s.CreatorID}, nil); err != nil {
				t.Errorf("closing %s through OPF: %v", s.ID, err)
			}
			break
		}
	}
}

// TestUnbound: the resolver's control commands, through OPF's DNS tools
// and the lease names it adds.
func TestUnbound(t *testing.T) {
	a := configured(t)
	const ctl = "unbound-control -c /var/unbound/etc/unbound.conf"
	argv := func(args ...string) []string {
		return append([]string{"unbound-control", "-c", "/var/unbound/etc/unbound.conf"}, args...)
	}
	for _, c := range []string{"stats_noreset", "status", "dump_cache", "list_local_zones", "list_local_data", "flush_bogus", "flush_negative"} {
		step(t, ctl+" "+c, argv(c))
	}
	step(t, ctl+" lookup *", argv("lookup", "example.com."))
	step(t, ctl+" flush *", argv("flush", "example.com."))
	step(t, ctl+" flush_zone *", argv("flush_zone", "example.com."))
	if out := step(t, ctl+" local_data * * IN A *", argv("local_data", "conform.home.arpa.", "300", "IN", "A", "192.0.2.9")); strings.TrimSpace(out) != "ok" {
		t.Errorf("local_data printed %q; leases.expectOK wants exactly ok", out)
	}
	step(t, ctl+" local_data * * IN PTR *", argv("local_data", "9.2.0.192.in-addr.arpa.", "300", "IN", "PTR", "conform.home.arpa."))
	if !strings.Contains(must(t, argv("list_local_data")...), "conform.home.arpa.") {
		t.Error("list_local_data doesn't show the name local_data added")
	}
	step(t, ctl+" local_data_remove *", argv("local_data_remove", "conform.home.arpa."))
	// Every zone OPF configures for blocking names.
	conf := readFile(t, "/var/unbound/etc/unbound.conf")
	// The names of rpz: clauses only; views (opf-net-*) have names too.
	var zones []string
	section := ""
	for _, l := range strings.Split(conf, "\n") {
		if m := regexp.MustCompile(`^([a-z-]+):\s*$`).FindStringSubmatch(l); m != nil {
			section = m[1]
		} else if m := regexp.MustCompile(`^\s*name:\s*"?([^"\s]+)`).FindStringSubmatch(l); m != nil && section == "rpz" {
			zones = append(zones, m[1])
		}
	}
	if len(zones) == 0 {
		t.Error("unbound.conf has no zone of OPF's (rpz)")
	}
	for _, z := range zones {
		tmpl := ctl + " auth_zone_reload *"
		if z == "opf-own." {
			tmpl = ctl + " auth_zone_reload opf-own."
		}
		step(t, tmpl, argv("auth_zone_reload", z))
	}
	step(t, "unbound-anchor -v -a *", []string{"unbound-anchor", "-v", "-a", "/var/unbound/db/root.key"}, 0, 1)

	for _, tool := range []string{"lookup", "cache", "local", "flush", "flush_zone", "flush_bogus", "flush_negative"} {
		var res appliance.DNSToolResult
		if err := a.do("POST", "/api/dns/tools", appliance.DNSToolRequest{Tool: tool, Name: "example.com"}, &res); err != nil {
			t.Errorf("DNS tool %s: %v", tool, err)
		}
	}
	for _, p := range []string{"/api/dns/stats", "/api/dns/blocked", "/api/dns/leases", "/api/dhcp/leases", "/api/dns/activity", "/api/dns/blocklists"} {
		apiGet(t, a, p)
	}
	if b, _ := json.Marshal(apiGet(t, a, "/api/dns/stats")); !strings.Contains(string(b), "queries") {
		t.Errorf("OPF's DNS statistics have no queries: %.300s", b)
	}
}

// TestServices: rcctl's lists and each service's state, rc.conf's
// defaults OPF assumes, and starting and stopping through OPF.
func TestServices(t *testing.T) {
	a := configured(t)
	for _, tmpl := range []string{"rcctl ls on", "rcctl ls all"} {
		step(t, tmpl, strings.Fields(tmpl))
	}
	step(t, "rcctl ls started", []string{"rcctl", "ls", "started"}, 0, 1)
	for _, svc := range []string{"unbound", "dhcpd", "ntpd"} {
		step(t, "rcctl check *", []string{"rcctl", "check", svc})
		step(t, "rcctl get *", []string{"rcctl", "get", svc})
	}
	if _, code := run("rcctl", "check", "httpd"); code == 0 {
		t.Error("rcctl check says httpd, which isn't running, is")
	}
	// /etc/rc.conf's defaults OPF assumes: NO for RcNames (pf.RcValues),
	// ntpd and pflogd on unless told otherwise, httpd off. (rcctl getdef
	// prints a daemon's rc.d flags, not whether it's on.)
	defaults := map[string]string{}
	for _, l := range strings.Split(readFile(t, "/etc/rc.conf"), "\n") {
		if m := regexp.MustCompile(`^([a-z0-9_]+_flags)=(\S*)`).FindStringSubmatch(l); m != nil {
			defaults[m[1]] = strings.Trim(m[2], `"`)
		}
	}
	want := map[string]string{"ntpd_flags": "", "pflogd_flags": "", "httpd_flags": "NO"}
	for _, n := range pf.RcNames {
		want[n] = "NO"
	}
	for n, w := range want {
		if got, ok := defaults[n]; !ok || got != w {
			t.Errorf("/etc/rc.conf has %s=%q (set: %v), OPF assumes %q", n, got, ok, w)
		}
	}
	step(t, "rcctl * *", []string{"rcctl", "restart", "ntpd"})
	step(t, "rcctl * *", []string{"rcctl", "reload", "unbound"})
	flags := strings.TrimSpace(step(t, "rcctl get opf flags", []string{"rcctl", "get", "opf", "flags"}))
	step(t, "rcctl set opf flags ...", append([]string{"rcctl", "set", "opf", "flags"}, strings.Fields(flags)...))
	for _, act := range []string{"stop", "start", "restart"} {
		if err := a.do("POST", "/api/services/sndiod/"+act, nil, nil); err != nil {
			t.Errorf("%s sndiod through OPF: %v", act, err)
		}
	}
	apiGet(t, a, "/api/services")
	apiGet(t, a, "/api/services/unbound")
}

// TestAccounts: OPF's own accounts, made, changed and removed through
// OPF with useradd, usermod, userdel and groupadd, and signing in with
// them (login_passwd), with each step checked in master.passwd.
func TestAccounts(t *testing.T) {
	a := configured(t)
	const name = "conformop"
	acct := map[string]any{"name": name, "fullName": "Conformance Operator", "role": "operator", "password": "Another-Password-2", "shell": true}
	if err := a.do("POST", "/api/users", acct, nil); err != nil {
		t.Fatalf("adding %s: %v", name, err)
	}
	markRan("useradd -m -c * -s * -L default -p * ...", t.Name())
	pw := passwdLine(t, name)
	if len(pw) != 10 || pw[4] != "default" || pw[9] != "/bin/ksh" || !strings.HasPrefix(pw[1], "$2") || pw[8] != "/home/"+name {
		t.Errorf("%s in master.passwd: %q", name, pw)
	}
	if !inGroup(t, "_opfoperator", name) {
		t.Errorf("%s isn't in _opfoperator", name)
	}
	other := newAPI(t)
	if err := other.do("POST", "/api/session", map[string]string{"user": name, "password": "Another-Password-2"}, nil); err != nil {
		t.Errorf("signing in as %s (login_passwd): %v", name, err)
	}
	if err := a.do("PUT", "/api/users/"+name+"/role", map[string]string{"role": "view"}, nil); err != nil {
		t.Error(err)
	}
	markRan("usermod -S * *", t.Name())
	if inGroup(t, "_opfoperator", name) || !inGroup(t, "_opfview", name) {
		t.Errorf("after the role change: operator %v, view %v", inGroup(t, "_opfoperator", name), inGroup(t, "_opfview", name))
	}
	if err := a.do("PUT", "/api/users/"+name+"/password", map[string]string{"password": "Third-Password-3"}, nil); err != nil {
		t.Error(err)
	}
	markRan("usermod -p * *", t.Name())
	markRan("encrypt", t.Name())
	if err := a.do("PUT", "/api/users/"+name+"/lock", map[string]bool{"locked": true}, nil); err != nil {
		t.Error(err)
	}
	markRan("usermod -Z *", t.Name())
	if pw := passwdLine(t, name); !strings.HasPrefix(pw[1], "*") || !strings.HasSuffix(pw[9], "-") {
		t.Errorf("usermod -Z: OPF reads a locked account as a hash starting with * and a shell ending in -: %q", pw)
	}
	if err := a.do("PUT", "/api/users/"+name+"/lock", map[string]bool{"locked": false}, nil); err != nil {
		t.Error(err)
	}
	markRan("usermod -U *", t.Name())
	if err := a.do("DELETE", "/api/users/"+name, nil, nil); err != nil {
		t.Error(err)
	}
	markRan("userdel -r *", t.Name())
	if passwdLine(t, name) != nil {
		t.Errorf("%s is still in master.passwd", name)
	}
	if _, err := os.Stat("/home/" + name); err == nil {
		t.Errorf("userdel -r left /home/%s", name)
	}
	// OPF made its groups at its first start.
	markRan("groupadd -g * *", t.Name())
	for _, g := range []string{"_opfadmin", "_opfoperator", "_opfview"} {
		if !strings.Contains(readFile(t, "/etc/group"), g+":") {
			t.Errorf("no group %s", g)
		}
	}
	// groupdel: on a scratch group, as OPF would remove one of its own.
	must(t, "groupadd", "-g", "990", "_conformgrp")
	step(t, "groupdel *", []string{"groupdel", "_conformgrp"})
	// The audit log: OPF's sign-ins go to authlog through logger.
	markRan("logger -p auth.notice -t opf", t.Name())
	if !regexp.MustCompile(`(?m) opf: .*` + adminUser).MatchString(readFile(t, "/var/log/authlog")) {
		t.Error("/var/log/authlog has no line from OPF about the admin's sign-in")
	}
	apiGet(t, a, "/api/users")
}

func passwdLine(t *testing.T, name string) []string {
	t.Helper()
	for _, l := range strings.Split(readFile(t, "/etc/master.passwd"), "\n") {
		if f := strings.Split(l, ":"); f[0] == name {
			return f
		}
	}
	return nil
}

func inGroup(t *testing.T, group, name string) bool {
	t.Helper()
	for _, l := range strings.Split(readFile(t, "/etc/group"), "\n") {
		if f := strings.Split(l, ":"); len(f) == 4 && f[0] == group {
			return slices.Contains(strings.Split(f[3], ","), name)
		}
	}
	return false
}

// TestAuthpf: a user signs in over SSH from the client, authpf loads
// their rules, OPF sees the session, and ends it.
func TestAuthpf(t *testing.T) {
	a := configured(t)
	key := filepath.Join(t.TempDir(), "id")
	must(t, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key)
	pub := strings.TrimSpace(readFile(t, key+".pub"))
	var cfg appliance.Staged
	if err := a.do("GET", "/api/config", nil, &cfg); err != nil {
		t.Fatal(err)
	}
	m := cfg.Model
	if m.Firewall.Authpf == nil || len(m.Firewall.Authpf.SignIn) == 0 {
		t.Fatal("the everything model has no sign-in access")
	}
	m.Firewall.Authpf.Users = append(m.Firewall.Authpf.Users, pf.AuthpfUser{ID: "conform", Name: "conformuser", Description: "Conformance", Keys: []string{pub}})
	a.apply(t, m, "Add a sign-in user")
	if pw := passwdLine(t, "conformuser"); pw == nil || pw[9] != "/usr/sbin/authpf" {
		t.Fatalf("the sign-in account: %q", pw)
	}
	markRan("useradd -m -c * -s * -L default -p * ...", t.Name())

	sess := exec.Command("route", "-T"+clientRdom, "exec", "ssh", "-i", key, "-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null", "-o", "BatchMode=yes", "-tt", "conformuser@"+clientRoute)
	if err := sess.Start(); err != nil {
		t.Fatal(err)
	}
	defer sess.Process.Kill()
	var pid string
	for i := 0; i < 30 && pid == ""; i++ {
		time.Sleep(time.Second)
		ps := step(t, "ps -axww -o pid,lstart,command", []string{"ps", "-axww", "-o", "pid,lstart,command"})
		if m := regexp.MustCompile(`(?m)^\s*(\d+) .* -authpf: conformuser@` + regexp.QuoteMeta(clientAddr)).FindStringSubmatch(ps); m != nil {
			pid = m[1]
		}
	}
	if pid == "" {
		t.Fatal("no authpf process for the signed-in user")
	}
	anchors := step(t, "pfctl -a authpf -s Anchors", []string{"pfctl", "-a", "authpf", "-s", "Anchors"})
	if !strings.Contains(anchors, "authpf/conformuser("+pid+")") {
		t.Errorf("pfctl -a authpf -s Anchors: %q, want authpf/conformuser(%s)", anchors, pid)
	}
	var body struct {
		Sessions []map[string]any `json:"sessions"`
	}
	a.get(t, "/api/firewall/authpf/sessions", &body)
	if sessions := body.Sessions; len(sessions) != 1 {
		t.Errorf("OPF sees %d sessions: %v", len(sessions), sessions)
	}
	if err := a.do("POST", "/api/firewall/authpf/sessions/"+pid+"/end", nil, nil); err != nil {
		t.Errorf("ending the session: %v", err)
	}
	markRan("kill -TERM *", t.Name())
	time.Sleep(2 * time.Second)
	if strings.Contains(must(t, "pfctl", "-a", "authpf", "-s", "Anchors"), "conformuser") {
		t.Error("the user's anchor is still loaded after the session ended")
	}
}

// TestSystemDNS: the firewall's own resolver proposal on lo0, which
// resolvd puts first in resolv.conf.
func TestSystemDNS(t *testing.T) {
	a := configured(t)
	// A peer's name as the UI checks it: no such name, exit 2 and
	// nothing printed (offline, after the resolver gives up), then one
	// from /etc/hosts here (the suite's), saved last.
	if out := step(t, "getent hosts *", []string{"getent", "hosts", "nosuch.invalid"}, 2); out != "" {
		t.Errorf("getent hosts for no such name printed %q", out)
	}
	if out := step(t, "getent hosts *", []string{"getent", "hosts", "vpn.example.net"}); !strings.Contains(out, "192.0.2.81") {
		t.Errorf("getent hosts vpn.example.net: %q", out)
	}
	var found appliance.HostLookupResult
	if err := a.do("POST", "/api/dns/lookup-host", appliance.HostLookupRequest{Name: "vpn.example.net"}, &found); err != nil || !slices.Contains(found.Addresses, "192.0.2.81") || found.Error != "" {
		t.Errorf("OPF's lookup of vpn.example.net: %+v, %v", found, err)
	}
	// Offline, no server answers for a name the hosts file hasn't: OPF
	// says so after its 8 s, as netstart would wait.
	var none appliance.HostLookupResult
	err := a.do("POST", "/api/dns/lookup-host", appliance.HostLookupRequest{Name: "nosuch.invalid"}, &none)
	if err != nil || len(none.Addresses) != 0 || (internet() && none.Error != "") || none.Seconds > 10 {
		t.Errorf("OPF's lookup of nosuch.invalid (internet %v): %+v, %v", internet(), none, err)
	}
	step(t, "route nameserver lo0 ...", []string{"route", "nameserver", "lo0", "192.0.2.53"})
	time.Sleep(2 * time.Second)
	rc := sysinfo.ParseResolvConf(readFile(t, "/etc/resolv.conf"))
	if len(rc.Servers) == 0 || rc.Servers[0].Address != "192.0.2.53" || rc.Servers[0].From != "lo0" {
		t.Errorf("resolv.conf after the proposal: %+v", rc.Servers)
	}
	step(t, "route nameserver lo0 ...", []string{"route", "nameserver", "lo0"})
	time.Sleep(2 * time.Second)
	if strings.Contains(readFile(t, "/etc/resolv.conf"), "192.0.2.53") {
		t.Error("withdrawing the proposal left it in resolv.conf")
	}
}

// TestImportCompare: the take-over's comparison found the stock pf.conf
// the same; the stock example's pfctl -nvf output, against its Format.
func TestImportCompare(t *testing.T) {
	configured(t)
	if r := setup.report.Ruleset; r == nil || !r.Same {
		t.Errorf("the stock system's ruleset, as imported: %+v (%s)", r, setup.report.RulesetError)
	}
	step(t, "pfctl -nvf *", []string{"pfctl", "-nvf", "/etc/examples/pf.conf"})
}

// TestDiff: diff's exit statuses, which config.Diff reads: 0 the same,
// 1 different.
func TestDiff(t *testing.T) {
	owns(t)
	dir := t.TempDir()
	x, y := filepath.Join(dir, "x"), filepath.Join(dir, "y")
	os.WriteFile(x, []byte("a\n"), 0644)
	os.WriteFile(y, []byte("b\n"), 0644)
	out := step(t, "diff -u -L * -L * * *", []string{"diff", "-u", "-L", "old", "-L", "new", x, y}, 1)
	if !strings.HasPrefix(out, "--- old\n+++ new\n@@ ") {
		t.Errorf("diff -u: %q", out)
	}
	step(t, "diff -u -L * -L * * *", []string{"diff", "-u", "-L", "old", "-L", "new", x, x}, 0)
}

// TestTools: the diagnostics tools through internal/diag, as the parent
// runs them, against targets on this machine, with every word OPF can
// pass each tool.
func TestTools(t *testing.T) {
	configured(t)
	used := map[string]map[string]bool{}
	rs := &diag.Runs{Runner: oprun.Exec{}}
	for _, req := range []diag.Request{
		{Tool: "ping", Host: "127.0.0.1", Count: 2},
		{Tool: "ping", Host: "127.0.0.1", Count: 1, Size: 1400, DontFragment: true},
		{Tool: "ping", Host: "::1", Count: 1},
		{Tool: "traceroute", Host: clientAddr, MaxHops: 2},
		{Tool: "traceroute", Host: clientAddr, MaxHops: 2, Protocol: "icmp", Names: true},
		{Tool: "traceroute", Host: "::1", MaxHops: 1},
		{Tool: "traceroute", Host: "::1", MaxHops: 1, Protocol: "icmp"},
		{Tool: "dns", Name: "example.com"},
		{Tool: "dns", Name: clientRoute, Server: "127.0.0.1", DNSSEC: true},
		{Tool: "port", Host: "127.0.0.1", Port: 8443},
		{Tool: "port", Host: "127.0.0.1", Port: 53, Protocol: "udp"}, // unbound
		{Tool: "port", Host: "::1", Port: 22},                        // sshd
	} {
		r, err := rs.Start(req)
		if err != nil {
			t.Errorf("%+v: %v", req, err)
			continue
		}
		var done *diag.Run
		for deadline := time.Now().Add(time.Minute); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
			if done, _ = rs.Get(r.ID, 0); !done.Running {
				break
			}
		}
		argv := strings.Fields(done.Command)
		if used[argv[0]] == nil {
			used[argv[0]] = map[string]bool{}
		}
		for _, w := range argv[1:] {
			used[argv[0]][w] = true
		}
		out := strings.Join(done.Lines, "\n")
		key := "tool " + argv[0]
		if _, ok := Formats[key]; !ok {
			key = "tool " + strings.TrimSuffix(argv[0], "6")
		}
		if f, ok := Formats[key]; ok {
			save(t, f.Fixture, out)
			for _, p := range f.Check(out) {
				t.Errorf("%s: %s", done.Command, p)
			}
		}
		offline := req.Tool == "dns" && req.Server == "" && !internet() // nothing to resolve it
		if !offline && (done.ExitCode == nil || *done.ExitCode != 0) {
			code := "none"
			if done.ExitCode != nil {
				code = strconv.Itoa(*done.ExitCode)
			}
			t.Errorf("%s: exit %s, error %q:\n%s", done.Command, code, done.Error, out)
		}
	}
	// The words that need the internet (+trace, -A) are checked by
	// TestInternet.
	for _, tl := range Tools {
		for _, w := range tl.Words {
			// diag refuses don't-fragment for IPv6 before ping6's -D.
			unreachable := tl.Program == "ping6" && w == "-D"
			if !used[tl.Program][w] && !unreachable && w != "+trace" && w != "-A" && w != "-4" && w != "-6" && w != "-u" {
				t.Errorf("%s's word %q was never passed", tl.Program, w)
			}
		}
	}
}

// internet says whether the guest reaches the internet (the host gives
// it NAT only if set up to).
func internet() bool {
	_, code := run("ping", "-c", "1", "-w", "3", "9.9.9.9")
	return code == 0
}

// TestInternet: what needs the internet, when the guest has it: a
// download as OPF makes it, syspatch, and the tools' internet words.
func TestInternet(t *testing.T) {
	configured(t)
	if !internet() {
		for _, tmpl := range []string{"ftp -V -o - -- *", "syspatch -c"} {
			markRan(tmpl, "NOT RUN: the guest has no internet")
		}
		t.Skip("the guest has no internet; give the host NAT for 100.64.0.0/10 to run this")
	}
	out := step(t, "ftp -V -o - -- *", []string{"ftp", "-V", "-o", "-", "--", "https://cdn.openbsd.org/pub/OpenBSD/" + release() + "/SHA256"})
	if !strings.Contains(out, "SHA256 (") {
		t.Errorf("ftp's download: %.200q", out)
	}
	bad := step(t, "ftp -V -o - -- *", []string{"ftp", "-V", "-o", "-", "--", "https://cdn.openbsd.org/no/such/file"}, 1)
	if !strings.Contains(bad, "404") {
		t.Errorf("ftp's error for a missing file: %q (fetch.go shows its last line)", bad)
	}
	step(t, "syspatch -c", []string{"syspatch", "-c"}, 0)
	rs := &diag.Runs{Runner: oprun.Exec{}}
	for _, req := range []diag.Request{
		{Tool: "traceroute", Host: "9.9.9.9", MaxHops: 3, ASNumbers: true},
		{Tool: "dns", Name: "example.com", Trace: true},
		{Tool: "port", Host: "9.9.9.9", Port: 53, Protocol: "udp", Family: "ipv4"},
	} {
		if _, err := rs.Start(req); err != nil {
			t.Errorf("%+v: %v", req, err)
		}
	}
	_ = context.Background
}

// TestValidators runs every file OPF generates, for every model, through
// the real validator, as a commit does (config.Store.CheckContent), and
// checks each validator refuses a broken file, so a release where one
// accepts anything is caught too.
func TestValidators(t *testing.T) {
	owns(t)
	for _, dev := range append([]string{"vether0", "vether1", "pair0"}, modelDevices()...) {
		run("ifconfig", dev, "create")
	}
	st, stateDir := newStore(t)
	ctx := context.Background()
	// The trust anchor unbound-checkconf wants with DNSSEC, which OPF
	// makes before a commit's checks (appliance's prepare step).
	if _, err := os.Stat(pf.RootKeyPath); err != nil {
		run("unbound-anchor", "-v", "-a", pf.RootKeyPath)
	}
	checked := map[string]bool{}
	live := map[string]string{}
	for _, p := range []string{pf.RcPath, pf.SysctlPath, pf.HostsPath, "/etc/ssh/sshd_config"} {
		if data, err := os.ReadFile(p); err == nil {
			live[p] = string(data)
		}
	}
	for _, nm := range Models(devices) {
		files := Files(nm.Model, live)
		// The model's files staged together, as a commit has them: a
		// checker reads the others it names from there ({staged}), such
		// as unbound-checkconf the zone files.
		candidate := filepath.Join(stateDir, "candidate")
		os.RemoveAll(candidate)
		for _, f := range files {
			os.MkdirAll(filepath.Join(candidate, filepath.Dir(f.Path)), 0755)
			os.WriteFile(filepath.Join(candidate, f.Path), []byte(f.Content), 0644)
		}
		for _, f := range files {
			// Lists a table loads from a file: the download is the
			// appliance's, so stand in an empty one.
			for _, m := range tableFileRE.FindAllStringSubmatch(f.Content, -1) {
				if _, err := os.Stat(m[1]); err != nil {
					os.MkdirAll(filepath.Dir(m[1]), 0755)
					os.WriteFile(m[1], nil, 0644)
				}
			}
			// Zones the appliance downloads: stand in an empty one.
			for _, m := range zoneFileRE.FindAllStringSubmatch(f.Content, -1) {
				if _, err := os.Stat(filepath.Join(candidate, m[1])); err != nil {
					if _, err := os.Stat(m[1]); err != nil {
						os.MkdirAll(filepath.Join(candidate, filepath.Dir(m[1])), 0755)
						os.WriteFile(filepath.Join(candidate, m[1]), []byte(pf.RPZZone(nil, nil, nm.Model.DNS.BlockAnswer)), 0644)
					}
				}
			}
			file, err := st.LookupPath(f.Path)
			if err != nil || file.Check == nil {
				continue
			}
			out, ok, err := st.CheckContent(ctx, file.Name, []byte(f.Content))
			if err != nil {
				t.Errorf("%s %s: %v", nm.Name, f.Path, err)
				continue
			}
			if !ok {
				t.Errorf("%s: %s doesn't pass %s:\n%s\n--- the file:\n%s", nm.Name, f.Path, strings.Join(file.Check, " "), out, numbered(f.Content))
			}
			checked[strings.Join(file.Check, " ")] = true
		}
	}
	for c := range checked {
		for _, cmd := range Commands {
			if cmd.Matches(strings.Fields(c)) || strings.HasPrefix(c, "sh -c") && strings.Join(cmd.Argv, " ") == "sh -c * sh {} {staged} {root}" {
				markRan(strings.Join(cmd.Argv, " "), t.Name())
			}
		}
	}
	// httpd.conf isn't generated: the stock example must pass.
	out, ok, err := st.CheckContent(ctx, "httpd.conf", []byte(readFile(t, "/etc/examples/httpd.conf")))
	if err != nil || !ok {
		t.Errorf("httpd -n -f on the stock example: %v %s", err, out)
	}
	markRan("httpd -n -f {}", t.Name())
	// Each validator refuses a broken file.
	for _, f := range config.DefaultFiles() {
		if f.Check == nil || strings.Contains(f.Path, "*") {
			continue
		}
		out, ok, err := st.CheckContent(ctx, f.Name, []byte("this is not { a valid ; file\n\"\n"))
		if err == nil && ok {
			t.Errorf("%s's check (%s) passes a broken file: %s", f.Path, strings.Join(f.Check, " "), out)
		}
	}
}

var (
	tableFileRE = regexp.MustCompile(`persist file "([^"]+)"`)
	zoneFileRE  = regexp.MustCompile(`zonefile: "([^"]+)"`)
)

// newStore is a config store on this machine, with the real commands,
// for its file checks.
func newStore(t *testing.T) (*config.Store, string) {
	t.Helper()
	dir := t.TempDir()
	st, err := config.New(config.Options{Root: "/", StateDir: dir, Files: config.DefaultFiles(), Runner: oprun.Exec{}, ConfirmTimeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	return st, dir
}

func numbered(s string) string {
	var b strings.Builder
	for i, l := range strings.Split(s, "\n") {
		fmt.Fprintf(&b, "%4d  %s\n", i+1, l)
	}
	return b.String()
}

// modelDevices are the devices the models make (vlanN, wgN), which pf
// needs to exist to load rules on them.
func modelDevices() []string {
	seen := map[string]bool{}
	for _, nm := range Models(devices) {
		for _, i := range nm.Model.Interfaces {
			if !pf.PhysicalDevice(i.Device) {
				seen[i.Device] = true
			}
		}
	}
	return slices.Sorted(maps.Keys(seen))
}
