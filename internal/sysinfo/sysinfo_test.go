package sysinfo

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "rewrite the golden files")

// Output captured on real systems, by release (openbsd-other: real
// output from systems whose release wasn't recorded), and output written by
// hand for what the capture host doesn't have (wg, vlan, carp; pflog
// entries). Handwritten fixtures are checked on real OpenBSD later
// (TODO.md › Verify on real OpenBSD).
var fixtureDirs = []string{"openbsd-7.9", "openbsd-other", "handwritten"}

func fixture(t *testing.T, dir, name string) (string, bool) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", dir, name))
	if os.IsNotExist(err) {
		return "", false
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(b), true
}

// golden compares v, as JSON, with testdata/<dir>/<name>.golden.json.
func golden(t *testing.T, dir, name string, v any) {
	t.Helper()
	got, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	path := filepath.Join("testdata", dir, name+".golden.json")
	if *update {
		if err := os.WriteFile(path, got, 0644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test -update to create it)", err)
	}
	if string(got) != string(want) {
		t.Errorf("%s: got\n%s\nwant\n%s", path, got, want)
	}
}

// eachFixture runs f for every fixture directory that has name.
func eachFixture(t *testing.T, name string, f func(t *testing.T, dir, out string)) {
	t.Helper()
	found := false
	for _, dir := range fixtureDirs {
		if out, ok := fixture(t, dir, name); ok {
			found = true
			t.Run(dir, func(t *testing.T) { f(t, dir, out) })
		}
	}
	if !found {
		t.Fatalf("no fixture %s", name)
	}
}

func TestParseSysctl(t *testing.T) {
	eachFixture(t, "sysctl_kern.txt", func(t *testing.T, dir, out string) {
		v := ParseSysctl(out)
		if v["kern.osrelease"] != "7.9" || v["kern.hostname"] != "openbsd-dev.my.domain" {
			t.Errorf("got %q", v)
		}
		want := "OpenBSD 7.9 (GENERIC.MP) #15: Sun Sep 27 02:47:36 MDT 2026\n    root@syspatch-79-amd64.openbsd.org:/usr/src/sys/arch/amd64/compile/GENERIC.MP"
		if v["kern.version"] != want {
			t.Errorf("kern.version = %q, want %q", v["kern.version"], want)
		}
	})
	v := ParseSysctl("hw.model=x\nsysctl: kern.nope: value is not available\nhw.ncpu=4\n")
	if len(v) != 2 || v["hw.ncpu"] != "4" {
		t.Errorf("got %q", v)
	}
}

func TestParseCPU(t *testing.T) {
	eachFixture(t, "sysctl_kern_cp_time.txt", func(t *testing.T, dir, out string) {
		ticks, err := ParseCPUTicks(ParseSysctl(out)["kern.cp_time"])
		if err != nil {
			t.Fatal(err)
		}
		if ticks != (CPUTicks{301, 0, 217, 39, 12, 42423}) {
			t.Errorf("got %+v", ticks)
		}
	})
	a := CPUTicks{User: 100, System: 100, Idle: 800}
	b := CPUTicks{User: 150, System: 110, Idle: 840}
	u, ok := b.Usage(a)
	if !ok || u.User != 50 || u.System != 10 || u.Idle != 40 || u.Busy() != 60 {
		t.Errorf("usage = %+v, %v", u, ok)
	}
	if _, ok := a.Usage(b); ok {
		t.Error("counters going backwards should give no usage")
	}
	if _, ok := a.Usage(a); ok {
		t.Error("no time passing should give no usage")
	}
	for _, bad := range []string{"", "1,2,3", "1,2,3,4,5,x", "1,2,3,4,5,6,7"} {
		if _, err := ParseCPUTicks(bad); err == nil {
			t.Errorf("ParseCPUTicks(%q) should fail", bad)
		}
	}
}

func TestParseLoadAndBoot(t *testing.T) {
	eachFixture(t, "sysctl_vm_loadavg.txt", func(t *testing.T, dir, out string) {
		l, err := ParseLoadavg(ParseSysctl(out)["vm.loadavg"])
		if err != nil || l != [3]float64{0.01, 0.04, 0.02} {
			t.Errorf("got %v, %v", l, err)
		}
	})
	eachFixture(t, "sysctl_kern_boottime.txt", func(t *testing.T, dir, out string) {
		b, err := ParseBoottime(ParseSysctl(out)["kern.boottime"], time.UTC)
		if err != nil || !b.Equal(time.Date(2026, 9, 29, 16, 9, 55, 0, time.UTC)) {
			t.Errorf("got %v, %v", b, err)
		}
	})
	b, err := ParseBoottime("Thu Oct  1 09:05:00 2026", time.UTC)
	if err != nil || b.Day() != 1 {
		t.Errorf("space-padded day: %v, %v", b, err)
	}
}

func TestParseSensors(t *testing.T) {
	eachFixture(t, "sysctl_hw_sensors.txt", func(t *testing.T, dir, out string) {
		golden(t, dir, "sysctl_hw_sensors", ParseSensors(out))
	})
	s := ParseSensors("hw.sensors.cpu0.temp0=45.50 degC\nhw.sensors.lm1.volt0=3.31 VDC (VCore A), WARNING\nhw.sensors.sd0.drive0=online (sd0), OK\n")
	if len(s) != 3 || *s[0].Number != 45.5 || s[0].Unit != "degC" || s[1].Description != "VCore A" || s[1].Status != "WARNING" || s[2].Value != "online" || s[2].Number != nil {
		b, _ := json.Marshal(s)
		t.Errorf("got %s", b)
	}
}

func TestParseMemoryDisks(t *testing.T) {
	eachFixture(t, "vmstat_-s.txt", func(t *testing.T, dir, out string) {
		phys, _ := fixture(t, dir, "sysctl_hw_physmem.txt")
		n, err := strconv.ParseUint(ParseSysctl(phys)["hw.physmem"], 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		m, err := ParseVmstatMemory(out, n)
		if err != nil {
			t.Fatal(err)
		}
		golden(t, dir, "vmstat_-s", m)
	})
	if _, err := ParseVmstatMemory("nonsense", 1); err == nil {
		t.Error("vmstat output without a page size should fail")
	}
	eachFixture(t, "swapctl_-lk.txt", func(t *testing.T, dir, out string) {
		golden(t, dir, "swapctl_-lk", ParseSwapctl(out))
	})
	if s := ParseSwapctl("swapctl: no swap devices configured\n"); s != (Swap{}) {
		t.Errorf("no swap: %+v", s)
	}
	two := "Device      1K-blocks     Used    Avail Capacity  Priority\n/dev/sd0b 100 10 90 10% 0\n/dev/sd1b 100 20 80 20% 0\nTotal 200 30 170 15%\n"
	if s := ParseSwapctl(two); s != (Swap{200 * 1024, 30 * 1024}) {
		t.Errorf("two devices: %+v", s)
	}
	eachFixture(t, "df_-kP.txt", func(t *testing.T, dir, out string) {
		golden(t, dir, "df_-kP", ParseDf(out))
	})
	d := ParseDf("Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/sd1i 10 5 5 50% /mnt/my disk\n")
	if len(d) != 1 || d[0].Mount != "/mnt/my disk" {
		t.Errorf("mount with a space: %+v", d)
	}
}

func TestParseIfconfig(t *testing.T) {
	eachFixture(t, "ifconfig_-A.txt", func(t *testing.T, dir, out string) {
		golden(t, dir, "ifconfig_-A", ParseIfconfig(out))
	})
}

func TestParseNetstat(t *testing.T) {
	eachFixture(t, "netstat_-ibn.txt", func(t *testing.T, dir, out string) {
		pkts, _ := fixture(t, dir, "netstat_-in.txt")
		golden(t, dir, "netstat", ParseNetstatIfaces(out, pkts))
	})
}

func TestParsePing(t *testing.T) {
	eachFixture(t, "ping_ok.txt", func(t *testing.T, dir, out string) {
		p, ok := ParsePing(out)
		if !ok || p != (Ping{Sent: 3, Received: 3, MinMs: 0.134, AvgMs: 0.188, MaxMs: 0.230}) {
			t.Errorf("got %+v, %v", p, ok)
		}
	})
	eachFixture(t, "ping_lost.txt", func(t *testing.T, dir, out string) {
		p, ok := ParsePing(out)
		if !ok || p != (Ping{Sent: 2, LossPct: 100}) {
			t.Errorf("got %+v, %v", p, ok)
		}
	})
	// As root, with the 0.2 s interval the gateway check uses.
	eachFixture(t, "ping_fast.txt", func(t *testing.T, dir, out string) {
		if p, ok := ParsePing(out); !ok || p.Received != 3 || p.AvgMs != 0.184 {
			t.Errorf("got %+v, %v", p, ok)
		}
	})
	if _, ok := ParsePing("ping: unknown host\n"); ok {
		t.Error("no statistics should be not ok")
	}
}

// The parsers take output from programs that may change format; none of
// them may panic, whatever they're given.
func FuzzParsers(f *testing.F) {
	for _, dir := range fixtureDirs {
		ents, _ := os.ReadDir(filepath.Join("testdata", dir))
		for _, e := range ents {
			if filepath.Ext(e.Name()) == ".txt" {
				b, _ := os.ReadFile(filepath.Join("testdata", dir, e.Name()))
				f.Add(string(b))
			}
		}
	}
	f.Fuzz(func(t *testing.T, s string) {
		ParseSysctl(s)
		ParseCPUTicks(s)
		ParseLoadavg(s)
		ParseBoottime(s, time.UTC)
		ParseSensors(s)
		ParseVmstatMemory(s, 1)
		ParseSwapctl(s)
		ParseDf(s)
		ParseIfconfig(s)
		ParseNetstatIfaces(s, s)
		ParsePing(s)
		ParseNtpctl(s)
		ParseSyspatch(s)
		ParsePfInfo(s)
		ParsePfMemory(s)
		ParsePfStates(s, 10)
		ParsePfRules(s)
		ParsePflog(s, time.Now(), 10)
		ParseUnboundStats(s)
		ParseRPZLog(s, time.Now())
		ParseProcessRSS(s, "unbound")
		ParseSyslog(s, time.Now())
	})
}

func TestParseSyspatch(t *testing.T) {
	eachFixture(t, "syspatch_-c.txt", func(t *testing.T, dir, out string) {
		p := ParseSyspatch(out)
		if len(p) != 16 || p[0] != "015_smtpd" || p[15] != "030_uidrange" {
			t.Errorf("got %q", p)
		}
	})
	// Up to date: syspatch prints nothing.
	if p := ParseSyspatch(""); p == nil || len(p) != 0 {
		t.Errorf("empty: %#v", p)
	}
	if p := ParseSyspatch("syspatch: Error retrieving https://cdn.openbsd.org/...\n"); len(p) != 0 {
		t.Errorf("error text: %q", p)
	}
}

func TestParseNtpctl(t *testing.T) {
	eachFixture(t, "ntpctl_-s_all.txt", func(t *testing.T, dir, out string) {
		golden(t, dir, "ntpctl_-s_all", must(ParseNtpctl(out)))
	})
	u, ok := ParseNtpctl("0/2 peers valid, clock unsynced\n")
	if !ok || u.Synced || u.OffsetMs != nil {
		t.Errorf("unsynced: %+v", u)
	}
	if _, ok := ParseNtpctl("ntpctl: connect: /var/run/ntpd.sock: No such file or directory\n"); ok {
		t.Error("ntpd not running should be not ok")
	}
}

func must[T any](v T, ok bool) T {
	if !ok {
		panic("not ok")
	}
	return v
}

func TestParsePfInfo(t *testing.T) {
	eachFixture(t, "pfctl_-v_-s_info.txt", func(t *testing.T, dir, out string) {
		golden(t, dir, "pfctl_-v_-s_info", must(ParsePfInfo(out)))
	})
	p, ok := ParsePfInfo("Status: Disabled                               Debug: err\n")
	if !ok || p.Enabled {
		t.Errorf("disabled: %+v", p)
	}
	if _, ok := ParsePfInfo("pfctl: /dev/pf: Permission denied\n"); ok {
		t.Error("an error message should be not ok")
	}
	if m := ParsePfMemory(fixtureOr(t, "pfctl_-s_memory.txt")); m["states"] != 100000 || m["table-entries"] != 200000 {
		t.Errorf("memory: %v", m)
	}
}

// fixtureOr returns the first fixture directory's copy of name.
func fixtureOr(t *testing.T, name string) string {
	for _, dir := range fixtureDirs {
		if out, ok := fixture(t, dir, name); ok {
			return out
		}
	}
	t.Fatalf("no fixture %s", name)
	return ""
}

func TestParsePfStates(t *testing.T) {
	eachFixture(t, "pfctl_-vv_-s_states.txt", func(t *testing.T, dir, out string) {
		s, trunc := ParsePfStates(out, 1000)
		if trunc {
			t.Error("truncated")
		}
		golden(t, dir, "pfctl_-vv_-s_states", s)
	})
	out := fixtureOr(t, "pfctl_-vv_-s_states.txt")
	if s, trunc := ParsePfStates(out, 2); len(s) != 2 || !trunc {
		t.Errorf("max 2: %d, %v", len(s), trunc)
	}
	// Without its id line a state can't be killed, so it's left out.
	if s, _ := ParsePfStates("all tcp 1.2.3.4:1 -> 5.6.7.8:2       ESTABLISHED:ESTABLISHED\n   age 00:00:01, expires in 00:00:02, 1:1 pkts, 1:1 bytes, rule 1\n", 10); len(s) != 0 {
		t.Errorf("no id: %+v", s)
	}
	for _, bad := range []string{"all tcp", "all tcp x -> y z", "all tcp 1.2.3.4:1 (5.6.7.8:2 -> 9.9.9.9:3 S", "all tcp 1.2.3.4:99999 -> 5.6.7.8:1 S"} {
		if _, ok := parseStateLine(bad); ok {
			t.Errorf("parseStateLine(%q) should fail", bad)
		}
	}
}

func TestParsePfRules(t *testing.T) {
	eachFixture(t, "pfctl_-vv_-s_rules.txt", func(t *testing.T, dir, out string) {
		golden(t, dir, "pfctl_-vv_-s_rules", ParsePfRules(out))
	})
}

func TestParsePflog(t *testing.T) {
	now := time.Date(2026, 9, 29, 17, 0, 0, 0, time.UTC)
	eachFixture(t, "tcpdump_pflog.txt", func(t *testing.T, dir, out string) {
		golden(t, dir, "tcpdump_pflog", ParsePflog(out, now, 100))
	})
	out, _ := fixture(t, "handwritten", "tcpdump_pflog.txt")
	if es := ParsePflog(out, now, 2); len(es) != 2 || es[1].Reason != "short" {
		t.Errorf("last 2: %+v", es)
	}
	// A December entry read in January is last year's.
	e, ok := parsePflogLine("Dec 31 23:59:59.000000 rule 0/(match) block in on em0: 1.2.3.4.1 > 5.6.7.8.2: S 1:1(0) win 1", time.Date(2027, 1, 1, 0, 0, 5, 0, time.UTC))
	if !ok || e.Time.Year() != 2026 {
		t.Errorf("year: %v %v", e.Time, ok)
	}
	// pf's default rule, as a real capture has it.
	real, _ := fixture(t, "openbsd-7.9", "tcpdump_pflog.txt")
	if es := ParsePflog(real, now, 10); len(es) != 2 || es[0].Rule != -1 || es[0].Reason != "ip-option" || es[0].Source != "::" || es[0].Destination != "ff02::16" {
		t.Errorf("rule def: %+v", es)
	}
	// Space-padded days.
	if e, ok := parsePflogLine("Oct  1 01:02:03.000004 rule 1/(match) pass out on em0: 1.2.3.4 > 5.6.7.8: icmp: echo request", now); !ok || e.Time.Day() != 1 || e.Proto != "icmp" {
		t.Errorf("padded day: %+v %v", e, ok)
	}
}

func TestParseUnboundStats(t *testing.T) {
	eachFixture(t, "unbound-control_stats_noreset.txt", func(t *testing.T, dir, out string) {
		s, ok := ParseUnboundStats(out)
		if !ok {
			t.Fatal("not read")
		}
		golden(t, dir, "unbound-control_stats_noreset", s)
	})
	// Two queries blocked with 0.0.0.0 and one let through, on 7.9.
	out, _ := fixture(t, "openbsd-7.9", "unbound-control_stats_noreset.txt")
	if s, _ := ParseUnboundStats(out); s.Blocked() != 3 || s.RPZ["rpz-passthru"] != 1 || !s.Extended || s.Answers["NXDOMAIN"] != 1 {
		t.Errorf("7.9: %+v", s)
	}
	// Without extended-statistics there are only the totals.
	s, ok := ParseUnboundStats("total.num.queries=10\ntotal.num.cachehits=4\ntime.up=5.5\n")
	if !ok || s.Extended || s.Queries != 10 || s.CacheHits != 4 || s.Uptime != 5.5 || s.Blocked() != 0 {
		t.Errorf("basic: %+v %v", s, ok)
	}
	if _, ok := ParseUnboundStats("error: connect to /var/run/unbound.sock: No such file or directory\n"); ok {
		t.Error("an error read as stats")
	}
}

func TestParseRPZLog(t *testing.T) {
	now := time.Date(2026, 9, 29, 17, 0, 0, 0, time.UTC)
	eachFixture(t, "daemon_rpz.txt", func(t *testing.T, dir, out string) {
		golden(t, dir, "daemon_rpz", ParseRPZLog(out, now))
	})
}

func TestParseProcessRSS(t *testing.T) {
	eachFixture(t, "ps_-A_-o_rss_comm.txt", func(t *testing.T, dir, out string) {
		if n, ok := ParseProcessRSS(out, "unbound"); !ok || n != 782744*1024 {
			t.Errorf("got %d %v", n, ok)
		}
	})
	if _, ok := ParseProcessRSS(" 12 init\n", "unbound"); ok {
		t.Error("found a process that isn't there")
	}
}

func TestParseSyslog(t *testing.T) {
	now := time.Date(2026, 9, 30, 17, 0, 0, 0, time.UTC)
	eachFixture(t, "syslog_messages.txt", func(t *testing.T, dir, out string) {
		golden(t, dir, "syslog_messages", ParseSyslog(out, now))
	})
}
