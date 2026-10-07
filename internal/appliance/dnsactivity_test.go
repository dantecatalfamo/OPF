package appliance

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dantecatalfamo/OPF/internal/activity"
	"github.com/dantecatalfamo/OPF/internal/config"
	"github.com/dantecatalfamo/OPF/internal/leases"
	"github.com/dantecatalfamo/OPF/internal/pf"
)

// activityEnv is the sample model with DNS activity on, devices too, an
// unbound log file of its own and a DHCP lease for 192.168.1.112.
func activityEnv(t *testing.T) (*env, string) {
	t.Helper()
	e := newEnv(t, time.Minute)
	dir := t.TempDir()
	e.m.DNSLog = filepath.Join(dir, "opf-dns.log")
	now := time.Now().UTC()
	stamp := func(t time.Time) string {
		return fmt.Sprintf("%d %s UTC", t.Weekday(), t.Format("2006/01/02 15:04:05"))
	}
	lf := filepath.Join(dir, "dhcpd.leases")
	lease := fmt.Sprintf("lease 192.168.1.112 { starts %s; ends %s; hardware ethernet 3C:22:FB:91:04:7D; client-hostname \"priya-mbp\"; }\n", stamp(now.Add(-time.Hour)), stamp(now.Add(time.Hour)))
	if err := os.WriteFile(lf, []byte(lease), 0644); err != nil {
		t.Fatal(err)
	}
	e.m.SetLeaseWatcher(&leases.Watcher{File: lf, Model: func() (*pf.Model, error) { c, err := e.m.Live(); return c.Model, err }, Resolver: &leases.Memory{}})
	m := e.live().Model
	m.DNS.Activity = &pf.DNSActivity{Enabled: true, Devices: true, Days: 7}
	if err := stageCommit(t, e, m); err != nil {
		t.Fatal(err)
	}
	return e, e.m.DNSLog
}

func appendLog(t *testing.T, path string, lines ...string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, l := range lines {
		fmt.Fprintln(f, l)
	}
}

func logLine(at time.Time, rest string) string {
	return fmt.Sprintf("[%d] unbound[123:0] %s", at.Unix(), rest)
}

func TestDNSActivityReadsTheLog(t *testing.T) {
	e, path := activityEnv(t)
	now := time.Now()
	appendLog(t, path,
		logLine(now, "reply: 192.168.1.112 Example.com. A IN NOERROR 0.010000 0 56"),
		logLine(now, "reply: 192.168.1.112 example.com. AAAA IN NOERROR 0.000000 1 56"),
		logLine(now, "info: rpz: applied [opf:list:ads] *.ads.example. rpz-nxdomain 192.168.1.112@5353 tracker.ads.example. A IN"),
		logLine(now, "reply: 192.168.1.112 tracker.ads.example. A IN NXDOMAIN 0.000000 0 44"),
		logLine(now, "reply: 10.8.0.2 nope.example. A IN NXDOMAIN 0.020000 0 44"),
		logLine(now, "reply: 127.0.0.1 pool.ntp.org. A IN NOERROR 0.020000 0 44"),
		logLine(now, "reply: 192.168.1.99 a.example. A IN SERVFAIL 1.000000 0 44"),
		logLine(now, "info: rpz: applied [someone:else] x. rpz-nxdomain 192.168.1.99@1 x. A IN"),
		logLine(now, "warning: continuing with less udp ports: 472"),
		logLine(now, "reply: 192.168.1.112 half.example. A IN NOERR"), // still being written: no newline below
	)
	// The last line has no end yet.
	data, _ := os.ReadFile(path)
	os.WriteFile(path, data[:len(data)-1], 0644)

	os.Chmod(path, 0o644)
	model := e.live().Model
	e.m.readDNSActivity(model, now)
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Errorf("the log is %v, not private", fi.Mode().Perm())
	}
	a, err := e.m.DNSActivity(DNSActivityRequest{Days: 1})
	if err != nil || !a.Enabled || a.Summary == nil {
		t.Fatalf("%+v %v", a, err)
	}
	want := map[string]int64{"queries": 6, "blocked": 1, "nxdomain": 1, "servfail": 1, "cached": 1}
	got := map[string]int64{"queries": a.Total.Queries, "blocked": a.Total.Blocked, "nxdomain": a.Total.NXDomain, "servfail": a.Total.ServFail, "cached": a.Total.Cached}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %d, want %d", k, got[k], v)
		}
	}
	if a.ByList["ads"] != 1 || len(a.Blocked) != 1 || a.Blocked[0].Name != "tracker.ads.example" || a.Blocked[0].Entry != "*.ads.example" {
		t.Errorf("blocks: %+v %+v", a.ByList, a.Blocked)
	}
	if len(a.Names) == 0 || a.Names[0].Name != "example.com" || a.Names[0].Count != 2 {
		t.Errorf("names: %+v", a.Names)
	}
	keys := map[string]ActivityDevice{}
	for _, d := range a.Devices {
		keys[d.Key] = a.DeviceInfo[d.Key]
	}
	if d, ok := keys["mac:3c:22:fb:91:04:7d"]; !ok || d.Name != "priya-mbp" || d.Kind != "device" {
		t.Errorf("the leased device: %+v (%+v)", d, keys)
	}
	if d := keys["vpn:p1"]; d.Kind != "vpn" || d.Name != "Priya phone" {
		t.Errorf("the VPN device: %+v", d)
	}
	if d := keys[deviceFirewall]; d.Kind != "firewall" {
		t.Errorf("the firewall: %+v", d)
	}
	if d := keys["ip:192.168.1.99"]; d.Kind != "address" {
		t.Errorf("an unknown address: %+v", d)
	}
	dev, err := e.m.DNSDeviceActivity(DNSActivityRequest{Days: 1, Device: "mac:3c:22:fb:91:04:7d"})
	if err != nil || dev.Total.Queries != 3 || dev.Total.Blocked != 1 || dev.Address != "192.168.1.112" || dev.Name != "priya-mbp" {
		t.Errorf("device: %+v %v", dev, err)
	}
	// When and by whom one of the network's names was asked for.
	n, err := e.m.DNSNameActivity(DNSActivityRequest{Days: 1, List: activity.ListNames, Name: "Example.com"})
	if err != nil || n.Count != 2 || len(n.Devices) != 1 || n.DeviceInfo[n.Devices[0].Key].Name != "priya-mbp" || len(n.Hours) != 1 {
		t.Errorf("name: %+v %v", n, err)
	}
	if b, err := e.m.DNSNameActivity(DNSActivityRequest{Days: 1, List: activity.ListBlocked, Name: "tracker.ads.example"}); err != nil || b.BlockList != "ads" {
		t.Errorf("blocked name: %+v %v", b, err)
	}
	if _, err := e.m.DNSNameActivity(DNSActivityRequest{Days: 1, List: "everything", Name: "example.com"}); code(err) != CodeInvalid {
		t.Errorf("a list that isn't one: %v", err)
	}
	// The blocked names come from the counts while unbound logs here.
	if b, _ := e.m.DNSBlocked(); b.Blocked != 1 || b.ByList["ads"] != 1 || len(b.Names) != 1 {
		t.Errorf("DNSBlocked: %+v", b)
	}

	// The half line, finished, is read next time; nothing twice.
	appendLog(t, path, "R 0.000000 0 44")
	e.m.readDNSActivity(model, now)
	if a, _ := e.m.DNSActivity(DNSActivityRequest{Days: 1}); a.Total.Queries != 7 {
		t.Errorf("after the rest of the line: %d queries", a.Total.Queries)
	}
	// Saved and read again (a restart): the place in the file too.
	if err := e.m.SaveDNSActivity(); err != nil {
		t.Fatal(err)
	}
	m2, _ := New(e.m.store)
	m2.DNSLog = path
	m2.readDNSActivity(model, now)
	if a, _ := m2.DNSActivity(DNSActivityRequest{Days: 1}); a.Total.Queries != 7 {
		t.Errorf("after a restart: %d queries", a.Total.Queries)
	}

	// Without devices, theirs go; off, everything goes, the log too.
	model.DNS.Activity.Devices = false
	e.m.readDNSActivity(model, now)
	if a, _ := e.m.DNSActivity(DNSActivityRequest{Days: 1}); a.Summary == nil || len(a.Summary.Devices) != 0 || a.Total.Queries != 7 {
		t.Errorf("devices off: %+v", a.Summary)
	}
	model.DNS.Activity.Enabled = false
	e.m.readDNSActivity(model, now)
	if _, err := os.Stat(path); err == nil {
		t.Error("the log is still there")
	}
	if _, err := os.Stat(e.m.store.StatePath(activityFile)); err == nil {
		t.Error("the saved activity is still there")
	}
}

// Large and read to its end, the log is emptied; a new file (unbound
// made it again) is read from its start.
func TestDNSActivityEmptiesTheLog(t *testing.T) {
	e, path := activityEnv(t)
	model := e.live().Model
	now := time.Now()
	line := logLine(now, "reply: 192.168.1.112 example.com. A IN NOERROR 0.010000 0 56")
	n := truncateAt/len(line) + 1
	appendLog(t, path, strings.Repeat(line+"\n", n-1)+line)
	e.m.readDNSActivity(model, now)
	if fi, err := os.Stat(path); err != nil || fi.Size() != 0 {
		t.Fatalf("not emptied: %v %v", fi.Size(), err)
	}
	appendLog(t, path, line)
	e.m.readDNSActivity(model, now)
	os.Remove(path)
	appendLog(t, path, line, line)
	e.m.readDNSActivity(model, now)
	if a, _ := e.m.DNSActivity(DNSActivityRequest{Days: 1}); a.Total.Queries != int64(n+3) {
		t.Errorf("%d queries, want %d", a.Total.Queries, n+3)
	}
}

func TestDNSActivityIsOptIn(t *testing.T) {
	m := sample(t)
	if strings.Contains(pf.GenerateUnboundConf(m), "log-replies") {
		t.Error("the sample logs every answer")
	}
	m.DNS.Activity = &pf.DNSActivity{Enabled: true, Days: 7}
	conf := pf.GenerateUnboundConf(m)
	for _, l := range []string{"use-syslog: no", `logfile: "` + pf.DNSLogPath + `"`, "log-replies: yes", "log-tag-queryreply: yes"} {
		if !strings.Contains(conf, l) {
			t.Errorf("unbound.conf hasn't %q", l)
		}
	}
	// Turning it on or off restarts unbound, which a reload wouldn't
	// take back to syslog; any other change still reloads it.
	off := pf.GenerateUnboundConf(sample(t))
	var restartIf func(before, after []byte) bool
	for _, f := range config.DefaultFiles() {
		if f.Path == "/var/unbound/etc/unbound.conf" {
			restartIf = f.RestartIf
		}
	}
	if restartIf == nil || !restartIf([]byte(off), []byte(conf)) || !restartIf([]byte(conf), []byte(off)) || restartIf([]byte(conf), []byte(conf+"\n")) {
		t.Error("unbound.conf's RestartIf doesn't see activity turned on or off")
	}
	for _, bad := range []pf.DNSActivity{{Enabled: true, Days: 0}, {Enabled: true, Days: pf.MaxActivityDays + 1}, {Devices: true, Days: 7}} {
		m.DNS.Activity = &bad
		if len(pf.Validate(m)) == 0 {
			t.Errorf("%+v accepted", bad)
		}
	}
}

// A device that has only just asked (its lease newer than the last look)
// is still kept under its MAC address, not its address.
func TestDNSActivityLooksUpNewDevices(t *testing.T) {
	e, path := activityEnv(t)
	model := e.live().Model
	now := time.Now()
	appendLog(t, path, logLine(now, "reply: 192.168.1.112 a.example. A IN NOERROR 0.010000 0 56"))
	e.m.readDNSActivity(model, now)

	stamp := func(t time.Time) string {
		return fmt.Sprintf("%d %s UTC", t.Weekday(), t.UTC().Format("2006/01/02 15:04:05"))
	}
	f, _ := os.OpenFile(e.m.leases.File, os.O_APPEND|os.O_WRONLY, 0644)
	fmt.Fprintf(f, "lease 192.168.1.140 { starts %s; ends %s; hardware ethernet 02:00:00:00:00:aa; client-hostname \"new-phone\"; }\n", stamp(now.Add(-time.Minute)), stamp(now.Add(time.Hour)))
	f.Close()
	appendLog(t, path, logLine(now, "reply: 192.168.1.140 b.example. A IN NOERROR 0.010000 0 56"))
	e.m.readDNSActivity(model, now.Add(missEvery))
	a, _ := e.m.DNSActivity(DNSActivityRequest{Days: 1})
	for _, d := range a.Devices {
		if d.Key == "ip:192.168.1.140" {
			t.Errorf("kept under its address: %+v", a.Devices)
		}
	}
	if a.DeviceInfo["mac:02:00:00:00:00:aa"].Name != "new-phone" {
		t.Errorf("not under its MAC address: %+v", a.DeviceInfo)
	}
}
