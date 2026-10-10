package conformance

// Every command in the registry, run for real on the configured
// firewall: its exit status, its output against its Format (saved as a
// capture), and what OPF makes of it through its API.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// ran records the registry templates the suite ran, for TestZCoverage.
var ran = struct {
	sync.Mutex
	m map[string]string // template → the test that ran it, or why it didn't
}{m: map[string]string{}}

func markRan(tmpl, by string) {
	ran.Lock()
	defer ran.Unlock()
	if ran.m[tmpl] == "" {
		ran.m[tmpl] = by
	}
}

// exits are the exit statuses a command may end with besides 0.
var exits = map[string][]int{
	"swapctl -lk":                       {1}, // no swap
	"rcctl ls started":                  {1}, // its list is still right
	"ntpctl -s all":                     {1}, // ntpd not running
	"ping -n -q -c 3 -i 0.2 -w 1 -- *":  {1}, // nothing answered
	"ping6 -n -q -c 3 -i 0.2 -w 1 -- *": {1},
	"ls -ln ...":                        {1}, // some rotated copies aren't there yet
}

// instances gives the command lines the suite runs for a template with
// values OPF chooses at run time; a template without "*" or "..." runs
// as it is.
func instances(t *testing.T, tmpl string) [][]string {
	t.Helper()
	logs := []string{"/var/log/messages", "/var/log/daemon", "/var/log/authlog", "/var/log/maillog"}
	switch tmpl {
	case "ping -n -q -c 3 -i 0.2 -w 1 -- *":
		return [][]string{{"ping", "-n", "-q", "-c", "3", "-i", "0.2", "-w", "1", "--", defaultGateway(&recorder{T: t})}}
	case "ping6 -n -q -c 3 -i 0.2 -w 1 -- *":
		return [][]string{{"ping6", "-n", "-q", "-c", "3", "-i", "0.2", "-w", "1", "--", "::1"}}
	case "ls -ln ...":
		return [][]string{append([]string{"ls", "-ln", "/var/log/pflog"}, append(logs, "/var/log/daemon.0.gz", "/var/log/messages.0.gz")...)}
	case "tail -n * *":
		var out [][]string
		for _, l := range logs {
			out = append(out, []string{"tail", "-n", "5000", l})
		}
		return append(out, []string{"tail", "-n", "20000", "/var/log/daemon"})
	}
	if strings.Contains(tmpl, "*") || strings.Contains(tmpl, "...") {
		t.Fatalf("no instance of %q: add one to instances", tmpl)
	}
	return [][]string{strings.Fields(tmpl)}
}

// runRegistered runs every Read command whose Test is test.
func runRegistered(t *testing.T, test string) {
	t.Helper()
	for _, c := range Commands {
		if c.Test != test || c.Kind != Read {
			continue
		}
		tmpl := strings.Join(c.Argv, " ")
		for _, argv := range instances(t, tmpl) {
			out, code := run(argv...)
			if code != 0 && !slices.Contains(exits[tmpl], code) {
				t.Errorf("%s: exit %d:\n%s", strings.Join(argv, " "), code, out)
				continue
			}
			checkOutput(t, tmpl, out)
		}
		markRan(tmpl, test)
	}
}

// apiGet fetches a resource and fails on an error OPF reports in it.
func apiGet(t *testing.T, a *api, path string) map[string]any {
	t.Helper()
	var v map[string]any
	if err := a.do("GET", path, nil, &v); err != nil {
		t.Errorf("GET %s: %v", path, err)
		return nil
	}
	for _, k := range []string{"error", "errors"} {
		switch e := v[k].(type) {
		case string:
			if e != "" {
				t.Errorf("GET %s: error %q", path, e)
			}
		case []any:
			if len(e) > 0 {
				t.Errorf("GET %s: errors %v", path, e)
			}
		}
	}
	data, _ := json.MarshalIndent(v, "", "  ")
	save(t, "api"+strings.NewReplacer("/", "_", "?", "_", "=", "_").Replace(path)+".json", string(data)+"\n")
	return v
}

// TestStatusReads: the dashboard's, graphs' and storage's commands.
func TestStatusReads(t *testing.T) {
	a := configured(t)
	runRegistered(t, "TestStatusReads")
	for _, p := range []string{"/api/status", "/api/system", "/api/network/interfaces", "/api/network/gateways",
		"/api/diagnostics/storage", "/api/logs/system/messages", "/api/logs/system/daemon", "/api/logs/system/authlog",
		"/api/logs/system/maillog", "/api/logs/system/dmesg", "/api/metrics?range=3600", "/api/events"} {
		apiGet(t, a, p)
	}
}

// TestNetworkReads: ARP, routes and the egress group.
func TestNetworkReads(t *testing.T) {
	a := configured(t)
	runRegistered(t, "TestNetworkReads")
	arp := apiGet(t, a, "/api/network/arp")
	if b, _ := json.Marshal(arp); !strings.Contains(string(b), clientAddr) {
		t.Errorf("OPF's ARP table doesn't have the client %s: %s", clientAddr, b)
	}
	routes := apiGet(t, a, "/api/network/routes")
	if b, _ := json.Marshal(routes); !strings.Contains(string(b), `"default"`) {
		t.Errorf("OPF's routes have no default route: %s", b)
	}
	apiGet(t, a, "/api/devices")
}

// TestPfReads: pf's state, statistics, rules, labels and log.
func TestPfReads(t *testing.T) {
	a := configured(t)
	runRegistered(t, "TestPfReads")
	for _, p := range []string{"/api/pf/status", "/api/pf/stats", "/api/pf/states", "/api/pf/rules/counters",
		"/api/firewall/tables", "/api/logs/firewall", "/api/traffic"} {
		apiGet(t, a, p)
	}
	// The log shows what's logged since the rules were last loaded, so
	// the client's blocked traffic is sent now, and pflogd writes it out
	// (SIGALRM flushes its buffer).
	run("route", "-T"+clientRdom, "exec", "nc", "-z", "-w", "1", clientRoute, "9")
	run("pkill", "-ALRM", "-x", "pflogd")
	time.Sleep(2 * time.Second)
	if b, _ := json.Marshal(apiGet(t, a, "/api/logs/firewall")); !strings.Contains(string(b), clientAddr) {
		t.Errorf("the firewall log has nothing from the client's blocked traffic: %.500s", b)
	}
}

// files in the capture directory, for a test that wants to compare.
func captured(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(outDir(), "captures", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
