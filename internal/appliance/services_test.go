package appliance

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dantecatalfamo/OPF/internal/pf"
)

// rcctlRunner answers rcctl as the test VM does, and records the rest.
type rcctlRunner struct {
	mu   sync.Mutex
	cmds []string
}

func (r *rcctlRunner) Run(_ context.Context, argv ...string) ([]byte, error) {
	cmd := strings.Join(argv, " ")
	switch cmd {
	case "rcctl ls all":
		return []byte("cron\ndhcpd\nmypkg\nntpd\nopf\npf\naccounting\nsndiod\nsshd\nunbound\n"), nil
	case "rcctl ls on":
		return []byte("cron\ndhcpd\nntpd\nopf\npf\nsndiod\nsshd\nunbound\n"), nil
	case "rcctl ls started":
		return []byte("cron\ndhcpd\nntpd\nopf\nsshd\nunbound\n"), nil
	case "rcctl get ntpd":
		return []byte("ntpd_class=daemon\nntpd_flags=-s\nntpd_timeout=30\n"), nil
	case "rcctl check ntpd":
		return []byte("ntpd(ok)\n"), nil
	}
	r.mu.Lock()
	r.cmds = append(r.cmds, cmd)
	r.mu.Unlock()
	if strings.HasSuffix(cmd, " cron") && strings.HasPrefix(cmd, "rcctl reload") {
		return []byte("cron(failed)\n"), errors.New("exit status 1")
	}
	return nil, nil
}

func TestServices(t *testing.T) {
	e := newEnv(t, time.Minute)
	r := &rcctlRunner{}
	e.m.Runner, e.m.Actions = r, r
	m := e.live().Model
	m.System.Services = []pf.ServiceSetting{{Name: "ntpd", Enabled: true, Flags: ptrTo("-s")}}
	if err := stageCommit(t, e, m); err != nil {
		t.Fatal(err)
	}
	r.cmds = nil
	got, err := e.m.Services()
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]ServiceStatus{}
	for _, s := range got.Services {
		by[s.Name] = s
	}
	if s := by["sndiod"]; !s.Enabled || s.Running || !s.Failed || !s.Known {
		t.Errorf("sndiod %+v", s)
	}
	if s := by["accounting"]; s.Kind != pf.ServiceBoot || s.Failed || s.Running {
		t.Errorf("a boot setting %+v", s)
	}
	if s := by["mypkg"]; s.Known || s.Category != "Packages and others" {
		t.Errorf("a package's %+v", s)
	}
	if s := by["ntpd"]; s.Setting == nil || *s.Setting.Flags != "-s" {
		t.Errorf("ntpd's setting %+v", s)
	}
	if s := by["unbound"]; s.ManagedAt != "/services/dns" {
		t.Errorf("unbound %+v", s)
	}
	d, err := e.m.Service("ntpd")
	if err != nil || !d.Running || d.Vars["flags"] != "-s" {
		t.Errorf("ntpd detail %+v %v", d, err)
	}

	r.cmds = nil // the detail read the daemon log
	// Allowed: a daemon's start, stop, restart, reload; refused: OPF
	// itself, pf and every boot setting, starting or stopping one another
	// page sets up, a service rcctl doesn't know, an action that isn't one.
	for _, ok := range []ServiceActionRequest{{Name: "ntpd", Action: "restart", By: "op"}, {Name: "sshd", Action: "stop"}, {Name: "unbound", Action: "reload"}, {Name: "mypkg", Action: "start"}} {
		if res, err := e.m.ServiceAction(ok); err != nil || !res.OK {
			t.Errorf("%+v: %+v %v", ok, res, err)
		}
	}
	for _, bad := range []ServiceActionRequest{
		{Name: "opf", Action: "stop"}, {Name: "opf", Action: "restart"},
		{Name: "pf", Action: "stop"}, {Name: "accounting", Action: "start"},
		{Name: "dhcpd", Action: "stop"}, {Name: "unbound", Action: "start"},
		{Name: "nosuch", Action: "start"}, {Name: "ntpd; reboot", Action: "start"},
		{Name: "ntpd", Action: "enable"}, {Name: "ntpd", Action: "disable"},
	} {
		if _, err := e.m.ServiceAction(bad); err == nil {
			t.Errorf("%+v: allowed", bad)
		}
	}
	// A failure is said, and recorded.
	if res, err := e.m.ServiceAction(ServiceActionRequest{Name: "cron", Action: "reload"}); err != nil || res.OK || res.Output != "cron(failed)" {
		t.Errorf("a failure: %+v %v", res, err)
	}
	want := "rcctl restart ntpd\nrcctl stop sshd\nrcctl reload unbound\nrcctl start mypkg\nrcctl reload cron"
	if strings.Join(r.cmds, "\n") != want {
		t.Errorf("ran\n%s\nwant\n%s", strings.Join(r.cmds, "\n"), want)
	}
	ev, _ := e.m.Events(EventsRequest{Kinds: []string{EventService}})
	if len(ev.Events) == 0 || ev.Events[0].Message != "Someone couldn't reload cron: cron(failed)" || !ev.Events[0].Warning || ev.Events[len(ev.Events)-1].Message != "op restarted ntpd" {
		t.Errorf("events %+v", ev.Events)
	}
}

func ptrTo[T any](v T) *T { return &v }
