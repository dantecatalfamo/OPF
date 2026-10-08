package appliance

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/dantecatalfamo/OPF/internal/pf"
)

// The base system's services, as rcctl(8) has them: which there are,
// which start at boot, which are running now; one service's rc.d
// variables and recent log lines; and starting, stopping and
// restarting them. Boot settings are the model's (pf.ServiceSetting),
// written into rc.conf.local by a commit, never with rcctl enable or
// set: those rewrite the whole file, sorted.

// ServiceStatus is a service now.
type ServiceStatus struct {
	pf.ServiceInfo
	// Known: OPF knows what it is (a base service); a package's isn't.
	Known bool `json:"known"`
	// Enabled: it starts at boot (rcctl ls on).
	Enabled bool `json:"enabled"`
	// Running: a daemon running now (rcctl ls started).
	Running bool `json:"running"`
	// Failed: a daemon that starts at boot but isn't running.
	Failed bool `json:"failed"`
	// Setting is OPF's boot setting for it, as applied; nil is the
	// system's own.
	Setting *pf.ServiceSetting `json:"setting,omitempty"`
}

// Services is every service rcctl knows.
type Services struct {
	Services []ServiceStatus `json:"services"`
	Errors   []string        `json:"errors"`
}

// ServiceDetail is one service: its status, its rc.d variables (rcctl
// get), and its recent lines in the daemon log.
type ServiceDetail struct {
	ServiceStatus
	Vars map[string]string `json:"vars"`
	Log  []LogLine         `json:"log"`
}

var serviceNameRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

func lsLines(out string) map[string]bool {
	set := map[string]bool{}
	for _, l := range strings.Fields(out) {
		if serviceNameRE.MatchString(l) {
			set[l] = true
		}
	}
	return set
}

// Services is every service and its state.
func (m *Manager) Services() (*Services, error) {
	model, err := m.liveOrEmpty()
	if err != nil {
		return nil, apiError(err)
	}
	out := &Services{Services: []ServiceStatus{}, Errors: []string{}}
	all, err := m.read("rcctl", "ls", "all")
	if err != nil {
		return nil, errorf(CodeInternal, "rcctl ls all: %v", err)
	}
	on, started := map[string]bool{}, map[string]bool{}
	if o, err := m.read("rcctl", "ls", "on"); err == nil {
		on = lsLines(o)
	} else {
		out.Errors = append(out.Errors, "rcctl ls on: "+err.Error())
	}
	// rcctl ls started exits 1 when nothing is; its list is still right.
	if o, _ := m.read("rcctl", "ls", "started"); o != "" {
		started = lsLines(o)
	}
	names := []string{}
	for n := range lsLines(all) {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		out.Services = append(out.Services, m.serviceStatus(model, n, on[n], started[n]))
	}
	return out, nil
}

func (m *Manager) serviceStatus(model *pf.Model, name string, on, started bool) ServiceStatus {
	info, known := pf.BaseService(name)
	if !known {
		info = pf.ServiceInfo{Name: name, Kind: pf.ServiceDaemon, Category: "Packages and others"}
	}
	s := ServiceStatus{ServiceInfo: info, Known: known, Enabled: on}
	if info.Kind == pf.ServiceDaemon {
		s.Running = started
		s.Failed = on && !started
	}
	for i := range model.System.Services {
		if model.System.Services[i].Name == name {
			setting := model.System.Services[i]
			s.Setting = &setting
		}
	}
	return s
}

// Service is one service, in detail.
func (m *Manager) Service(name string) (*ServiceDetail, error) {
	if !serviceNameRE.MatchString(name) {
		return nil, errorf(CodeNotFound, "no service %q", printable(name, 40))
	}
	all, err := m.read("rcctl", "ls", "all")
	if err != nil {
		return nil, errorf(CodeInternal, "rcctl ls all: %v", err)
	}
	if !lsLines(all)[name] {
		return nil, errorf(CodeNotFound, "no service %q", name)
	}
	model, err := m.liveOrEmpty()
	if err != nil {
		return nil, apiError(err)
	}
	on, started := false, false
	if o, err := m.read("rcctl", "ls", "on"); err == nil {
		on = lsLines(o)[name]
	}
	if _, err := m.read("rcctl", "check", name); err == nil {
		started = true
	}
	d := &ServiceDetail{ServiceStatus: m.serviceStatus(model, name, on, started), Vars: map[string]string{}, Log: []LogLine{}}
	if out, err := m.read("rcctl", "get", name); err == nil {
		for _, l := range strings.Split(out, "\n") {
			if k, v, ok := strings.Cut(l, "="); ok {
				d.Vars[strings.TrimPrefix(k, name+"_")] = v
			}
		}
	}
	if l, err := m.SystemLog(SystemLogRequest{Log: "daemon", Program: name, Limit: 30}); err == nil {
		d.Log = l.Lines
	}
	return d, nil
}

// ServiceActionRequest starts, stops, restarts, reloads or checks a
// service.
type ServiceActionRequest struct {
	Name   string `json:"name"`
	Action string `json:"action"`
	// By is who asked; the privileged side sets it from the session.
	By string `json:"-"`
}

// ServiceActionResult is what rcctl said.
type ServiceActionResult struct {
	OK     bool   `json:"ok"`
	Output string `json:"output"`
}

var serviceActions = []string{"start", "stop", "restart", "reload", "check"}

// ServiceAction runs rcctl on a service. A boot setting (pf among them)
// and OPF itself are only checked: rcctl stop pf turns the packet filter
// off, and stopping OPF ends this interface. A service OPF sets up on
// its own page is started and stopped by that page's settings, so here
// it's only restarted, reloaded or checked.
func (m *Manager) ServiceAction(req ServiceActionRequest) (*ServiceActionResult, error) {
	if !slices.Contains(serviceActions, req.Action) {
		return nil, errorf(CodeInvalid, "the action is start, stop, restart, reload or check, not %q", printable(req.Action, 20))
	}
	if !serviceNameRE.MatchString(req.Name) {
		return nil, errorf(CodeNotFound, "no service %q", printable(req.Name, 40))
	}
	all, err := m.read("rcctl", "ls", "all")
	if err != nil {
		return nil, errorf(CodeInternal, "rcctl ls all: %v", err)
	}
	if !lsLines(all)[req.Name] {
		return nil, errorf(CodeNotFound, "no service %q", req.Name)
	}
	info, known := pf.BaseService(req.Name)
	if req.Action != "check" {
		switch {
		case req.Name == "opf":
			return nil, errorf(CodeInvalid, "OPF doesn't stop or restart itself from its own interface")
		case known && info.Kind == pf.ServiceBoot:
			return nil, errorf(CodeInvalid, "%s is a boot setting, not a daemon: it's only on or off at boot", req.Name)
		case known && info.ManagedAt != "" && (req.Action == "start" || req.Action == "stop"):
			return nil, errorf(CodeInvalid, "%s is started and stopped by its settings (%s)", req.Name, info.ManagedAt)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	run := m.actions().Run
	if req.Action == "check" {
		run = m.runner().Run // only looks
	}
	out, err := run(ctx, "rcctl", req.Action, req.Name)
	res := &ServiceActionResult{OK: err == nil, Output: strings.TrimSpace(string(out))}
	if req.Action != "check" {
		who := req.By
		if who == "" {
			who = "Someone"
		}
		past := map[string]string{"start": "started", "stop": "stopped", "restart": "restarted", "reload": "reloaded"}[req.Action]
		msg := fmt.Sprintf("%s %s %s", who, past, req.Name)
		if err != nil {
			msg = fmt.Sprintf("%s couldn't %s %s: %s", who, req.Action, req.Name, rcctlError(res.Output))
		}
		m.RecordEvent(Event{Time: time.Now(), Kind: EventService, Subject: req.Name, Warning: err != nil, Message: msg})
	}
	return res, nil
}

// rcctlError is the first line of what rcctl said when it failed.
func rcctlError(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	if s == "" {
		return "it failed"
	}
	return s
}
