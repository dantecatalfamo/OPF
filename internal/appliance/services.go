package appliance

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"
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
	// LogName is the log those lines are from.
	LogName string `json:"logName"`
}

// serviceLog is the log a service writes to: syslog.conf sends sshd's
// to authlog and smtpd's to maillog; the rest go to daemon.
func serviceLog(name string) string {
	switch name {
	case "sshd":
		return "authlog"
	case "smtpd":
		return "maillog"
	}
	return "daemon"
}

// rcctl ls on and ls started check every service, seconds each on a
// small machine (6 s on the test VM): they run side by side, and what
// they said is kept a few seconds for every page and poll that asks.
const (
	serviceListsTimeout = 45 * time.Second
	serviceListsKeep    = 10 * time.Second
)

type serviceListsCache struct {
	mu          sync.Mutex
	at          time.Time
	on, started map[string]bool
	err         error
}

func (c *serviceListsCache) forget() {
	c.mu.Lock()
	c.at = time.Time{}
	c.mu.Unlock()
}

// serviceLists are which services start at boot and which run now.
func (m *Manager) serviceLists() (on, started map[string]bool, err error) {
	c := &m.svcLists
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Since(c.at) < serviceListsKeep {
		return c.on, c.started, c.err
	}
	ctx, cancel := context.WithTimeout(context.Background(), serviceListsTimeout)
	defer cancel()
	var onOut, startedOut []byte
	var onErr error
	var wg sync.WaitGroup
	wg.Go(func() { onOut, onErr = m.runner().Run(ctx, "rcctl", "ls", "on") })
	// rcctl ls started exits 1 when nothing is; its list is still right.
	wg.Go(func() { startedOut, _ = m.runner().Run(ctx, "rcctl", "ls", "started") })
	wg.Wait()
	c.on, c.started, c.err = lsLines(string(onOut)), lsLines(string(startedOut)), nil
	if onErr != nil {
		c.err = fmt.Errorf("rcctl ls on: %v", onErr)
	}
	c.at = time.Now()
	return c.on, c.started, c.err
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
	on, started, err := m.serviceLists()
	if err != nil {
		out.Errors = append(out.Errors, err.Error())
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
	if o, _, err := m.serviceLists(); err == nil {
		on = o[name]
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
	if l, err := m.SystemLog(SystemLogRequest{Log: serviceLog(name), Program: name, Limit: 30}); err == nil {
		d.Log, d.LogName = l.Lines, serviceLog(name)
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
	if req.Action != "check" && m.ReadOnly() {
		return nil, errReadOnly
	}
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
	m.svcLists.forget()
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
