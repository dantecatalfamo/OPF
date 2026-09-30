package appliance

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dantecatalfamo/OPF/internal/sysinfo"
)

// switchable answers ifconfig -A with what it's set to, and rcctl
// check with whether a daemon is set to run.
type switchable struct {
	mu      sync.Mutex
	ifc     string
	stopped map[string]bool
}

func (s *switchable) set(ifc string) {
	s.mu.Lock()
	s.ifc = ifc
	s.mu.Unlock()
}

func (s *switchable) Run(_ context.Context, argv ...string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case len(argv) == 2 && argv[0] == "ifconfig":
		return []byte(s.ifc), nil
	case len(argv) == 3 && argv[0] == "rcctl":
		if s.stopped[argv[2]] {
			return []byte(argv[2] + "(failed)\n"), errors.New("exit status 1")
		}
		return []byte(argv[2] + "(ok)\n"), nil
	}
	return nil, errors.New("exit status 1")
}

func ifconfigText(lanCarrier bool, wanAddr string) string {
	status := "active"
	if !lanCarrier {
		status = "no carrier"
	}
	return fmt.Sprintf(`em0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	status: active
	inet %s netmask 0xffffff00 broadcast 203.0.113.255
em1: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	status: %s
	inet 192.168.1.1 netmask 0xffffff00 broadcast 192.168.1.255
`, wanAddr, status)
}

func eventsOf(t *testing.T, m *Manager, kind string) []Event {
	t.Helper()
	res, err := m.Events(EventsRequest{Kinds: []string{kind}})
	if err != nil {
		t.Fatal(err)
	}
	return res.Events
}

func TestEventWatch(t *testing.T) {
	e := newEnv(t, time.Minute)
	sw := &switchable{ifc: ifconfigText(true, "203.0.113.24"), stopped: map[string]bool{}}
	e.m.Runner = sw
	e.m.metricsStore()
	model := e.live().Model
	now := time.Now()

	// The first look is how things are: no events.
	ifs := sysinfo.ParseIfconfig(sw.ifc)
	e.m.watchInterfaces(model, ifs, now)
	e.m.watchSlow(model, &GatewaysStatus{Gateways: map[string]GatewayHealth{"gw_wan": {Address: "9.9.9.9", Online: true}}}, now)
	e.m.collect.watch.started = true
	if all, _ := e.m.Events(EventsRequest{Kinds: []string{EventLink, EventGateway, EventDevice, EventService, EventAddress}}); len(all.Events) != 0 {
		t.Fatalf("first look: %+v", all.Events)
	}

	// The LAN loses its carrier, the WAN gets a new address, the
	// gateway stops answering, unbound stops.
	sw.set(ifconfigText(false, "203.0.113.30"))
	sw.stopped["unbound"] = true
	e.m.watchInterfaces(model, sysinfo.ParseIfconfig(sw.ifc), now.Add(10*time.Second))
	e.m.watchSlow(model, &GatewaysStatus{Gateways: map[string]GatewayHealth{"gw_wan": {Address: "9.9.9.9", Online: false}}}, now.Add(10*time.Second))
	if l := eventsOf(t, e.m, EventLink); len(l) != 1 || !l[0].Warning || l[0].Subject != "lan" || !strings.Contains(l[0].Message, "LAN (em1): link down (no carrier)") {
		t.Errorf("link: %+v", l)
	}
	if a := eventsOf(t, e.m, EventAddress); len(a) != 1 || !strings.Contains(a[0].Message, "203.0.113.30 (was 203.0.113.24)") {
		t.Errorf("address: %+v", a)
	}
	if g := eventsOf(t, e.m, EventGateway); len(g) != 1 || !g[0].Warning || !strings.Contains(g[0].Message, "WAN_DHCP stopped answering") {
		t.Errorf("gateway: %+v", g)
	}
	if s := eventsOf(t, e.m, EventService); len(s) != 1 || s[0].Message != "unbound stopped" {
		t.Errorf("service: %+v", s)
	}

	// Back again: one event each, newest first.
	sw.set(ifconfigText(true, "203.0.113.30"))
	delete(sw.stopped, "unbound")
	e.m.watchInterfaces(model, sysinfo.ParseIfconfig(sw.ifc), now.Add(20*time.Second))
	e.m.watchSlow(model, &GatewaysStatus{Gateways: map[string]GatewayHealth{"gw_wan": {Address: "9.9.9.9", Online: true}}}, now.Add(20*time.Second))
	if l := eventsOf(t, e.m, EventLink); len(l) != 2 || l[0].Warning || l[0].Message != "LAN (em1): link up" {
		t.Errorf("link back: %+v", l)
	}
	if s := eventsOf(t, e.m, EventService); len(s) != 2 || s[0].Message != "unbound is running again" {
		t.Errorf("service back: %+v", s)
	}

	// A device OPF hasn't seen; the rest of the ARP table it has.
	if runtime.GOOS != "openbsd" {
		l := e.m.eventLog()
		l.mu.Lock()
		delete(l.known, "68:57:2d:10:e3:41")
		l.mu.Unlock()
		e.m.watchSlow(model, nil, now.Add(30*time.Second))
		if d := eventsOf(t, e.m, EventDevice); len(d) != 1 || d[0].Subject != "68:57:2d:10:e3:41" || !strings.Contains(d[0].Message, "at 192.168.20.101 on IoT") {
			t.Errorf("device: %+v", d)
		}
	}

	// Lists: a failure after working, and working again; a second
	// failure in a row says nothing more.
	e.m.noteRefresh(dnsKey("hosts"), nil)
	e.m.noteRefresh(dnsKey("hosts"), errors.New("connection refused"))
	e.m.noteRefresh(dnsKey("hosts"), errors.New("connection refused"))
	e.m.noteRefresh(dnsKey("hosts"), nil)
	if l := eventsOf(t, e.m, EventList); len(l) != 2 || !strings.Contains(l[1].Message, "Couldn't download DNS blocklist hosts: connection refused") || l[0].Message != "Downloaded DNS blocklist hosts again" {
		t.Errorf("lists: %+v", l)
	}

	// Patches: only ones that weren't there before.
	t0 := now.Add(-time.Hour)
	e.m.notePatches(&UpdatesStatus{CheckedAt: &t0, Patches: []string{"001_a"}}, &UpdatesStatus{CheckedAt: &now, Patches: []string{"001_a", "002_b"}})
	if u := eventsOf(t, e.m, EventUpdates); len(u) != 1 || u[0].Message != "1 new security patch: 002_b" {
		t.Errorf("updates: %+v", u)
	}

	// Search and paging.
	if r, _ := e.m.Events(EventsRequest{Query: "WAN_dhcp"}); len(r.Events) != 2 {
		t.Errorf("search: %+v", r.Events)
	}
	if r, _ := e.m.Events(EventsRequest{Limit: 2}); len(r.Events) != 2 || !r.More {
		t.Errorf("page: %+v", r)
	}
	for _, bad := range []EventsRequest{{Kinds: []string{"nope"}}, {Limit: MaxEventsPage + 1}, {Query: strings.Repeat("x", 101)}} {
		if _, err := e.m.Events(bad); err == nil {
			t.Errorf("took %+v", bad)
		}
	}

	// Saved and read back; a tampered file is cleaned.
	if err := e.m.saveEvents(); err != nil {
		t.Fatal(err)
	}
	path := e.m.store.StatePath(eventsFile)
	data, _ := os.ReadFile(path)
	data = []byte(strings.Replace(string(data), `"events":[`, `"events":[{"time":"2026-01-01T00:00:00Z","kind":"bogus","message":"x"},{"time":"2099-01-01T00:00:00Z","kind":"link","message":"future"},`, 1))
	os.WriteFile(path, data, 0600)
	m2, _ := New(e.m.store)
	m2.loadEvents()
	r1, _ := e.m.Events(EventsRequest{Limit: MaxEventsPage})
	r2, _ := m2.Events(EventsRequest{Limit: MaxEventsPage})
	if len(r2.Events) != len(r1.Events) {
		t.Errorf("after reading back: %d events, want %d", len(r2.Events), len(r1.Events))
	}
}

func TestEventLogBounds(t *testing.T) {
	l := &eventLog{known: map[string]time.Time{}}
	now := time.Now()
	l.record(Event{Time: now.Add(-100 * 24 * time.Hour), Kind: EventOPF, Message: "too old"})
	for i := range MaxEvents + 10 {
		l.record(Event{Time: now.Add(time.Duration(i) * time.Millisecond), Kind: EventOPF, Message: "x\x1b[31m"})
	}
	if len(l.events) != MaxEvents || l.events[0].Message == "too old" || strings.Contains(l.events[0].Message, "\x1b") {
		t.Errorf("%d events, first %q", len(l.events), l.events[0].Message)
	}
	// Seen for the first time: news, unless it's OPF's first look.
	if l.seen("00:11:22:33:44:55", now, false) || !l.seen("00:11:22:33:44:55", now, false) || !l.seen("00:11:22:33:44:66", now, true) {
		t.Error("seen")
	}
}
