package appliance

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/dantecatalfamo/OPF/internal/config"
)

// The event log: things that happen, where the graphs show values that
// vary. The collector notices them by comparing each sample with the
// last (a link going down, the WAN address changing, a device seen for
// the first time); commits come from the history itself, so there's
// one record of those. Events are kept in the state directory, the
// newest MaxEvents of them and none older than eventsKeep, so the file
// stays small. A device's MAC address is personal data: the log keeps
// it no longer than the rest (TODO.md › Privacy).

// Event kinds.
const (
	EventOPF     = "opf"     // OPF started
	EventLink    = "link"    // an interface's link went down or came up
	EventAddress = "address" // an interface's address changed (the WAN's, from DHCP)
	EventGateway = "gateway" // a gateway stopped or started answering
	EventDevice  = "device"  // a device seen for the first time
	EventVPN     = "vpn"     // a VPN device connected from somewhere new
	EventService = "service" // a daemon stopped or started again
	EventList    = "list"    // a downloaded list failed or recovered
	EventUpdates = "updates" // security patches became available
	EventCommit  = "commit"  // a change was applied, confirmed, reverted or failed
)

const (
	MaxEvents  = 5000
	eventsKeep = 90 * 24 * time.Hour
	maxKnown   = 20000 // devices remembered as seen
	eventsFile = "events.json"
)

// Event is one thing that happened.
type Event struct {
	Time time.Time `json:"time"`
	Kind string    `json:"kind"`
	// Warning: something went wrong (a link down, a gateway not
	// answering); otherwise it's news.
	Warning bool `json:"warning,omitempty"`
	// Subject is what it's about, for the UI to link: an interface,
	// gateway, VPN device or list id, a device's MAC address, a commit
	// id.
	Subject string `json:"subject,omitempty"`
	Message string `json:"message"`
}

type eventLog struct {
	mu     sync.Mutex
	events []Event              // oldest first
	known  map[string]time.Time // MAC addresses seen, and when first
	dirty  bool
}

type eventsFileBody struct {
	Events []Event              `json:"events"`
	Known  map[string]time.Time `json:"known"`
}

func (m *Manager) eventLog() *eventLog {
	m.eventsOnce.Do(func() { m.events = &eventLog{known: map[string]time.Time{}} })
	return m.events
}

// record adds an event, keeping the log within its bounds.
func (l *eventLog) record(e Event) {
	e.Message = printable(e.Message, maxMessageRunes)
	e.Subject = printable(e.Subject, 80)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, e)
	l.trim(time.Now())
	l.dirty = true
}

func (l *eventLog) trim(now time.Time) {
	old := now.Add(-eventsKeep)
	i := 0
	for i < len(l.events) && l.events[i].Time.Before(old) {
		i++
	}
	if n := len(l.events) - i; n > MaxEvents {
		i += n - MaxEvents
	}
	if i > 0 {
		l.events = append([]Event(nil), l.events[i:]...)
	}
	for mac, t := range l.known {
		if t.Before(old) && len(l.known) > maxKnown/2 {
			delete(l.known, mac)
		}
	}
}

// seen says whether a device's MAC address was seen before, and
// remembers it. The first time OPF looks (first), everything is taken
// as known, or every device would be news.
func (l *eventLog) seen(mac string, now time.Time, first bool) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.known[mac]; ok {
		return true
	}
	if len(l.known) >= maxKnown {
		return true // full: say nothing rather than forget the rest
	}
	l.known[mac] = now
	l.dirty = true
	return first
}

// SeedEvents adds events that happened before now, for the mock's
// history.
func (m *Manager) SeedEvents(es []Event) {
	for _, e := range es {
		m.eventLog().record(e)
	}
	l := m.eventLog()
	l.mu.Lock()
	sort.SliceStable(l.events, func(i, j int) bool { return l.events[i].Time.Before(l.events[j].Time) })
	l.mu.Unlock()
}

// saveEvents writes the log if it changed, whole or not at all.
func (m *Manager) saveEvents() error {
	l := m.eventLog()
	l.mu.Lock()
	if !l.dirty {
		l.mu.Unlock()
		return nil
	}
	data, err := json.Marshal(eventsFileBody{Events: l.events, Known: l.known})
	l.dirty = false
	l.mu.Unlock()
	if err != nil {
		return err
	}
	path := m.store.StatePath(eventsFile)
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+eventsFile+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// loadEvents reads the saved log, cleaning what it reads as a new
// event is cleaned; a file that's too big or damaged is left out.
func (m *Manager) loadEvents() {
	data, err := os.ReadFile(m.store.StatePath(eventsFile))
	if err != nil {
		return
	}
	var body eventsFileBody
	if len(data) > 8<<20 || json.Unmarshal(data, &body) != nil {
		log.Printf("starting the event log over: %s is damaged", eventsFile)
		return
	}
	l := m.eventLog()
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	for _, e := range body.Events {
		if e.Time.IsZero() || e.Time.After(now.Add(time.Minute)) || !eventKinds[e.Kind] {
			continue
		}
		e.Message, e.Subject = printable(e.Message, maxMessageRunes), printable(e.Subject, 80)
		l.events = append(l.events, e)
	}
	sort.SliceStable(l.events, func(i, j int) bool { return l.events[i].Time.Before(l.events[j].Time) })
	for mac, t := range body.Known {
		if len(l.known) < maxKnown && isMAC(mac) {
			l.known[mac] = t
		}
	}
	l.trim(now)
}

var eventKinds = map[string]bool{
	EventOPF: true, EventLink: true, EventAddress: true, EventGateway: true, EventDevice: true,
	EventVPN: true, EventService: true, EventList: true, EventUpdates: true, EventCommit: true,
}

func isMAC(s string) bool {
	if len(s) != 17 {
		return false
	}
	for i, r := range s {
		if i%3 == 2 {
			if r != ':' {
				return false
			}
		} else if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

// EventsRequest asks for events, newest first: of some kinds (all if
// none), whose message or subject contains Query, before Before (now
// if zero), at most Limit (EventsPage if 0).
type EventsRequest struct {
	Kinds  []string  `json:"kinds,omitempty"`
	Query  string    `json:"query,omitempty"`
	Before time.Time `json:"before,omitzero"`
	Limit  int       `json:"limit,omitempty"`
}

const (
	EventsPage    = 100
	MaxEventsPage = 1000
)

// Events is a page of the log, newest first, and whether there's more
// before its last.
type Events struct {
	Events []Event `json:"events"`
	More   bool    `json:"more,omitempty"`
}

// Events returns events, newest first, with the commits from history.
func (m *Manager) Events(req EventsRequest) (*Events, error) {
	req.Query = strings.TrimSpace(req.Query)
	if len(req.Query) > 100 {
		return nil, errorf(CodeInvalid, "the search is at most 100 characters")
	}
	if req.Limit < 0 || req.Limit > MaxEventsPage {
		return nil, errorf(CodeInvalid, "limit: 1 to %d", MaxEventsPage)
	}
	for _, k := range req.Kinds {
		if !eventKinds[k] {
			return nil, errorf(CodeInvalid, "no kind of event %q", printable(k, 40))
		}
	}
	if req.Limit == 0 {
		req.Limit = EventsPage
	}
	l := m.eventLog()
	l.mu.Lock()
	all := append([]Event(nil), l.events...)
	l.mu.Unlock()
	all = append(all, m.commitEvents()...)
	sort.SliceStable(all, func(i, j int) bool { return all[i].Time.After(all[j].Time) })

	kinds := map[string]bool{}
	for _, k := range req.Kinds {
		kinds[k] = true
	}
	q := strings.ToLower(req.Query)
	res := &Events{Events: []Event{}}
	for _, e := range all {
		if !req.Before.IsZero() && !e.Time.Before(req.Before) {
			continue
		}
		if len(kinds) > 0 && !kinds[e.Kind] {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(e.Message+" "+e.Subject), q) {
			continue
		}
		if len(res.Events) == req.Limit {
			res.More = true
			break
		}
		res.Events = append(res.Events, e)
	}
	return res, nil
}

// commitEvents are the history's commits as events.
func (m *Manager) commitEvents() []Event {
	entries, err := m.store.History()
	if err != nil {
		return nil
	}
	var out []Event
	for _, e := range entries {
		msg := e.Message
		if msg == "" {
			msg = "a change"
		}
		ev := Event{Time: e.Time, Kind: EventCommit, Subject: e.ID}
		switch e.Status {
		case config.StatusPending:
			ev.Message = "Applied, waiting for confirmation: " + msg
		case config.StatusApplying:
			ev.Message, ev.Warning = "Interrupted while applying: "+msg, true
		case config.StatusFailed:
			ev.Message, ev.Warning = "Failed and put back: "+msg, true
		case config.StatusReverted:
			ev.Message, ev.Warning = "Applied and then reverted: "+msg, true
		default:
			ev.Message = "Applied: " + msg
		}
		out = append(out, ev)
	}
	return out
}
