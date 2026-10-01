package appliance

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/dantecatalfamo/OPF/internal/pf"
	"github.com/dantecatalfamo/OPF/internal/webhook"
)

// Webhooks: events sent as JSON to URLs, signed. The model says which
// webhooks there are and which events each gets; a webhook's URL and
// signing key are secrets, kept apart from the model in the state
// directory (secrets.json, only root can read it), so they're never in
// an API answer, the history or its diffs. Setting one takes effect at
// once, like changing a password, and only the URL's scheme and host
// are shown after.
//
// Deliveries are queued per webhook and sent one at a time by the
// sender (the OPF binary as the unprivileged user; package webhook),
// retried with backoff, and given up on after a few hours.

const (
	secretsFile     = "secrets.json"
	webhookQueueMax = 200
)

// retryAfter is how long to wait after each failed try; after the
// last, the delivery is dropped.
var retryAfter = []time.Duration{10 * time.Second, time.Minute, 5 * time.Minute, 30 * time.Minute, 2 * time.Hour}

type webhookSecret struct {
	URL string `json:"url"`
	Key string `json:"key,omitempty"`
}

type secretsBody struct {
	Webhooks map[string]webhookSecret `json:"webhooks"`
}

type delivery struct {
	ev    Event
	tries int
	next  time.Time
	test  bool
}

type hookState struct {
	queue       []delivery
	lastAttempt *time.Time
	lastOK      *time.Time
	lastError   string
	dropped     int
}

type webhooks struct {
	mu      sync.Mutex
	loaded  bool
	secrets map[string]webhookSecret
	state   map[string]*hookState
	commits map[string]string // commit id: its event's message, to notice changes
}

func (m *Manager) hooks() *webhooks {
	m.hooksOnce.Do(func() { m.webhooks = &webhooks{secrets: map[string]webhookSecret{}, state: map[string]*hookState{}} })
	h := m.webhooks
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.loaded {
		h.loaded = true
		m.loadSecrets(h)
	}
	return h
}

// loadSecrets reads the secrets file; one that's damaged is left out,
// and each secret is checked as a new one is.
func (m *Manager) loadSecrets(h *webhooks) {
	data, err := os.ReadFile(m.store.StatePath(secretsFile))
	if err != nil {
		return
	}
	var body secretsBody
	if len(data) > 1<<20 || json.Unmarshal(data, &body) != nil {
		log.Printf("%s is damaged; webhooks need their URLs set again", secretsFile)
		return
	}
	for id, s := range body.Webhooks {
		if isID(id) && webhook.CheckURL(s.URL) == nil && checkKey(s.Key) == nil && len(h.secrets) < pf.MaxWebhooks*4 {
			h.secrets[id] = s
		}
	}
}

// saveSecrets writes the secrets, readable by root only, whole or not
// at all. Call with h.mu held.
func (m *Manager) saveSecrets(h *webhooks) error {
	data, err := json.Marshal(secretsBody{Webhooks: h.secrets})
	if err != nil {
		return err
	}
	path := m.store.StatePath(secretsFile)
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+secretsFile+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func isID(s string) bool {
	if s == "" || len(s) > 32 {
		return false
	}
	for i, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' && i > 0) {
			return false
		}
	}
	return true
}

func checkKey(k string) error {
	if len(k) > webhook.MaxKey {
		return fmt.Errorf("a key is at most %d characters", webhook.MaxKey)
	}
	if strings.ContainsFunc(k, func(r rune) bool { return r > unicode.MaxASCII || !unicode.IsPrint(r) || r == ' ' }) {
		return fmt.Errorf("a key is printable ASCII, without spaces")
	}
	return nil
}

// modelWebhooks are the webhooks of the live model, and of the staged
// one if there is one (a webhook being added can have its URL set
// before it's applied).
func (m *Manager) modelWebhooks() (live, staged []pf.Webhook) {
	if model, _, err := m.live(); err == nil && model != nil && model.Notifications != nil {
		live = model.Notifications.Webhooks
	}
	if data, ok, err := m.stagedModel(); err == nil && ok {
		if model, err := decodeModel(data); err == nil && model.Notifications != nil {
			staged = model.Notifications.Webhooks
		}
	}
	return live, staged
}

// wants says whether a webhook gets an event.
func wants(w pf.Webhook, e Event) bool {
	if !w.Enabled || (w.ProblemsOnly && !e.Warning) {
		return false
	}
	if len(w.Kinds) == 0 {
		return true
	}
	for _, k := range w.Kinds {
		if k == e.Kind {
			return true
		}
	}
	return false
}

// notify queues an event for every applied webhook that wants it and
// has a URL.
func (m *Manager) notify(e Event) {
	live, _ := m.modelWebhooks()
	h := m.hooks()
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, w := range live {
		if _, ok := h.secrets[w.ID]; !ok || !wants(w, e) {
			continue
		}
		st := h.stateOf(w.ID)
		st.queue = append(st.queue, delivery{ev: e, next: time.Now()})
		if len(st.queue) > webhookQueueMax {
			st.queue = st.queue[1:]
			st.dropped++
		}
	}
}

func (h *webhooks) stateOf(id string) *hookState {
	st := h.state[id]
	if st == nil {
		st = &hookState{}
		h.state[id] = st
	}
	return st
}

// delivery is what a webhook is sent for an event, in its format, and
// which firewall it's from.
func (m *Manager) delivery(e Event, test bool, format string) formatted {
	host := ""
	if model, _, err := m.live(); err == nil && model != nil {
		host = model.System.Hostname
		if model.System.Domain != "" {
			host += "." + model.System.Domain
		}
	}
	return formatDelivery(format, host, e, test)
}

// formatOf is a webhook's format in the live model, or the staged one
// (a test before it's applied).
func (m *Manager) formatOf(id string) string {
	live, staged := m.modelWebhooks()
	for _, w := range append(live, staged...) {
		if w.ID == id {
			return w.Format
		}
	}
	return pf.WebhookJSON
}

// send delivers one event to a URL through the sender.
func (m *Manager) send(s webhookSecret, f formatted) error {
	if m.Sender == nil || m.Exe == "" {
		return fmt.Errorf("sending isn't set up in this OPF")
	}
	input, _ := json.Marshal(webhook.Request{URL: s.URL, Key: s.Key, Body: f.body, ContentType: f.contentType, Headers: f.headers})
	ctx, cancel := context.WithTimeout(context.Background(), webhook.Timeout+5*time.Second)
	defer cancel()
	out, err := m.Sender.RunInput(ctx, input, []string{SenderEnv + "=1"}, m.Exe)
	if err != nil {
		if msg := firstLine(string(out)); msg != "" {
			return fmt.Errorf("%s", msg)
		}
		return fmt.Errorf("the sender failed: %v", err)
	}
	return nil
}

// SenderEnv, set to 1, starts OPF's binary as the webhook sender
// (cmd/opf).
const SenderEnv = "OPF_WEBHOOK_SENDER"

// RunWebhooks sends what's queued, retrying with backoff, and notices
// commits (which come from history, not the event log), until ctx is
// done.
func (m *Manager) RunWebhooks(ctx context.Context) {
	h := m.hooks()
	m.noteCommits(h, true)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for n := 0; ; n++ {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		if n%10 == 0 {
			m.noteCommits(h, false)
		}
		if n%3600 == 0 {
			m.forgetOrphanSecrets(h)
		}
		m.deliverDue(h, time.Now())
	}
}

// deliverDue sends each webhook's first due delivery.
func (m *Manager) deliverDue(h *webhooks, now time.Time) {
	h.mu.Lock()
	type job struct {
		id  string
		s   webhookSecret
		d   delivery
		idx int
	}
	var jobs []job
	for id, st := range h.state {
		if len(st.queue) == 0 || st.queue[0].next.After(now) {
			continue
		}
		s, ok := h.secrets[id]
		if !ok {
			st.queue = nil // its URL was taken away
			continue
		}
		jobs = append(jobs, job{id: id, s: s, d: st.queue[0]})
	}
	h.mu.Unlock()
	for _, j := range jobs {
		err := m.send(j.s, m.delivery(j.d.ev, j.d.test, m.formatOf(j.id)))
		t := time.Now()
		h.mu.Lock()
		st := h.stateOf(j.id)
		st.lastAttempt = &t
		if len(st.queue) > 0 && st.queue[0].ev == j.d.ev {
			if err == nil {
				st.lastOK, st.lastError = &t, ""
				st.queue = st.queue[1:]
			} else {
				st.lastError = err.Error()
				q := &st.queue[0]
				if q.tries >= len(retryAfter) {
					st.lastError = fmt.Sprintf("gave up after %d tries: %v", q.tries+1, err)
					st.queue = st.queue[1:]
					st.dropped++
				} else {
					q.next = t.Add(retryAfter[q.tries])
					q.tries++
				}
			}
		}
		h.mu.Unlock()
	}
}

// noteCommits notices commits new or changed since it last looked (a
// pending one confirmed or reverted) and sends them; the first look
// only remembers.
func (m *Manager) noteCommits(h *webhooks, first bool) {
	evs := m.commitEvents()
	var fresh []Event
	h.mu.Lock()
	if h.commits == nil {
		h.commits = map[string]string{}
	}
	for _, e := range evs {
		if h.commits[e.Subject] != e.Message {
			h.commits[e.Subject] = e.Message
			if !first {
				fresh = append(fresh, e)
			}
		}
	}
	h.mu.Unlock()
	sort.Slice(fresh, func(i, j int) bool { return fresh[i].Time.Before(fresh[j].Time) })
	for _, e := range fresh {
		m.notify(e)
	}
}

// forgetOrphanSecrets drops the secrets of webhooks neither the live
// nor the staged model has any more.
func (m *Manager) forgetOrphanSecrets(h *webhooks) {
	live, staged := m.modelWebhooks()
	known := map[string]bool{}
	for _, w := range append(live, staged...) {
		known[w.ID] = true
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	changed := false
	for id := range h.secrets {
		if !known[id] {
			delete(h.secrets, id)
			delete(h.state, id)
			changed = true
		}
	}
	if changed {
		if err := m.saveSecrets(h); err != nil {
			log.Printf("saving webhook secrets: %v", err)
		}
	}
}

// WebhookStatus is a webhook's URL as far as it may be shown, and how
// its deliveries are going.
type WebhookStatus struct {
	ID string `json:"id"`
	// Target is the URL's scheme and host; empty until a URL is set.
	Target      string     `json:"target,omitempty"`
	Signed      bool       `json:"signed,omitempty"`
	LastAttempt *time.Time `json:"lastAttempt,omitempty"`
	LastOK      *time.Time `json:"lastOk,omitempty"`
	LastError   string     `json:"lastError,omitempty"`
	Queued      int        `json:"queued,omitempty"`
	Dropped     int        `json:"dropped,omitempty"`
}

// Webhooks reports the live and staged models' webhooks.
func (m *Manager) Webhooks() ([]WebhookStatus, error) {
	live, staged := m.modelWebhooks()
	ids := map[string]bool{}
	for _, w := range append(live, staged...) {
		ids[w.ID] = true
	}
	h := m.hooks()
	h.mu.Lock()
	defer h.mu.Unlock()
	out := []WebhookStatus{}
	for id := range ids {
		st := WebhookStatus{ID: id}
		if s, ok := h.secrets[id]; ok {
			st.Target, st.Signed = webhook.Target(s.URL), s.Key != ""
		}
		if hs := h.state[id]; hs != nil {
			st.LastAttempt, st.LastOK, st.LastError, st.Queued, st.Dropped = hs.lastAttempt, hs.lastOK, hs.lastError, len(hs.queue), hs.dropped
		}
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// WebhookSecretRequest sets a webhook's URL and how it's signed:
// Signing "keep" (the key it has), "none", "generate" (a new random
// key, returned once) or "set" (Key).
type WebhookSecretRequest struct {
	URL     string `json:"url"`
	Signing string `json:"signing"`
	Key     string `json:"key,omitempty"`
}

// WebhookSecretResult is the webhook's status, and a generated key,
// the only time it's shown.
type WebhookSecretResult struct {
	WebhookStatus
	Key string `json:"key,omitempty"`
}

// SetWebhookSecret sets a webhook's URL and key, now.
func (m *Manager) SetWebhookSecret(id string, req WebhookSecretRequest) (*WebhookSecretResult, error) {
	live, staged := m.modelWebhooks()
	found := false
	for _, w := range append(live, staged...) {
		found = found || w.ID == id
	}
	if !found {
		return nil, errorf(CodeNotFound, "no webhook %q in the configuration", printable(id, 40))
	}
	if err := webhook.CheckURL(strings.TrimSpace(req.URL)); err != nil {
		return nil, &Error{Code: CodeInvalid, Message: err.Error(), Details: []Detail{{Path: "url", Message: err.Error()}}}
	}
	h := m.hooks()
	h.mu.Lock()
	defer h.mu.Unlock()
	s := webhookSecret{URL: strings.TrimSpace(req.URL)}
	res := &WebhookSecretResult{}
	switch req.Signing {
	case "keep", "":
		s.Key = h.secrets[id].Key
	case "none":
	case "generate":
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		s.Key = hex.EncodeToString(b)
		res.Key = s.Key
	case "set":
		if err := checkKey(req.Key); err != nil || req.Key == "" {
			if err == nil {
				err = fmt.Errorf("enter the key")
			}
			return nil, &Error{Code: CodeInvalid, Message: err.Error(), Details: []Detail{{Path: "key", Message: err.Error()}}}
		}
		s.Key = req.Key
	default:
		return nil, errorf(CodeInvalid, "signing: keep, none, generate or set")
	}
	h.secrets[id] = s
	if err := m.saveSecrets(h); err != nil {
		return nil, err
	}
	res.WebhookStatus = WebhookStatus{ID: id, Target: webhook.Target(s.URL), Signed: s.Key != ""}
	return res, nil
}

// TestWebhook sends a test event to a webhook now and says how it went.
func (m *Manager) TestWebhook(id string) (*WebhookStatus, error) {
	h := m.hooks()
	h.mu.Lock()
	s, ok := h.secrets[id]
	h.mu.Unlock()
	if !ok {
		return nil, errorf(CodeNotFound, "set the webhook's URL first")
	}
	e := Event{Time: time.Now(), Kind: EventOPF, Message: "A test from OPF: this webhook works."}
	err := m.send(s, m.delivery(e, true, m.formatOf(id)))
	t := time.Now()
	h.mu.Lock()
	st := h.stateOf(id)
	st.lastAttempt = &t
	if err == nil {
		st.lastOK, st.lastError = &t, ""
	} else {
		st.lastError = err.Error()
	}
	res := WebhookStatus{ID: id, Target: webhook.Target(s.URL), Signed: s.Key != "", LastAttempt: st.lastAttempt, LastOK: st.lastOK, LastError: st.lastError, Queued: len(st.queue), Dropped: st.dropped}
	h.mu.Unlock()
	return &res, nil
}
