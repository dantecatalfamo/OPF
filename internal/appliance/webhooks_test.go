package appliance

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dantecatalfamo/OPF/internal/pf"
	"github.com/dantecatalfamo/OPF/internal/webhook"
)

// fakeSender records what the sender would be handed, and fails when
// told to.
type fakeSender struct {
	mu   sync.Mutex
	got  []webhook.Request
	env  [][]string
	fail bool
}

func (f *fakeSender) RunInput(_ context.Context, input []byte, env []string, argv ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var r webhook.Request
	json.Unmarshal(input, &r)
	f.got = append(f.got, r)
	f.env = append(f.env, env)
	if f.fail {
		return []byte("the receiver answered 503 Service Unavailable\n"), errors.New("exit status 1")
	}
	return []byte("delivered\n"), nil
}

func (f *fakeSender) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.got)
}

func withWebhooks(t *testing.T, e *env, hooks ...pf.Webhook) {
	t.Helper()
	m := e.live().Model
	m.Notifications = &pf.Notifications{Webhooks: hooks}
	if err := stageCommit(t, e, m); err != nil {
		t.Fatal(err)
	}
}

func TestWebhookSecrets(t *testing.T) {
	e := newEnv(t, time.Minute)
	withWebhooks(t, e, pf.Webhook{ID: "ha", Name: "Home Assistant", Enabled: true})
	secretURL := "https://hooks.example.com/api/webhook/s3cret-path?token=s3cret-token"

	if _, err := e.m.SetWebhookSecret("nope", WebhookSecretRequest{URL: secretURL}); err == nil {
		t.Error("set a secret for a webhook that isn't there")
	}
	for _, bad := range []WebhookSecretRequest{{URL: "ftp://x/y"}, {URL: "https://u:p@example.com/"}, {URL: secretURL, Signing: "set", Key: "has space"}, {URL: secretURL, Signing: "set"}, {URL: secretURL, Signing: "sometimes"}} {
		if _, err := e.m.SetWebhookSecret("ha", bad); err == nil {
			t.Errorf("took %+v", bad)
		}
	}
	res, err := e.m.SetWebhookSecret("ha", WebhookSecretRequest{URL: secretURL, Signing: "generate"})
	if err != nil || len(res.Key) != 64 || res.Target != "https://hooks.example.com" || !res.Signed {
		t.Fatalf("set: %+v %v", res, err)
	}
	key := res.Key

	// Only root can read the file, and it holds the secrets.
	fi, err := os.Stat(e.m.store.StatePath(secretsFile))
	if err != nil || fi.Mode().Perm() != 0600 {
		t.Errorf("secrets file: %v %v", fi.Mode(), err)
	}

	// The secret is nowhere else: not the status, the model, or the
	// history's files.
	st, _ := e.m.Webhooks()
	b, _ := json.Marshal(st)
	cfg, _ := json.Marshal(e.live())
	for what, s := range map[string]string{"status": string(b), "model": string(cfg)} {
		if strings.Contains(s, "s3cret") || strings.Contains(s, key) {
			t.Errorf("the %s shows the secret: %s", what, s)
		}
	}
	filepath.Walk(e.state, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || filepath.Base(p) == secretsFile {
			return nil
		}
		if data, _ := os.ReadFile(p); strings.Contains(string(data), "s3cret") || strings.Contains(string(data), key) {
			t.Errorf("%s holds the secret", p)
		}
		return nil
	})

	// Changing the URL keeps the key unless asked otherwise.
	res, _ = e.m.SetWebhookSecret("ha", WebhookSecretRequest{URL: "https://other.example.com/x"})
	if !res.Signed || res.Key != "" {
		t.Errorf("keep: %+v", res)
	}
	res, _ = e.m.SetWebhookSecret("ha", WebhookSecretRequest{URL: "https://other.example.com/x", Signing: "none"})
	if res.Signed {
		t.Errorf("none: %+v", res)
	}

	// A new Manager reads them back.
	m2, _ := New(e.m.store)
	if st, _ := m2.Webhooks(); len(st) != 1 || st[0].Target != "https://other.example.com" {
		t.Errorf("after a restart: %+v", st)
	}

	// Removing the webhook from the model forgets its secret.
	withWebhooks(t, e)
	e.m.forgetOrphanSecrets(e.m.hooks())
	data, _ := os.ReadFile(e.m.store.StatePath(secretsFile))
	if strings.Contains(string(data), "other.example.com") {
		t.Errorf("kept a removed webhook's secret: %s", data)
	}
}

func TestWebhookDelivery(t *testing.T) {
	e := newEnv(t, time.Minute)
	f := &fakeSender{}
	e.m.Sender, e.m.Exe = f, "/usr/local/bin/opf"
	withWebhooks(t, e,
		pf.Webhook{ID: "all", Name: "All", Enabled: true},
		pf.Webhook{ID: "problems", Name: "Problems", Enabled: true, ProblemsOnly: true},
		pf.Webhook{ID: "links", Name: "Links", Enabled: true, Kinds: []string{"link"}},
		pf.Webhook{ID: "off", Name: "Off", Enabled: false},
		pf.Webhook{ID: "nourl", Name: "No URL", Enabled: true},
	)
	for _, id := range []string{"all", "problems", "links", "off"} {
		if _, err := e.m.SetWebhookSecret(id, WebhookSecretRequest{URL: "https://hooks.example.com/" + id, Signing: "set", Key: "k-" + id}); err != nil {
			t.Fatal(err)
		}
	}
	h := e.m.hooks()
	e.m.eventLog().record(Event{Time: time.Now(), Kind: EventLink, Warning: true, Message: "LAN (em1): link down"})
	e.m.eventLog().record(Event{Time: time.Now(), Kind: EventDevice, Message: "New device"})
	for range 3 {
		e.m.deliverDue(h, time.Now())
	}
	sent := map[string]int{}
	for _, r := range f.got {
		sent[strings.TrimPrefix(r.URL, "https://hooks.example.com/")]++
		if !strings.HasPrefix(r.Key, "k-") {
			t.Errorf("sent without its key: %+v", r)
		}
		var body struct {
			Source string
			Host   string
			Event  Event
		}
		if json.Unmarshal(r.Body, &body) != nil || body.Source != "opf" || body.Host == "" || body.Event.Message == "" {
			t.Errorf("body %s", r.Body)
		}
	}
	// all: both; problems: the link; links: the link; off and no URL:
	// nothing.
	if sent["all"] != 2 || sent["problems"] != 1 || sent["links"] != 1 || sent["off"] != 0 || len(sent) != 3 {
		t.Errorf("sent %v", sent)
	}
	for _, env := range f.env {
		if len(env) != 1 || env[0] != SenderEnv+"=1" {
			t.Errorf("env %v", env)
		}
	}

	// Failures are retried with backoff, then given up on.
	f.mu.Lock()
	f.got, f.fail = nil, true
	f.mu.Unlock()
	e.m.eventLog().record(Event{Time: time.Now(), Kind: EventLink, Warning: true, Message: "WAN down"})
	now := time.Now()
	e.m.deliverDue(h, now)
	e.m.deliverDue(h, now) // not due again yet
	if n := f.count(); n != 3 {
		t.Errorf("first tries: %d", n)
	}
	for i := range retryAfter {
		now = now.Add(retryAfter[i] + time.Second)
		e.m.deliverDue(h, now)
	}
	st, _ := e.m.Webhooks()
	for _, s := range st {
		if s.ID == "links" && (s.Queued != 0 || s.Dropped != 1 || !strings.Contains(s.LastError, "gave up after 6 tries") || !strings.Contains(s.LastError, "503")) {
			t.Errorf("links after failing: %+v", s)
		}
	}

	// Commits are sent as they happen; the first look only remembers.
	f.mu.Lock()
	f.got, f.fail = nil, false
	f.mu.Unlock()
	e.m.noteCommits(h, true)
	m := e.live().Model
	m.System.Hostname = "renamed"
	if err := stageCommit(t, e, m); err != nil {
		t.Fatal(err)
	}
	e.m.noteCommits(h, false)
	e.m.deliverDue(h, time.Now())
	found := false
	for _, r := range f.got {
		found = found || strings.Contains(string(r.Body), `"kind":"commit"`)
	}
	if !found {
		t.Errorf("no commit sent: %d deliveries", len(f.got))
	}

	// A test goes now, marked as one.
	f.mu.Lock()
	f.got = nil
	f.mu.Unlock()
	if st, err := e.m.TestWebhook("all"); err != nil || st.LastOK == nil || !strings.Contains(string(f.got[0].Body), `"test":true`) {
		t.Errorf("test: %+v %v", st, err)
	}
	if _, err := e.m.TestWebhook("nourl"); err == nil {
		t.Error("tested a webhook without a URL")
	}
}

func TestWebhookModel(t *testing.T) {
	m := &pf.Model{Notifications: &pf.Notifications{Webhooks: []pf.Webhook{{ID: "Bad ID", Name: "x"}, {ID: "a", Name: "", Kinds: []string{"link", "nope"}}, {ID: "a", Name: "dup"}}}}
	errs := pf.Validate(m)
	var got []string
	for _, e := range errs {
		if strings.HasPrefix(e.Path, "notifications") {
			got = append(got, e.Path)
		}
	}
	if len(got) < 4 {
		t.Errorf("errors %v", got)
	}
	// The model's kinds are the event log's.
	if len(pf.EventKinds) != len(eventKinds) {
		t.Errorf("kinds differ: %v", pf.EventKinds)
	}
	for _, k := range pf.EventKinds {
		if !eventKinds[k] {
			t.Errorf("%s isn't an event kind", k)
		}
	}
}
