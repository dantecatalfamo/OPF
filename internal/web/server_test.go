package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dantecatalfamo/OPF/internal/appliance"
	"github.com/dantecatalfamo/OPF/internal/config"
	"github.com/dantecatalfamo/OPF/internal/pf"
	"github.com/dantecatalfamo/OPF/internal/run"
)

func newServer(t *testing.T) *Server {
	t.Helper()
	data, err := os.ReadFile("../../ui/src/model/sample-model.json")
	if err != nil {
		t.Fatal(err)
	}
	var model pf.Model
	if err := json.Unmarshal(data, &model); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	write := func(path string, b []byte) {
		p := filepath.Join(root, path)
		os.MkdirAll(filepath.Dir(p), 0755)
		if err := os.WriteFile(p, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range pf.GenerateFiles(&model) {
		write(f.Path, config.Normalize([]byte(f.Content)))
	}
	enc, _ := appliance.EncodeModel(&model)
	write(config.ModelPath, enc)
	store, err := config.New(config.Options{Root: root, StateDir: t.TempDir(), Files: config.DefaultFiles(), Runner: run.Dry{}, ConfirmTimeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	api, err := appliance.New(store)
	if err != nil {
		t.Fatal(err)
	}
	return New(api)
}

type client struct {
	t *testing.T
	s *Server
}

func (c client) do(method, path, body string, want int, out any) http.Header {
	c.t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	c.s.ServeHTTP(rec, req)
	if rec.Code != want {
		c.t.Fatalf("%s %s: status %d, want %d\n%s", method, path, rec.Code, want, rec.Body)
	}
	if out != nil {
		if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
			c.t.Fatalf("%s %s: %v\n%s", method, path, err, rec.Body)
		}
	}
	return rec.Header()
}

func js(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestCommitLifecycle(t *testing.T) {
	c := client{t, newServer(t)}

	var live appliance.Config
	h := c.do("GET", "/api/config", "", 200, &live)
	if h.Get("ETag") != `"`+live.Version+`"` || h.Get("Cache-Control") != "no-store" {
		t.Fatalf("headers %v", h)
	}
	c.do("GET", "/api/config/staged", "", 404, nil)

	live.Model.Firewall.Rules[5].Enabled = false // Allow LAN to anywhere
	var staged appliance.Staged
	c.do("PUT", "/api/config/staged", js(appliance.StageRequest{Base: live.Version, Model: live.Model}), 200, &staged)
	if len(staged.Changes) != 2 {
		t.Fatalf("changes %+v", staged.Changes)
	}

	var commit appliance.Commit
	h = c.do("POST", "/api/commits", js(appliance.CommitRequest{
		Staged: staged.Version, Message: "Close LAN",
		Changes: []config.ChangeNote{{Area: "firewall", Summary: "Disabled rule “Allow LAN to anywhere”"}},
	}), 201, &commit)
	if commit.Status != appliance.StatusPending || h.Get("Location") != "/api/commits/"+commit.ID {
		t.Fatalf("commit %+v, Location %q", commit, h.Get("Location"))
	}

	var st appliance.Status
	c.do("GET", "/api/status", "", 200, &st)
	if st.Pending == nil || st.Pending.ID != commit.ID || st.Pending.Deadline == nil {
		t.Fatalf("status %+v", st)
	}
	c.do("POST", "/api/commits/20000101-000000.000/confirm", "", 404, nil)
	var confirmed appliance.Commit
	c.do("POST", "/api/commits/"+commit.ID+"/confirm", "", 200, &confirmed)
	if confirmed.Status != appliance.StatusConfirmed {
		t.Fatalf("confirmed %+v", confirmed)
	}
	c.do("POST", "/api/commits/"+commit.ID+"/confirm", "", 409, nil)

	var list []appliance.Commit
	c.do("GET", "/api/commits", "", 200, &list)
	if len(list) != 1 || list[0].Changes[0].Area != "firewall" {
		t.Fatalf("list %+v", list)
	}
	var detail appliance.CommitDetail
	c.do("GET", "/api/commits/"+commit.ID, "", 200, &detail)
	if len(detail.Diffs) != 2 || !strings.Contains(detail.Log, "pfctl") {
		t.Fatalf("detail %+v", detail)
	}

	var before appliance.Config
	c.do("GET", "/api/commits/"+commit.ID+"/config/before", "", 200, &before)
	if before.Version != live.Version {
		t.Fatalf("before %s, want %s", before.Version, live.Version)
	}
	c.do("GET", "/api/commits/"+commit.ID+"/config/sideways", "", 404, nil)
	c.do("GET", "/api/commits/nope/config/before", "", 404, nil)
	c.do("GET", "/api/config/staged", "", 404, nil) // reading it staged nothing
	var now appliance.Config
	c.do("GET", "/api/config", "", 200, &now)
	var restored appliance.Staged
	c.do("PUT", "/api/config/staged", js(appliance.StageRequest{Base: now.Version, Model: before.Model}), 200, &restored)
	if restored.Version != live.Version {
		t.Fatalf("restored %s, want %s", restored.Version, live.Version)
	}
	c.do("DELETE", "/api/config/staged", "", 204, nil)
	c.do("POST", "/api/commits", js(appliance.CommitRequest{Staged: restored.Version}), 409, nil)
}

func TestRequestErrors(t *testing.T) {
	c := client{t, newServer(t)}
	var live appliance.Config
	c.do("GET", "/api/config", "", 200, &live)

	var e errorBody
	bad := *live.Model
	bad.Interfaces[1].Name = `LAN" up`
	c.do("PUT", "/api/config/staged", js(appliance.StageRequest{Base: live.Version, Model: &bad}), 422, &e)
	if e.Error.Code != appliance.CodeInvalid || e.Error.Details[0].Path != "interfaces[1].name" {
		t.Fatalf("invalid: %+v", e.Error)
	}
	c.do("PUT", "/api/config/staged", js(appliance.StageRequest{Base: "stale", Model: live.Model}), 409, &e)
	if e.Error.Code != appliance.CodeConflict {
		t.Fatalf("stale base: %+v", e.Error)
	}
	c.do("PUT", "/api/config/staged", `{"base":"x","model":{},"extra":1}`, 400, nil)
	c.do("PUT", "/api/config/staged", `{"base":"x"} {}`, 400, nil)
	c.do("GET", "/api/nope", "", 404, &e)
	c.do("GET", "/api/commits/..%2F..%2Fetc", "", 404, nil)

	// Not JSON: refused before anything is read, which also stops
	// cross-site HTML form posts.
	req := httptest.NewRequest("PUT", "/api/config/staged", strings.NewReader("base=x"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	c.s.ServeHTTP(rec, req)
	if rec.Code != 415 {
		t.Fatalf("form post: %d", rec.Code)
	}
	req = httptest.NewRequest("PUT", "/api/config/staged", strings.NewReader(`{"base":"`+strings.Repeat("a", maxBody)+`"}`))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	c.s.ServeHTTP(rec, req)
	if rec.Code != 413 {
		t.Fatalf("oversized: %d", rec.Code)
	}
}

func TestPfHelpers(t *testing.T) {
	c := client{t, newServer(t)}
	var r ruleBody
	c.do("POST", "/api/pf/parse", `{"text":"pass in proto tcp to port 22"}`, 200, &r)
	if r.Rule.Kind != "form" || r.Rule.Port != "22" {
		t.Fatalf("parse %+v", r.Rule)
	}
	var out renderBody
	c.do("POST", "/api/pf/render", js(renderRequest{Rule: r.Rule}), 200, &out)
	if out.Text != "pass in proto tcp from any to any port 22" {
		t.Fatalf("render %q", out.Text)
	}
	c.do("POST", "/api/pf/parse", `{"text":"not pf"}`, 422, nil)
}

func TestLeaseNames(t *testing.T) {
	c := client{t, newServer(t)}
	var n appliance.LeaseNames
	c.do("GET", "/api/dns/leases", "", 200, &n)
	var l appliance.DHCPLeases
	c.do("GET", "/api/dhcp/leases", "", 200, &l)
	if l.Leases == nil {
		t.Errorf("the list should be empty, not missing: %+v", l)
	}
	if n.Registered == nil || n.Refused == nil {
		t.Errorf("lists should be empty, not missing: %+v", n)
	}
}
