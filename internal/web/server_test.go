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
	"github.com/dantecatalfamo/OPF/internal/diag"
	"github.com/dantecatalfamo/OPF/internal/pf"
	"github.com/dantecatalfamo/OPF/internal/run"
	"testing/fstest"
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
	api.Runner = run.Dry{} // tests never run the system's commands
	return New(api, nil)
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
	var out pf.Rendered
	r.Rule.Description = "SSH"
	c.do("POST", "/api/pf/render", js(renderRequest{Rule: r.Rule}), 200, &out)
	if len(out.Lines) != 1 || out.Lines[0] != "pass in proto tcp from any to any port 22" || out.Comment != "# SSH" {
		t.Fatalf("render %+v", out)
	}
	c.do("POST", "/api/pf/parse", `{"text":"not pf"}`, 422, nil)
	// Exactly one object to render.
	c.do("POST", "/api/pf/render", `{}`, 422, nil)
	c.do("POST", "/api/pf/render", js(renderRequest{Rule: r.Rule, NAT: &pf.NATRule{}}), 422, nil)

	var live appliance.Config
	c.do("GET", "/api/config", "", 200, &live)
	var fwd pf.Rendered
	c.do("POST", "/api/pf/render", js(renderRequest{Model: live.Model, Forward: &live.Model.Firewall.Forwards[0]}), 200, &fwd)
	if len(fwd.Lines) < 2 || !strings.Contains(fwd.Lines[0], "rdr-to") {
		t.Errorf("forward %+v", fwd)
	}

	var rs rulesetBody
	c.do("POST", "/api/pf/ruleset", js(modelRequest{live.Model}), 200, &rs)
	origins := 0
	for _, l := range rs.Lines {
		if l.Origin != nil {
			origins++
		}
	}
	if len(rs.Lines) < 20 || origins == 0 {
		t.Errorf("ruleset: %d lines, %d with an origin", len(rs.Lines), origins)
	}

	var d pf.Derived
	c.do("POST", "/api/pf/derived", js(modelRequest{live.Model}), 200, &d)
	if len(d.AutomaticNAT) == 0 || len(d.LocalNetworks) == 0 || d.Rules["r3"] == "" || d.DynamicIfaces["wan"] != true || d.DynamicIfaces["lan"] != false {
		t.Errorf("derived %+v", d)
	}
	// No model is an empty one, not an error.
	c.do("POST", "/api/pf/derived", `{}`, 200, nil)
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

func TestUI(t *testing.T) {
	api := newServer(t).api
	files := fstest.MapFS{
		"index.html":               {Data: []byte("<!doctype html><title>OPF</title>")},
		"assets/index-abc123.js":   {Data: []byte("console.log(1)")},
		"assets/index-abc123.css":  {Data: []byte("body{}")},
		"assets/plex-abc123.woff2": {Data: []byte("wOF2")},
	}
	s := New(api, files)
	get := func(method, p string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, httptest.NewRequest(method, p, nil))
		return rec
	}
	for _, c := range []struct {
		path, body, ctype, cache string
		status                   int
	}{
		{"/", "<!doctype html>", "text/html", "no-cache", 200},
		{"/firewall/rules/lan", "<!doctype html>", "text/html", "no-cache", 200}, // the UI's own route
		{"/etc/passwd", "<!doctype html>", "text/html", "no-cache", 200},         // only the UI's files, never the system's
		{"/assets/index-abc123.js", "console.log", "text/javascript", "immutable", 200},
		{"/assets/index-abc123.css", "body{}", "text/css", "immutable", 200},
		{"/assets/plex-abc123.woff2", "wOF2", "font/woff2", "immutable", 200},
		{"/assets/missing.js", "", "", "", 404},
	} {
		rec := get("GET", c.path)
		if rec.Code != c.status {
			t.Errorf("%s: status %d, want %d", c.path, rec.Code, c.status)
			continue
		}
		h := rec.Header()
		if !strings.Contains(h.Get("Content-Security-Policy"), "frame-ancestors 'none'") || h.Get("X-Frame-Options") != "DENY" ||
			h.Get("X-Content-Type-Options") != "nosniff" || h.Get("Referrer-Policy") != "no-referrer" {
			t.Errorf("%s: missing security headers: %v", c.path, h)
		}
		if c.status != 200 {
			continue
		}
		if !strings.Contains(rec.Body.String(), c.body) || !strings.HasPrefix(h.Get("Content-Type"), c.ctype) || !strings.Contains(h.Get("Cache-Control"), c.cache) {
			t.Errorf("%s: body %q, type %q, cache %q", c.path, rec.Body.String(), h.Get("Content-Type"), h.Get("Cache-Control"))
		}
	}
	// Paths with dot-dot are cleaned by a redirect first.
	if rec := get("GET", "/../../etc/passwd"); rec.Code != 307 || rec.Header().Get("Location") != "/etc/passwd" {
		t.Errorf("dot-dot: %d, Location %q", rec.Code, rec.Header().Get("Location"))
	}
	if rec := get("HEAD", "/"); rec.Code != 200 || rec.Body.Len() != 0 {
		t.Errorf("HEAD /: %d, %d bytes", rec.Code, rec.Body.Len())
	}
	if rec := get("POST", "/"); rec.Code != 405 || rec.Header().Get("Allow") != "GET, HEAD" {
		t.Errorf("POST /: %d, Allow %q", rec.Code, rec.Header().Get("Allow"))
	}
	// The API is unchanged, and not handed to the UI.
	if rec := get("GET", "/api/nope"); rec.Code != 404 || !strings.Contains(rec.Body.String(), `"not_found"`) || rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("/api/nope: %d %q %q", rec.Code, rec.Body.String(), rec.Header().Get("Cache-Control"))
	}

	// Built without the UI: a page that says so, and the API still works.
	s = New(api, nil)
	if rec := get("GET", "/"); rec.Code != 404 || !strings.Contains(rec.Body.String(), "make build") {
		t.Errorf("no UI: %d %q", rec.Code, rec.Body.String())
	}
	if rec := get("GET", "/api/status"); rec.Code != 200 {
		t.Errorf("no UI, /api/status: %d", rec.Code)
	}
}

func TestTools(t *testing.T) {
	c := client{t, newServer(t)}
	var r diag.Run
	c.do("POST", "/api/diagnostics/runs", `{"tool":"ping","host":"9.9.9.9","count":2}`, http.StatusCreated, &r)
	if r.ID == "" || r.Command != "ping -c 2 -s 56 -w 2 -- 9.9.9.9" {
		t.Fatalf("started %+v", r)
	}
	for range 100 {
		c.do("GET", "/api/diagnostics/runs/"+r.ID+"?from=0", "", http.StatusOK, &r)
		if !r.Running {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	// The dry runner prints what it would have run.
	if r.Running || len(r.Lines) != 1 || !strings.HasPrefix(r.Lines[0], "dry-run: ping") {
		t.Errorf("finished %+v", r)
	}
	c.do("POST", "/api/diagnostics/runs/"+r.ID+"/cancel", "", http.StatusNoContent, nil)

	var e struct{ Error appliance.Error }
	c.do("POST", "/api/diagnostics/runs", `{"tool":"ping","host":"-f"}`, http.StatusUnprocessableEntity, &e)
	if len(e.Error.Details) != 1 || e.Error.Details[0].Path != "host" {
		t.Errorf("invalid: %+v", e.Error)
	}
	c.do("POST", "/api/diagnostics/runs", `{"tool":"rm"}`, http.StatusUnprocessableEntity, nil)
	c.do("POST", "/api/diagnostics/runs", `{"tool":"ping","host":"a","extra":1}`, http.StatusBadRequest, nil)
	c.do("GET", "/api/diagnostics/runs/nope", "", http.StatusNotFound, nil)
	c.do("GET", "/api/diagnostics/runs/"+r.ID+"?from=-1", "", http.StatusBadRequest, nil)
}
