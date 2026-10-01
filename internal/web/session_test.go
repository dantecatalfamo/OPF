package web

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dantecatalfamo/OPF/internal/appliance"
	"github.com/dantecatalfamo/OPF/internal/auth"
	"github.com/dantecatalfamo/OPF/internal/privsep"
)

// newAuthServer is the web server in front of a privileged process
// with accounts: an admin and a viewer.
func newAuthServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "master.passwd"), []byte(
		"admin:$2b$a:1000:1000::0:0:Admin:/home/admin:/bin/ksh\nviewer:$2b$v:1002:1002::0:0:Viewer:/home/viewer:/bin/ksh\n"), 0600)
	os.WriteFile(filepath.Join(dir, "group"), []byte("_opfadmin:*:900:admin\n_opfview:*:902:viewer\n"), 0644)
	sessions := auth.NewSessions(auth.Static{"admin": "admin-pass", "viewer": "viewer-pass"})
	sessions.Passwd, sessions.Group, sessions.MinFail = filepath.Join(dir, "master.passwd"), filepath.Join(dir, "group"), 0
	a, b := net.Pipe()
	go privsep.Serve(newManager(t), privsep.ServeOptions{Sessions: sessions}, a)
	c := privsep.NewClient(b)
	t.Cleanup(func() { c.Close() })
	s := New(c, nil)
	s.RequireAuth(AuthOf(c.Login, c.WithToken), "AB:CD")
	return s
}

// browser keeps the session cookie, as a browser would.
type browser struct {
	t      *testing.T
	s      *Server
	cookie *http.Cookie
}

func (b *browser) do(method, path, body string, want int) *httptest.ResponseRecorder {
	b.t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = "192.0.2.7:51000"
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set(activeHeader, "1")
	if b.cookie != nil {
		req.AddCookie(b.cookie)
	}
	rec := httptest.NewRecorder()
	b.s.ServeHTTP(rec, req)
	if rec.Code != want {
		b.t.Fatalf("%s %s: status %d, want %d\n%s", method, path, rec.Code, want, rec.Body)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == cookieName {
			if c.MaxAge < 0 {
				b.cookie = nil
			} else {
				b.cookie = c
			}
		}
	}
	return rec
}

func TestSignIn(t *testing.T) {
	b := &browser{t: t, s: newAuthServer(t)}
	// Not signed in: only the sign-in endpoints answer.
	if r := b.do("GET", "/api/session", "", 200); !strings.Contains(r.Body.String(), `"accounts":true`) || strings.Contains(r.Body.String(), `"session"`) || !strings.Contains(r.Body.String(), `"tls":"AB:CD"`) {
		t.Errorf("session before signing in: %s", r.Body)
	}
	for _, p := range []string{"/api/config", "/api/status", "/api/commits", "/api/sessions"} {
		b.do("GET", p, "", 401)
	}
	// Answered in this process, so checked here too.
	b.do("POST", "/api/pf/parse", `{"text":"pass all"}`, 401)

	b.do("POST", "/api/session", `{"user":"admin","password":"wrong"}`, 401)
	b.do("POST", "/api/session", `{"user":"admin","password":"admin-pass"}`, 429) // backed off
	b2 := &browser{t: t, s: b.s}
	b2.do("POST", "/api/session", `{"user":"viewer","password":"viewer-pass"}`, 429) // the same address
}

func TestSessionCookie(t *testing.T) {
	s := newAuthServer(t)
	b := &browser{t: t, s: s}
	r := b.do("POST", "/api/session", `{"user":" admin ","password":"admin-pass"}`, 200)
	c := b.cookie
	if c == nil || !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" || c.Domain != "" || len(c.Value) < 40 {
		t.Fatalf("cookie %+v", c)
	}
	if strings.Contains(r.Body.String(), c.Value) {
		t.Error("the token is in the body")
	}
	if !strings.Contains(r.Body.String(), `"user":"admin"`) || !strings.Contains(r.Body.String(), `"role":"admin"`) {
		t.Errorf("body %s", r.Body)
	}
	b.do("GET", "/api/config", "", 200)
	b.do("POST", "/api/pf/parse", `{"text":"pass all"}`, 200)

	// A viewer can look but not change.
	v := &browser{t: t, s: s}
	v.do("POST", "/api/session", `{"user":"viewer","password":"viewer-pass"}`, 200)
	var live appliance.Config
	if err := json.Unmarshal(v.do("GET", "/api/config", "", 200).Body.Bytes(), &live); err != nil {
		t.Fatal(err)
	}
	v.do("PUT", "/api/config/staged", js(appliance.StageRequest{Base: live.Version, Model: live.Model}), 403)

	// Signing out ends it here and in the privileged process.
	old := *b.cookie
	b.do("DELETE", "/api/session", "", 204)
	if b.cookie != nil {
		t.Error("cookie not cleared")
	}
	b.cookie = &old
	b.do("GET", "/api/config", "", 401)
}
