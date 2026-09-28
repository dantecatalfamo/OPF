package web

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dantecatalfamo/OPF/internal/config"
	"github.com/dantecatalfamo/OPF/internal/run"
)

func TestStageCommitConfirm(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc/pf.conf"), []byte("pass\n"), 0600); err != nil {
		t.Fatal(err)
	}
	store, err := config.New(config.Options{
		Root: root, StateDir: t.TempDir(), Files: config.DefaultFiles(),
		Runner: run.Dry{}, ConfirmTimeout: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(store, "")
	if err != nil {
		t.Fatal(err)
	}

	do := func(method, path string, form url.Values, want ...string) string {
		t.Helper()
		var body io.Reader
		if form != nil {
			body = strings.NewReader(form.Encode())
		}
		req := httptest.NewRequest(method, path, body)
		if form != nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("HX-Request", "true")
		}
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		if rec.Code >= 400 {
			t.Fatalf("%s %s: %d\n%s", method, path, rec.Code, rec.Body)
		}
		got := rec.Body.String()
		for _, w := range want {
			if !strings.Contains(got, w) {
				t.Fatalf("%s %s: missing %q in\n%s", method, path, w, got)
			}
		}
		return got
	}

	do("GET", "/", nil, "pf.conf", "/etc/pf.conf")
	do("GET", "/files/pf.conf", nil, "<textarea", "pass")
	do("POST", "/files/pf.conf/check", url.Values{"content": {"block\r\n"}}, "Check passed")
	do("POST", "/files/pf.conf", url.Values{"content": {"block\r\n"}}, "Staged", `class="add">&#43;block`, `class="del">-pass`)
	do("GET", "/banner", nil, "1 staged change ")
	do("GET", "/changes", nil, "Check and commit", "needs confirmation")
	do("POST", "/commit", url.Values{}, "Confirm using the banner")
	do("GET", "/banner", nil, "Confirm within", "every 1s")
	do("POST", "/confirm", url.Values{})

	if data, _ := os.ReadFile(filepath.Join(root, "etc/pf.conf")); string(data) != "block\n" {
		t.Fatalf("pf.conf = %q", data)
	}
	h, _ := store.History()
	do("GET", "/history", nil, h[0].ID, "confirmed")
	do("GET", "/history/"+h[0].ID, nil, "Stage version before this commit", "pfctl -f")

	req := httptest.NewRequest("GET", "/files/nope", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown file: %d", rec.Code)
	}
}
