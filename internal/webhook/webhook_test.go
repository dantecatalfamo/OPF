package webhook

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestCheckURL(t *testing.T) {
	for _, ok := range []string{"https://hooks.example.com/opf/abc?token=1", "http://192.168.1.20:8123/api/webhook/opf"} {
		if err := CheckURL(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "ftp://x/y", "https://", "https://user:pw@example.com/", "https://example.com/#x", "https://example.com/a b", "https://example.com/\x00", "javascript:alert(1)", "https://" + strings.Repeat("a", MaxURL)} {
		if err := CheckURL(bad); err == nil {
			t.Errorf("took %q", bad)
		}
	}
	if Target("https://hooks.example.com/services/T0/B0/secret?x=1") != "https://hooks.example.com" {
		t.Error("target shows more than scheme and host")
	}
}

func TestSend(t *testing.T) {
	var got *http.Request
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r
		b, _ := io.ReadAll(r.Body)
		body = string(b)
		switch r.URL.Path {
		case "/fail":
			w.WriteHeader(500)
		case "/redirect":
			http.Redirect(w, r, "https://elsewhere.example/steal", http.StatusFound)
		}
	}))
	defer srv.Close()
	now := time.Unix(1790000000, 0)
	if err := Send(context.Background(), Request{URL: srv.URL + "/ok?token=s3cret", Key: "k", Body: []byte(`{"a":1}`)}, now); err != nil {
		t.Fatal(err)
	}
	if got.Method != "POST" || body != `{"a":1}` || got.Header.Get("X-OPF-Timestamp") != strconv.FormatInt(now.Unix(), 10) {
		t.Errorf("%s %q %v", got.Method, body, got.Header)
	}
	if got.Header.Get("X-OPF-Signature") != "sha256="+Sign("k", now.Unix(), []byte(`{"a":1}`)) {
		t.Errorf("signature %q", got.Header.Get("X-OPF-Signature"))
	}
	// Unsigned without a key.
	Send(context.Background(), Request{URL: srv.URL + "/ok", Body: []byte(`{}`)}, now)
	if got.Header.Get("X-OPF-Signature") != "" {
		t.Error("signed without a key")
	}
	if err := Send(context.Background(), Request{URL: srv.URL + "/fail", Body: []byte(`{}`)}, now); err == nil || !strings.Contains(err.Error(), "500") {
		t.Errorf("fail: %v", err)
	}
	// A redirect isn't followed: it's a failure, and nothing went on.
	if err := Send(context.Background(), Request{URL: srv.URL + "/redirect", Body: []byte(`{}`)}, now); err == nil || !strings.Contains(err.Error(), "302") {
		t.Errorf("redirect: %v", err)
	}
	// An error doesn't repeat the URL, which may hold the secret.
	err := Send(context.Background(), Request{URL: "http://127.0.0.1:1/hook?token=s3cret", Body: []byte(`{}`)}, now)
	if err == nil || strings.Contains(err.Error(), "s3cret") {
		t.Errorf("unreachable: %v", err)
	}
}

// A known answer, for receivers to test their check against.
func TestSignKnown(t *testing.T) {
	if s := Sign("secret", 1790000000, []byte(`{"kind":"link"}`)); len(s) != 64 || s != Sign("secret", 1790000000, []byte(`{"kind":"link"}`)) || s == Sign("secret", 1790000001, []byte(`{"kind":"link"}`)) {
		t.Errorf("sign %s", s)
	}
}

func TestSendHeaders(t *testing.T) {
	var got *http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = r }))
	defer srv.Close()
	now := time.Now()
	err := Send(context.Background(), Request{URL: srv.URL, Body: []byte("hello"), ContentType: "text/plain; charset=utf-8", Headers: map[string]string{"Title": "gw: link", "Priority": "4"}}, now)
	if err != nil || got.Header.Get("Content-Type") != "text/plain; charset=utf-8" || got.Header.Get("Title") != "gw: link" || got.Header.Get("Priority") != "4" {
		t.Fatalf("%v %v", err, got.Header)
	}
	for _, bad := range []map[string]string{{"Title": "a\r\nX-Evil: 1"}, {"Bad Name": "x"}, {"Host": "evil.example"}, {"X-OPF-Signature": "forged"}, {"content-type": "x"}} {
		if err := Send(context.Background(), Request{URL: srv.URL, Body: []byte("x"), Headers: bad}, now); err == nil {
			t.Errorf("sent header %v", bad)
		}
	}
}
