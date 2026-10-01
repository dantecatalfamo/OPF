// Package webhook sends OPF's events to a URL as JSON, signed so the
// receiver can check they came from this firewall.
//
// The privileged process has no network access, and the web process
// faces the network, so neither sends. Sending is the OPF binary
// started as the unprivileged user (see cmd/opf), sandboxed to making
// connections and reading the certificates and resolver files; it
// reads what to send on stdin, never the command line, which any user
// can read with ps. Redirects aren't followed, so a secret in the URL
// isn't sent anywhere else.
//
// A delivery is a POST of Body with:
//
//	Content-Type: application/json
//	User-Agent: OPF
//	X-OPF-Timestamp: <unix seconds>
//	X-OPF-Signature: sha256=<hex HMAC-SHA256 of "<timestamp>.<body>" with the key>
//
// The signature is there when the webhook has a key. A receiver should
// compute it and compare, and refuse a timestamp more than a few
// minutes old, so a delivery can't be replayed later.
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// Request is what the sender reads on stdin. ContentType is the body's
// (JSON if empty); Headers are more to send (ntfy's Title and
// Priority), names of letters, digits and hyphens.
type Request struct {
	URL         string            `json:"url"`
	Key         string            `json:"key,omitempty"`
	Body        []byte            `json:"body"`
	ContentType string            `json:"contentType,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
}

// checkHeaders refuses a header that could be taken for another, or
// that would break the request.
func checkHeaders(h map[string]string) error {
	if len(h) > 8 {
		return errors.New("too many headers")
	}
	for k, v := range h {
		if k == "" || len(k) > 64 || strings.ContainsFunc(k, func(r rune) bool {
			return !(r == '-' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9')
		}) {
			return fmt.Errorf("a header's name isn't one")
		}
		if len(v) > 1024 || strings.ContainsAny(v, "\r\n\x00") {
			return fmt.Errorf("header %s has a value that can't be sent", k)
		}
		switch http.CanonicalHeaderKey(k) {
		case "Host", "Content-Length", "Content-Type", "Transfer-Encoding", "Connection", "X-Opf-Signature", "X-Opf-Timestamp":
			return fmt.Errorf("header %s is set by the sender", k)
		}
	}
	return nil
}

// Limits.
const (
	MaxURL     = 2048
	MaxKey     = 256
	MaxBody    = 64 << 10
	MaxRequest = 1 << 20 // what the sender reads from stdin
	Timeout    = 15 * time.Second
)

// CheckURL says what's wrong with a webhook's URL, if anything: it must
// be http or https with a host, no user name or password (put a token
// in the path or query), no fragment, and printable.
func CheckURL(s string) error {
	if s == "" {
		return errors.New("enter the URL to send to")
	}
	if len(s) > MaxURL {
		return fmt.Errorf("at most %d characters", MaxURL)
	}
	if strings.ContainsFunc(s, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) {
		return errors.New("no spaces or control characters")
	}
	u, err := url.Parse(s)
	if err != nil {
		return errors.New("that isn't a URL")
	}
	switch {
	case u.Scheme != "https" && u.Scheme != "http":
		return errors.New("use an https:// (or http://) URL")
	case u.Host == "" || u.Hostname() == "":
		return errors.New("the URL needs a host")
	case u.User != nil:
		return errors.New("leave out a user name and password; put a token in the path or query instead")
	case u.Fragment != "" || strings.Contains(s, "#"):
		return errors.New("leave out the #fragment")
	}
	return nil
}

// Target is what may be shown of a URL: its scheme and host, never its
// path or query, which often hold its secret.
func Target(s string) string {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// Sign is the signature of a delivery: hex HMAC-SHA256 of
// "<timestamp>.<body>".
func Sign(key string, ts int64, body []byte) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(strconv.FormatInt(ts, 10) + "."))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// Send delivers a request. A 2xx answer is success; anything else, or
// no answer within Timeout, is an error saying what happened.
func Send(ctx context.Context, r Request, now time.Time) error {
	if err := CheckURL(r.URL); err != nil {
		return err
	}
	if len(r.Body) > MaxBody {
		return errors.New("the event is too large to send")
	}
	if err := checkHeaders(r.Headers); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.URL, bytes.NewReader(r.Body))
	if err != nil {
		return err
	}
	ts := now.Unix()
	ct := r.ContentType
	if ct == "" {
		ct = "application/json"
	}
	for k, v := range r.Headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", ct)
	req.Header.Set("User-Agent", "OPF")
	req.Header.Set("X-OPF-Timestamp", strconv.FormatInt(ts, 10))
	if r.Key != "" {
		req.Header.Set("X-OPF-Signature", "sha256="+Sign(r.Key, ts, r.Body))
	}
	client := &http.Client{
		// Not followed: the secret in the URL would go wherever the
		// answer points.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // without the URL, which may hold the secret
		}
		return fmt.Errorf("couldn't send: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("the receiver answered %s", resp.Status)
	}
	return nil
}
