package web

import (
	"bytes"
	"compress/gzip"
	"io"
	"io/fs"
	"net/http"
	"strings"
	"sync"
)

// Responses are gzipped for clients that accept it: the API's JSON is
// repetitive (a model, a state table) and shrinks five to ten times,
// which matters over a slow VPN.
//
// Compression and secrets don't mix: when a response holds a secret
// and also text an attacker can influence, its compressed size can
// leak the secret (BREACH). No response holds a secret today (the
// model has WireGuard public keys only, and sessions will live in
// cookies, which aren't compressed). A response that ever carries one,
// a private key or a CSRF token, must set Content-Encoding: identity
// (noCompression) so it's sent as it is.

// accepts says whether the client takes gzip.
func accepts(r *http.Request) bool {
	for _, part := range strings.Split(r.Header.Get("Accept-Encoding"), ",") {
		name, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		if strings.EqualFold(strings.TrimSpace(name), "gzip") {
			q := strings.ReplaceAll(params, " ", "")
			return q != "q=0" && q != "q=0.0" && q != "q=0.00" && q != "q=0.000"
		}
	}
	return false
}

// compressible are the types worth compressing; images and archives
// already are.
func compressible(ct string) bool {
	ct, _, _ = strings.Cut(ct, ";")
	switch strings.TrimSpace(ct) {
	case "application/json", "text/html", "text/css", "text/javascript", "application/javascript", "image/svg+xml", "application/wasm", "text/plain":
		return true
	}
	return false
}

// noCompression marks a response to be sent uncompressed (see above).
func noCompression(w http.ResponseWriter) { w.Header().Set("Content-Encoding", "identity") }

// gzipWriter compresses a response as it's written, once its headers
// say it's a type worth compressing.
type gzipWriter struct {
	http.ResponseWriter
	gz      *gzip.Writer
	started bool
}

func (g *gzipWriter) WriteHeader(code int) {
	if g.started {
		return
	}
	g.started = true
	h := g.Header()
	switch {
	case h.Get("Content-Encoding") == "identity":
		h.Del("Content-Encoding")
	case h.Get("Content-Encoding") == "" && compressible(h.Get("Content-Type")) && code != http.StatusNoContent && code != http.StatusNotModified:
		h.Set("Content-Encoding", "gzip")
		h.Del("Content-Length")
		g.gz, _ = gzip.NewWriterLevel(g.ResponseWriter, gzip.BestSpeed)
	}
	g.ResponseWriter.WriteHeader(code)
}

func (g *gzipWriter) Write(b []byte) (int, error) {
	if !g.started {
		if g.Header().Get("Content-Type") == "" {
			g.Header().Set("Content-Type", http.DetectContentType(b))
		}
		g.WriteHeader(http.StatusOK)
	}
	if g.gz != nil {
		return g.gz.Write(b)
	}
	return g.ResponseWriter.Write(b)
}

func (g *gzipWriter) Flush() {
	if g.gz != nil {
		g.gz.Flush()
	}
	if f, ok := g.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (g *gzipWriter) close() {
	if g.gz != nil {
		g.gz.Close()
	}
}

// withGzip compresses h's responses for clients that accept it.
func withGzip(w http.ResponseWriter, r *http.Request, h func(http.ResponseWriter, *http.Request)) {
	w.Header().Add("Vary", "Accept-Encoding")
	if !accepts(r) {
		h(w, r)
		return
	}
	g := &gzipWriter{ResponseWriter: w}
	defer g.close()
	h(g, r)
}

// uiGzip keeps the UI's files compressed: they're fixed for the life of
// the binary, so each is compressed once, at the best level.
type uiGzip struct {
	mu    sync.Mutex
	files map[string][]byte
}

// get returns name compressed, or false if it isn't worth it.
func (c *uiGzip) get(fsys fs.FS, name string) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if b, ok := c.files[name]; ok {
		return b, b != nil
	}
	if c.files == nil {
		c.files = map[string][]byte{}
	}
	f, err := fsys.Open(name)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	raw, err := io.ReadAll(f)
	if err != nil {
		return nil, false
	}
	var buf bytes.Buffer
	gz, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	gz.Write(raw)
	gz.Close()
	if buf.Len() >= len(raw) {
		c.files[name] = nil // not smaller: send it as it is
		return nil, false
	}
	c.files[name] = buf.Bytes()
	return c.files[name], true
}
