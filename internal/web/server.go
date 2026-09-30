// Package web serves OPF's JSON API. It runs in the unprivileged web
// process and reaches the configuration only through appliance.API.
//
// Resources:
//
//	GET    /api/status                    live and staged versions, pending commit
//	GET    /api/config                    the live model
//	GET    /api/config/staged             the staged model and the file changes it makes
//	PUT    /api/config/staged             stage a model
//	DELETE /api/config/staged             discard it
//	GET    /api/commits                   history, newest first
//	POST   /api/commits                   commit the staged model
//	GET    /api/commits/{id}              a commit with its diffs and log
//	POST   /api/commits/{id}/confirm      keep a pending commit
//	POST   /api/commits/{id}/revert       undo a pending commit now
//	GET    /api/commits/{id}/config/{which}  the model before or after a commit
//	GET    /api/dhcp/leases               dhcpd's current leases
//	GET    /api/dns/leases                names DHCP leases have in DNS, and refused ones
//	GET    /api/network/arp               the ARP table
//	GET    /api/network/routes            the routing table
//	GET    /api/network/interfaces        every interface's state, counters and traffic
//	GET    /api/network/gateways          whether each gateway answers pings
//	GET    /api/system                    the machine: release, uptime, CPU, memory, disks, sensors
//	GET    /api/system/updates            security patches available
//	POST   /api/pf/parse                  pf rule text to a rule
//	POST   /api/pf/ruleset                a model's annotated pf.conf
//	POST   /api/pf/derived                what the UI shows that depends on generation
//	POST   /api/pf/render                 a rule to pf rule text
//
// Errors are {"error": {"code", "message", "details"}} with the status
// codes in statusFor. See docs/api.md.
package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"mime"
	"net/http"
	"path"
	"strings"

	"github.com/dantecatalfamo/OPF/internal/appliance"
	"github.com/dantecatalfamo/OPF/internal/pf"
)

// maxBody bounds request bodies. A large model is a few hundred KB.
const maxBody = 4 << 20

type Server struct {
	api appliance.API
	ui  fs.FS // the built web interface, or nil
	mux *http.ServeMux
}

// New returns a Server for the API and, unless ui is nil, the built web
// interface (package ui) at every other path.
func New(api appliance.API, ui fs.FS) *Server {
	s := &Server{api: api, ui: ui, mux: http.NewServeMux()}
	s.mux.HandleFunc("GET /api/status", s.status)
	s.mux.HandleFunc("GET /api/config", s.getLive)
	s.mux.HandleFunc("GET /api/config/staged", s.getStaged)
	s.mux.HandleFunc("PUT /api/config/staged", s.putStaged)
	s.mux.HandleFunc("DELETE /api/config/staged", s.deleteStaged)
	s.mux.HandleFunc("GET /api/commits", s.listCommits)
	s.mux.HandleFunc("POST /api/commits", s.createCommit)
	s.mux.HandleFunc("GET /api/commits/{id}", s.getCommit)
	s.mux.HandleFunc("POST /api/commits/{id}/confirm", s.confirm)
	s.mux.HandleFunc("POST /api/commits/{id}/revert", s.revert)
	s.mux.HandleFunc("GET /api/commits/{id}/config/{which}", s.getCommitConfig)
	s.mux.HandleFunc("GET /api/dhcp/leases", s.dhcpLeases)
	s.mux.HandleFunc("GET /api/dns/leases", s.leaseNames)
	s.mux.HandleFunc("GET /api/network/arp", s.arpTable)
	s.mux.HandleFunc("GET /api/network/routes", s.routingTable)
	s.mux.HandleFunc("GET /api/network/interfaces", getter(s.api.Interfaces))
	s.mux.HandleFunc("GET /api/network/gateways", getter(s.api.Gateways))
	s.mux.HandleFunc("GET /api/system", getter(s.api.System))
	s.mux.HandleFunc("GET /api/system/updates", getter(s.api.Updates))
	s.mux.HandleFunc("POST /api/pf/parse", s.parseRule)
	s.mux.HandleFunc("POST /api/pf/render", s.render)
	s.mux.HandleFunc("POST /api/pf/ruleset", s.ruleset)
	s.mux.HandleFunc("POST /api/pf/derived", s.derived)
	s.mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, &appliance.Error{Code: appliance.CodeNotFound, Message: "no such resource"})
	})
	s.mux.HandleFunc("/", s.serveUI)
	return s
}

func init() {
	// Go's built-in table lacks the fonts, and the web process can't
	// read /etc/mime.types once it's sandboxed.
	mime.AddExtensionType(".woff2", "font/woff2")
	mime.AddExtensionType(".woff", "font/woff")
}

// uiPolicy allows the page only its own scripts, styles, fonts and API.
// Styles may be inline because the component library injects its CSS
// variables at runtime; scripts may not. The page can't be framed, so it
// can't be dressed up by another site to trick a click.
const uiPolicy = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data:; font-src 'self'; connect-src 'self'; manifest-src 'self'; " +
	"base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

// serveUI serves the built web interface. Paths that aren't files are
// the interface's own pages, so they get index.html; missing assets are
// 404s.
func (s *Server) serveUI(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Content-Security-Policy", uiPolicy)
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		h.Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.ui == nil {
		http.Error(w, "This OPF was built without its web interface. Build it with `make build`; the API is at /api/.", http.StatusNotFound)
		return
	}
	name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
	if info, err := fs.Stat(s.ui, name); name == "" || err != nil || info.IsDir() {
		if strings.HasPrefix(name, "assets/") {
			http.NotFound(w, r)
			return
		}
		name = "index.html"
	}
	if strings.HasPrefix(name, "assets/") {
		// Asset names carry a hash of their contents.
		h.Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		h.Set("Cache-Control", "no-cache")
	}
	http.ServeFileFS(w, r, s.ui, name)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	// Configuration is sensitive and changes underneath any cache.
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	s.mux.ServeHTTP(w, r)
}

// ---------- plumbing ----------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("web: writing response: %v", err)
	}
}

type errorBody struct {
	Error *appliance.Error `json:"error"`
}

func writeError(w http.ResponseWriter, status int, e *appliance.Error) {
	writeJSON(w, status, errorBody{e})
}

// statusFor maps API error codes to HTTP statuses.
func statusFor(c appliance.Code) int {
	switch c {
	case appliance.CodeInvalid, appliance.CodeCheckFailed, appliance.CodeUnsupported:
		return http.StatusUnprocessableEntity
	case appliance.CodeNotFound, appliance.CodeNothingStaged:
		return http.StatusNotFound
	case appliance.CodeConflict, appliance.CodePending, appliance.CodeNotPending, appliance.CodeModifiedOutside:
		return http.StatusConflict
	}
	return http.StatusInternalServerError
}

// fail reports an API error. Internal errors are logged and answered
// without their details.
func fail(w http.ResponseWriter, err error) {
	e := appliance.AsError(err)
	if e.Code == appliance.CodeInternal {
		log.Printf("web: %s", e.Message)
		e = &appliance.Error{Code: appliance.CodeInternal, Message: "internal error"}
	}
	writeError(w, statusFor(e.Code), e)
}

func badRequest(w http.ResponseWriter, status int, format string, args ...any) {
	writeError(w, status, &appliance.Error{Code: appliance.CodeInvalid, Message: fmt.Sprintf(format, args...)})
}

// decode reads a JSON request body into v: application/json only, at
// most maxBody bytes, no unknown fields, nothing after the value.
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		badRequest(w, http.StatusUnsupportedMediaType, "send the request body as application/json")
		return false
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			badRequest(w, http.StatusRequestEntityTooLarge, "the request body is larger than %d bytes", maxBody)
		} else {
			badRequest(w, http.StatusBadRequest, "invalid JSON: %v", err)
		}
		return false
	}
	if _, err := dec.Token(); err != io.EOF {
		badRequest(w, http.StatusBadRequest, "invalid JSON: unexpected data after the value")
		return false
	}
	return true
}

func setETag(w http.ResponseWriter, version string) {
	w.Header().Set("ETag", `"`+version+`"`)
}

// ---------- configuration ----------

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	st, err := s.api.Status()
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) getLive(w http.ResponseWriter, r *http.Request) {
	c, err := s.api.Live()
	if err != nil {
		fail(w, err)
		return
	}
	setETag(w, c.Version)
	writeJSON(w, http.StatusOK, c)
}

func (s *Server) getStaged(w http.ResponseWriter, r *http.Request) {
	st, err := s.api.Staged()
	if err != nil {
		fail(w, err)
		return
	}
	setETag(w, st.Version)
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) putStaged(w http.ResponseWriter, r *http.Request) {
	var req appliance.StageRequest
	if !decode(w, r, &req) {
		return
	}
	st, err := s.api.Stage(req)
	if err != nil {
		fail(w, err)
		return
	}
	setETag(w, st.Version)
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) deleteStaged(w http.ResponseWriter, r *http.Request) {
	if err := s.api.Discard(); err != nil {
		fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------- commits ----------

func (s *Server) listCommits(w http.ResponseWriter, r *http.Request) {
	list, err := s.api.Commits()
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// createCommit answers 201 whenever a commit was made, including one
// that couldn't be applied and was reverted (status "failed"): it's in
// history with its log. Requests that make no commit are errors.
func (s *Server) createCommit(w http.ResponseWriter, r *http.Request) {
	var req appliance.CommitRequest
	if !decode(w, r, &req) {
		return
	}
	c, err := s.api.Commit(req)
	if err != nil {
		if e := appliance.AsError(err); e.Code == appliance.CodeNothingStaged {
			writeError(w, http.StatusConflict, e) // the resource exists; its state is wrong
			return
		}
		fail(w, err)
		return
	}
	w.Header().Set("Location", "/api/commits/"+c.ID)
	writeJSON(w, http.StatusCreated, c)
}

func (s *Server) getCommit(w http.ResponseWriter, r *http.Request) {
	d, err := s.api.GetCommit(r.PathValue("id"))
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

func (s *Server) confirm(w http.ResponseWriter, r *http.Request) {
	c, err := s.api.Confirm(r.PathValue("id"))
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, c)
}

func (s *Server) revert(w http.ResponseWriter, r *http.Request) {
	c, err := s.api.Revert(r.PathValue("id"))
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, c)
}

// getCommitConfig returns the model before or after a commit. Restoring
// it is staging it with PUT /api/config/staged.
func (s *Server) getCommitConfig(w http.ResponseWriter, r *http.Request) {
	which := appliance.Which(r.PathValue("which"))
	if which != appliance.Before && which != appliance.After {
		writeError(w, http.StatusNotFound, &appliance.Error{Code: appliance.CodeNotFound, Message: "no such resource"})
		return
	}
	c, err := s.api.CommitConfig(r.PathValue("id"), which)
	if err != nil {
		fail(w, err)
		return
	}
	setETag(w, c.Version)
	writeJSON(w, http.StatusOK, c)
}

// ---------- DHCP and DNS ----------

func (s *Server) dhcpLeases(w http.ResponseWriter, r *http.Request) {
	l, err := s.api.DHCPLeases()
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, l)
}

func (s *Server) leaseNames(w http.ResponseWriter, r *http.Request) {
	n, err := s.api.LeaseNames()
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, n)
}

// getter serves what a read-only API call returns.
func getter[T any](get func() (T, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v, err := get()
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, http.StatusOK, v)
	}
}

func (s *Server) arpTable(w http.ResponseWriter, r *http.Request) {
	t, err := s.api.ARPTable()
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, t)
}

func (s *Server) routingTable(w http.ResponseWriter, r *http.Request) {
	t, err := s.api.RoutingTable()
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, t)
}

// ---------- pf helpers ----------
//
// Pure functions of their input: nothing is stored or applied. The
// model, if given, resolves interface, alias and gateway names.

type parseRequest struct {
	Text  string    `json:"text"`
	Model *pf.Model `json:"model,omitempty"`
}

type ruleBody struct {
	Rule *pf.Rule `json:"rule"`
}

func (s *Server) parseRule(w http.ResponseWriter, r *http.Request) {
	var req parseRequest
	if !decode(w, r, &req) {
		return
	}
	if len(req.Text) > 4096 {
		badRequest(w, http.StatusUnprocessableEntity, "a rule is at most 4096 bytes")
		return
	}
	rule, err := pf.ParseRule(req.Text, req.Model)
	if err != nil {
		badRequest(w, http.StatusUnprocessableEntity, "%v", err)
		return
	}
	if rule == nil {
		badRequest(w, http.StatusUnprocessableEntity, "not a pf rule")
		return
	}
	writeJSON(w, http.StatusOK, ruleBody{rule})
}

// The pf helpers work on the model being edited, which may not be valid
// yet; pf.Safe turns a generator's panic on a half-finished model into
// a 422 instead of a crash. They compute text only, so they run here in
// the web process.

type modelRequest struct {
	Model *pf.Model `json:"model"`
}

func (req modelRequest) model() *pf.Model {
	if req.Model == nil {
		return &pf.Model{}
	}
	return req.Model
}

type renderRequest struct {
	Model   *pf.Model       `json:"model,omitempty"`
	Rule    *pf.Rule        `json:"rule,omitempty"`
	NAT     *pf.NATRule     `json:"nat,omitempty"`
	Forward *pf.PortForward `json:"forward,omitempty"`
}

// render returns the pf text for one rule, NAT rule or port forward.
func (s *Server) render(w http.ResponseWriter, r *http.Request) {
	var req renderRequest
	if !decode(w, r, &req) {
		return
	}
	m := modelRequest{req.Model}.model()
	type result struct {
		out pf.Rendered
		err error
	}
	res, err := pf.Safe(func() result {
		out, err := pf.Render(m, req.Rule, req.NAT, req.Forward)
		return result{out, err}
	})
	if err == nil {
		err = res.err
	}
	if err != nil {
		badRequest(w, http.StatusUnprocessableEntity, "%v", err)
		return
	}
	writeJSON(w, http.StatusOK, res.out)
}

type rulesetBody struct {
	Lines []pf.PfLine `json:"lines"`
}

// ruleset returns a model's pf.conf, each line with where it came from.
func (s *Server) ruleset(w http.ResponseWriter, r *http.Request) {
	var req modelRequest
	if !decode(w, r, &req) {
		return
	}
	lines, err := pf.Safe(func() []pf.PfLine { return pf.GeneratePfRuleset(req.model()) })
	if err != nil {
		badRequest(w, http.StatusUnprocessableEntity, "%v", err)
		return
	}
	writeJSON(w, http.StatusOK, rulesetBody{lines})
}

// derived returns what the UI shows about a model that the generators
// work out: automatic NAT, local networks, each rule's text.
func (s *Server) derived(w http.ResponseWriter, r *http.Request) {
	var req modelRequest
	if !decode(w, r, &req) {
		return
	}
	d, err := pf.Safe(func() pf.Derived { return pf.Derive(req.model()) })
	if err != nil {
		badRequest(w, http.StatusUnprocessableEntity, "%v", err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}
