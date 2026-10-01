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
//	GET    /api/pf/status                 pf on or off, its state table, blocked traffic
//	GET    /api/pf/states                 the state table, a page: ?q=&proto=&offset=&limit=
//	POST   /api/pf/states/kill            end a connection
//	GET    /api/pf/rules/counters         each labelled rule's counters
//	GET    /api/logs/firewall             packets pf logged, newest first
//	GET    /api/firewall/tables           URL aliases' downloaded lists
//	POST   /api/firewall/aliases/{name}/refresh  download one again and load it
//	GET    /api/dns/blocklists            DNS blocklists' downloads
//	POST   /api/dns/blocklists/{id}/refresh  download one again and reload it
//	POST   /api/diagnostics/runs          start a tool (ping, traceroute, dns, port)
//	GET    /api/diagnostics/runs/{id}     a run and its output, from ?from=N on
//	POST   /api/diagnostics/runs/{id}/cancel  stop it
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
	"strconv"
	"strings"
	"time"

	"github.com/dantecatalfamo/OPF/internal/appliance"
	"github.com/dantecatalfamo/OPF/internal/diag"
	"github.com/dantecatalfamo/OPF/internal/pf"
)

// maxBody bounds request bodies. A large model is a few hundred KB.
const maxBody = 4 << 20

type Server struct {
	api  appliance.API // without Auth; with it, each request's caller (apiFor)
	ui   fs.FS         // the built web interface, or nil
	mux  *http.ServeMux
	uiGz uiGzip // the UI's files, compressed

	auth           Auth // session.go
	tlsFingerprint string
}

// New returns a Server for the API and, unless ui is nil, the built web
// interface (package ui) at every other path.
func New(api appliance.API, ui fs.FS) *Server {
	s := &Server{api: api, ui: ui, mux: http.NewServeMux()}
	s.mux.HandleFunc("POST /api/wireguard/keys", s.newTunnelKey)
	s.mux.HandleFunc("POST /api/wireguard/device-keys", s.newDeviceKey)
	s.mux.HandleFunc("GET /api/session", s.getSession)
	s.mux.HandleFunc("POST /api/session", s.login)
	s.mux.HandleFunc("DELETE /api/session", s.logout)
	s.mux.HandleFunc("GET /api/sessions", s.listSessions)
	s.mux.HandleFunc("DELETE /api/sessions/{id}", s.endSession)
	s.mux.HandleFunc("POST /api/session/reauth", s.reauth)
	s.mux.HandleFunc("PUT /api/session/password", s.ownPassword)
	s.mux.HandleFunc("GET /api/users", s.listUsers)
	s.mux.HandleFunc("POST /api/users", s.createUser)
	s.mux.HandleFunc("PUT /api/users/{name}/role", s.setUserRole)
	s.mux.HandleFunc("PUT /api/users/{name}/password", s.setUserPassword)
	s.mux.HandleFunc("PUT /api/users/{name}/lock", s.lockUser)
	s.mux.HandleFunc("DELETE /api/users/{name}", s.removeUser)
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
	s.mux.HandleFunc("GET /api/network/interfaces", getter(s, appliance.API.Interfaces))
	s.mux.HandleFunc("GET /api/network/gateways", getter(s, appliance.API.Gateways))
	s.mux.HandleFunc("GET /api/system", getter(s, appliance.API.System))
	s.mux.HandleFunc("GET /api/system/updates", getter(s, appliance.API.Updates))
	s.mux.HandleFunc("POST /api/system/updates/check", getter(s, appliance.API.CheckUpdates))
	s.mux.HandleFunc("GET /api/pf/status", getter(s, appliance.API.PfStatus))
	s.mux.HandleFunc("GET /api/pf/states", s.pfStates)
	s.mux.HandleFunc("POST /api/pf/states/kill", s.killState)
	s.mux.HandleFunc("GET /api/pf/rules/counters", getter(s, appliance.API.RuleCounters))
	s.mux.HandleFunc("GET /api/logs/firewall", getter(s, appliance.API.FirewallLog))
	s.mux.HandleFunc("GET /api/firewall/tables", getter(s, func(api appliance.API) (tablesBody, error) {
		t, err := api.Tables()
		return tablesBody{t}, err
	}))
	s.mux.HandleFunc("POST /api/firewall/aliases/{name}/refresh", s.refreshAlias)
	s.mux.HandleFunc("GET /api/dns/blocklists", getter(s, func(api appliance.API) (dnsListsBody, error) {
		l, err := api.DNSLists()
		return dnsListsBody{l}, err
	}))
	s.mux.HandleFunc("POST /api/dns/blocklists/{id}/refresh", s.refreshDNSList)
	s.mux.HandleFunc("GET /api/dns/stats", getter(s, appliance.API.DNSStats))
	s.mux.HandleFunc("GET /api/metrics", s.metrics)
	s.mux.HandleFunc("GET /api/events", s.events)
	s.mux.HandleFunc("GET /api/logs/system/{log}", s.systemLog)
	s.mux.HandleFunc("POST /api/dns/tools", s.dnsTool)
	s.mux.HandleFunc("GET /api/webhooks", getter(s, func(api appliance.API) (webhooksBody, error) {
		w, err := api.Webhooks()
		return webhooksBody{w}, err
	}))
	s.mux.HandleFunc("PUT /api/webhooks/{id}/secret", s.setWebhookSecret)
	s.mux.HandleFunc("POST /api/webhooks/{id}/test", s.testWebhook)
	s.mux.HandleFunc("GET /api/dns/blocked", getter(s, appliance.API.DNSBlocked))
	s.mux.HandleFunc("POST /api/diagnostics/runs", s.startTool)
	s.mux.HandleFunc("GET /api/diagnostics/runs/{id}", s.toolRun)
	s.mux.HandleFunc("POST /api/diagnostics/runs/{id}/cancel", s.cancelTool)
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
// variables at runtime; scripts may not. 'wasm-unsafe-eval' lets the
// page compile its own WebAssembly (OPF's generators, for previews of a
// large model) and nothing else: JavaScript eval stays blocked, and the
// module still has to come from 'self'. The page can't be framed, so it
// can't be dressed up by another site to trick a click.
const uiPolicy = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; " +
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
	h.Add("Vary", "Accept-Encoding")
	// Compressed from memory when the client takes it; a range of a
	// file (rare for these) is served from the file as it is.
	if ct := mime.TypeByExtension(path.Ext(name)); accepts(r) && r.Header.Get("Range") == "" && compressible(ct) {
		if gz, ok := s.uiGz.get(s.ui, name); ok {
			h.Set("Content-Type", ct)
			h.Set("Content-Encoding", "gzip")
			h.Set("Content-Length", strconv.Itoa(len(gz)))
			w.WriteHeader(http.StatusOK)
			if r.Method != http.MethodHead {
				w.Write(gz)
			}
			return
		}
	}
	http.ServeFileFS(w, r, s.ui, name)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	// Configuration is sensitive and changes underneath any cache.
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	if strings.HasPrefix(r.URL.Path, "/api/") {
		r, ok := s.authorize(w, r)
		if !ok {
			return
		}
		withGzip(w, r, s.mux.ServeHTTP)
		return
	}
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
	case appliance.CodeBusy, appliance.CodeRateLimited:
		return http.StatusTooManyRequests
	case appliance.CodeUnauthorized:
		return http.StatusUnauthorized
	case appliance.CodeForbidden, appliance.CodeReauth:
		return http.StatusForbidden
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
	st, err := s.apiFor(r).Status()
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) getLive(w http.ResponseWriter, r *http.Request) {
	c, err := s.apiFor(r).Live()
	if err != nil {
		fail(w, err)
		return
	}
	setETag(w, c.Version)
	writeJSON(w, http.StatusOK, c)
}

func (s *Server) getStaged(w http.ResponseWriter, r *http.Request) {
	st, err := s.apiFor(r).Staged()
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
	st, err := s.apiFor(r).Stage(req)
	if err != nil {
		fail(w, err)
		return
	}
	setETag(w, st.Version)
	// Not the model: the client just sent it, and for a large firewall
	// it's most of the response. GET /api/config/staged has it.
	writeJSON(w, http.StatusOK, stageResult{st.Version, st.Base, st.Changes})
}

// stageResult is what staging answers: the staged version, the live
// version it replaces, and the file changes it would make.
type stageResult struct {
	Version string                 `json:"version"`
	Base    string                 `json:"base"`
	Changes []appliance.FileChange `json:"changes"`
}

func (s *Server) deleteStaged(w http.ResponseWriter, r *http.Request) {
	if err := s.apiFor(r).Discard(); err != nil {
		fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------- commits ----------

func (s *Server) listCommits(w http.ResponseWriter, r *http.Request) {
	list, err := s.apiFor(r).Commits()
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
	c, err := s.apiFor(r).Commit(req)
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
	d, err := s.apiFor(r).GetCommit(r.PathValue("id"))
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

func (s *Server) confirm(w http.ResponseWriter, r *http.Request) {
	c, err := s.apiFor(r).Confirm(r.PathValue("id"))
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, c)
}

func (s *Server) revert(w http.ResponseWriter, r *http.Request) {
	c, err := s.apiFor(r).Revert(r.PathValue("id"))
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
	c, err := s.apiFor(r).CommitConfig(r.PathValue("id"), which)
	if err != nil {
		fail(w, err)
		return
	}
	setETag(w, c.Version)
	writeJSON(w, http.StatusOK, c)
}

// ---------- DHCP and DNS ----------

func (s *Server) dhcpLeases(w http.ResponseWriter, r *http.Request) {
	l, err := s.apiFor(r).DHCPLeases()
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, l)
}

func (s *Server) leaseNames(w http.ResponseWriter, r *http.Request) {
	n, err := s.apiFor(r).LeaseNames()
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, n)
}

func (s *Server) killState(w http.ResponseWriter, r *http.Request) {
	var req appliance.KillStateRequest
	if !decode(w, r, &req) {
		return
	}
	if err := s.apiFor(r).KillState(req); err != nil {
		fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type dnsListsBody struct {
	Lists []appliance.DNSListStatus `json:"lists"`
}

func (s *Server) refreshDNSList(w http.ResponseWriter, r *http.Request) {
	l, err := s.apiFor(r).RefreshDNSList(r.PathValue("id"))
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, l)
}

type tablesBody struct {
	Tables []appliance.TableStatus `json:"tables"`
}

func (s *Server) refreshAlias(w http.ResponseWriter, r *http.Request) {
	t, err := s.apiFor(r).RefreshAlias(r.PathValue("name"))
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, t)
}

type webhooksBody struct {
	Webhooks []appliance.WebhookStatus `json:"webhooks"`
}

// setWebhookSecret sets a webhook's URL and key. Its answer can carry a
// generated key, a secret, so it's never compressed (gzip.go).
func (s *Server) setWebhookSecret(w http.ResponseWriter, r *http.Request) {
	var req appliance.WebhookSecretRequest
	if !decode(w, r, &req) {
		return
	}
	res, err := s.apiFor(r).SetWebhookSecret(r.PathValue("id"), req)
	if err != nil {
		fail(w, err)
		return
	}
	noCompression(w)
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) testWebhook(w http.ResponseWriter, r *http.Request) {
	st, err := s.apiFor(r).TestWebhook(r.PathValue("id"))
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) dnsTool(w http.ResponseWriter, r *http.Request) {
	var req appliance.DNSToolRequest
	if !decode(w, r, &req) {
		return
	}
	res, err := s.apiFor(r).DNSTool(req)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// systemLog answers ?q=<search>&program=<name>&limit=.
func (s *Server) systemLog(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	req := appliance.SystemLogRequest{Log: r.PathValue("log"), Query: q.Get("q"), Program: q.Get("program")}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			badRequest(w, http.StatusBadRequest, "limit is a number")
			return
		}
		req.Limit = n
	}
	l, err := s.apiFor(r).SystemLog(req)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, l)
}

// events answers ?kind=link,gateway&q=<search>&before=<RFC 3339 time>&limit=.
func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	req := appliance.EventsRequest{Query: q.Get("q")}
	if v := q.Get("kind"); v != "" {
		req.Kinds = strings.Split(v, ",")
	}
	if v := q.Get("before"); v != "" {
		t, err := time.Parse(time.RFC3339Nano, v)
		if err != nil {
			badRequest(w, http.StatusBadRequest, "before is a time like 2026-09-30T12:00:00Z")
			return
		}
		req.Before = t
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			badRequest(w, http.StatusBadRequest, "limit is a number")
			return
		}
		req.Limit = n
	}
	ev, err := s.apiFor(r).Events(req)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ev)
}

// pfStates answers ?q=<part of an address>&proto=tcp|udp|icmp&offset=&limit=.
func (s *Server) pfStates(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	req := appliance.PfStatesRequest{Query: q.Get("q"), Proto: q.Get("proto")}
	for name, dst := range map[string]*int{"offset": &req.Offset, "limit": &req.Limit} {
		if v := q.Get(name); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil {
				badRequest(w, http.StatusBadRequest, "%s is a number", name)
				return
			}
			*dst = n
		}
	}
	st, err := s.apiFor(r).PfStates(req)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

// metrics answers ?series=a,b&range=<seconds>[&step=<seconds>].
func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	req := appliance.MetricsRequest{}
	if v := q.Get("series"); v != "" {
		req.Series = strings.Split(v, ",")
	}
	var err error
	if req.Range, err = strconv.Atoi(q.Get("range")); err != nil {
		badRequest(w, http.StatusBadRequest, "range is a number of seconds")
		return
	}
	if v := q.Get("step"); v != "" {
		if req.Step, err = strconv.Atoi(v); err != nil {
			badRequest(w, http.StatusBadRequest, "step is a number of seconds")
			return
		}
	}
	m, err := s.apiFor(r).Metrics(req)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, m)
}

func (s *Server) startTool(w http.ResponseWriter, r *http.Request) {
	var req diag.Request
	if !decode(w, r, &req) {
		return
	}
	run, err := s.apiFor(r).StartTool(req)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, run)
}

func (s *Server) toolRun(w http.ResponseWriter, r *http.Request) {
	from := 0
	if f := r.URL.Query().Get("from"); f != "" {
		n, err := strconv.Atoi(f)
		if err != nil || n < 0 {
			badRequest(w, http.StatusBadRequest, "from is a line number")
			return
		}
		from = n
	}
	run, err := s.apiFor(r).ToolRun(r.PathValue("id"), from)
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, run)
}

func (s *Server) cancelTool(w http.ResponseWriter, r *http.Request) {
	if err := s.apiFor(r).CancelTool(r.PathValue("id")); err != nil {
		fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// getter serves what a read-only API call returns.
func getter[T any](s *Server, get func(appliance.API) (T, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v, err := get(s.apiFor(r))
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, http.StatusOK, v)
	}
}

func (s *Server) arpTable(w http.ResponseWriter, r *http.Request) {
	t, err := s.apiFor(r).ARPTable()
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, t)
}

func (s *Server) routingTable(w http.ResponseWriter, r *http.Request) {
	t, err := s.apiFor(r).RoutingTable()
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

// newTunnelKey makes a tunnel's key pair on the firewall: {"publicKey"}.
func (s *Server) newTunnelKey(w http.ResponseWriter, r *http.Request) {
	pub, err := s.apiFor(r).NewTunnelKey()
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, struct {
		PublicKey string `json:"publicKey"`
	}{pub})
}

// newDeviceKey makes a device's key pair, for a browser that can't:
// {"privateKey", "publicKey"}, kept nowhere. Not compressed: it carries
// a secret.
func (s *Server) newDeviceKey(w http.ResponseWriter, r *http.Request) {
	k, err := s.apiFor(r).NewDeviceKey()
	if err != nil {
		fail(w, err)
		return
	}
	noCompression(w)
	writeJSON(w, http.StatusCreated, k)
}
