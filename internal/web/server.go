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
//	POST   /api/pf/parse                  pf rule text to a rule
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
	"log"
	"mime"
	"net/http"

	"github.com/dantecatalfamo/OPF/internal/appliance"
	"github.com/dantecatalfamo/OPF/internal/pf"
)

// maxBody bounds request bodies. A large model is a few hundred KB.
const maxBody = 4 << 20

type Server struct {
	api appliance.API
	mux *http.ServeMux
}

func New(api appliance.API) *Server {
	s := &Server{api: api, mux: http.NewServeMux()}
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
	s.mux.HandleFunc("POST /api/pf/parse", s.parseRule)
	s.mux.HandleFunc("POST /api/pf/render", s.renderRule)
	s.mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, &appliance.Error{Code: appliance.CodeNotFound, Message: "no such resource"})
	})
	return s
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

type renderRequest struct {
	Rule  *pf.Rule  `json:"rule"`
	Model *pf.Model `json:"model,omitempty"`
}

type renderBody struct {
	Text string `json:"text"`
}

func (s *Server) renderRule(w http.ResponseWriter, r *http.Request) {
	var req renderRequest
	if !decode(w, r, &req) {
		return
	}
	if req.Rule == nil {
		badRequest(w, http.StatusUnprocessableEntity, "rule is required")
		return
	}
	writeJSON(w, http.StatusOK, renderBody{pf.GenerateRule(req.Rule, req.Model)})
}
