package web

import (
	"context"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/dantecatalfamo/OPF/internal/appliance"
	"github.com/dantecatalfamo/OPF/internal/auth"
)

// Signing in. The privileged process checks passwords and keeps the
// sessions; this process only carries a session's token between the
// browser's cookie and every call it makes, and the privileged process
// checks it and the role each time. Without Auth (the mock server)
// there are no accounts, and the UI says so.
//
//	GET    /api/session         who's signed in: {"accounts", "session", "tls"}
//	POST   /api/session         sign in: {"user", "password"}
//	DELETE /api/session         sign out
//	GET    /api/sessions        your sessions; an admin's, everyone's
//	DELETE /api/sessions/{id}   end one
//	POST   /api/session/reauth    give your password again: {"password"}
//	PUT    /api/session/password  change yours: {"current", "new"}
//	GET    /api/users             who can sign in, and who could (admins)
//	POST   /api/users             make an account: {"name", "fullName", "role", "password", "shell"}
//	PUT    /api/users/{name}/role      {"role"}: admin, operator, view, or "" for none
//	PUT    /api/users/{name}/password  {"password"}
//	PUT    /api/users/{name}/lock      {"locked"}
//	DELETE /api/users/{name}      remove it, or if OPF didn't make it, its role

// Auth signs people in, and makes callers acting as them.
type Auth interface {
	Login(user, password, source string) (token string, s *appliance.Session, err error)
	// As calls as the token's session. Only an active call (someone
	// used the page lately, not a timer polling) counts as the session
	// being used, so an unattended page still times out.
	As(token string, active bool) Caller
}

// Caller is the API as someone signed in.
type Caller interface {
	appliance.API
	Session() (*appliance.Session, error)
	Sessions() ([]appliance.Session, error)
	EndSession(id string) error
	Logout() error
	Reauth(password, source string) error
	ChangeOwnPassword(current, new, source string) error
	// Accounts, for admins.
	Users() (members, candidates []auth.Account, err error)
	CreateUser(auth.NewAccount) error
	SetUserRole(name, role string) error
	SetUserPassword(name, password string) error
	LockUser(name string, locked bool) error
	RemoveUser(name string) (note string, err error)
}

// The session cookie: only over HTTPS (or to localhost), never to
// scripts, never on a request from another site, and for this host
// alone (__Host-).
const cookieName = "__Host-opf"

// activeHeader marks a request made because someone used the page.
const activeHeader = "X-OPF-Active"

// RequireAuth makes every API request but signing in need a session.
// tlsFingerprint, the SHA-256 of the certificate being served, is shown
// on the sign-in page to compare with the one OPF logs at start.
func (s *Server) RequireAuth(a Auth, tlsFingerprint string) {
	s.auth, s.tlsFingerprint = a, tlsFingerprint
}

type callerKey struct{}

// apiFor is the API as the request's caller.
func (s *Server) apiFor(r *http.Request) appliance.API {
	if c, ok := r.Context().Value(callerKey{}).(Caller); ok {
		return c
	}
	return s.api
}

func token(r *http.Request) string {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return ""
	}
	return c.Value
}

// authorize lets an API request through with its caller, or answers
// it: 401 without a valid session.
func (s *Server) authorize(w http.ResponseWriter, r *http.Request) (*http.Request, bool) {
	if s.auth == nil || r.URL.Path == "/api/session" {
		return r, true
	}
	tok := token(r)
	if tok == "" {
		writeError(w, http.StatusUnauthorized, &appliance.Error{Code: appliance.CodeUnauthorized, Message: "sign in first"})
		return r, false
	}
	c := s.auth.As(tok, r.Header.Get(activeHeader) == "1")
	// Checked here as well as by every call, for the requests answered
	// in this process (pf parse and render) and so a lapsed session
	// gets a 401, not whatever its first call would have said.
	if _, err := c.Session(); err != nil {
		fail(w, err)
		return r, false
	}
	return r.WithContext(context.WithValue(r.Context(), callerKey{}, c)), true
}

type sessionBody struct {
	// Accounts is false on a server without them (the mock): nobody
	// signs in, and anyone who can reach it can do anything.
	Accounts bool               `json:"accounts"`
	Session  *appliance.Session `json:"session,omitempty"`
	TLS      string             `json:"tls,omitempty"` // the certificate's SHA-256
}

func (s *Server) getSession(w http.ResponseWriter, r *http.Request) {
	if s.auth == nil {
		writeJSON(w, http.StatusOK, sessionBody{})
		return
	}
	body := sessionBody{Accounts: true, TLS: s.tlsFingerprint}
	if tok := token(r); tok != "" {
		if sess, err := s.auth.As(tok, r.Header.Get(activeHeader) == "1").Session(); err == nil {
			body.Session = sess
		}
	}
	writeJSON(w, http.StatusOK, body)
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if s.auth == nil {
		writeError(w, http.StatusNotFound, &appliance.Error{Code: appliance.CodeUnsupported, Message: "this server has no accounts"})
		return
	}
	var req struct {
		User     string `json:"user"`
		Password string `json:"password"`
	}
	if !decode(w, r, &req) {
		return
	}
	source, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		source = r.RemoteAddr
	}
	tok, sess, err := s.auth.Login(strings.TrimSpace(req.User), req.Password, source)
	if err != nil {
		fail(w, err)
		return
	}
	setCookie(w, tok, false)
	writeJSON(w, http.StatusOK, sessionBody{Accounts: true, Session: sess, TLS: s.tlsFingerprint})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if s.auth != nil {
		if tok := token(r); tok != "" {
			s.auth.As(tok, true).Logout()
		}
	}
	setCookie(w, "", true)
	w.WriteHeader(http.StatusNoContent)
}

func setCookie(w http.ResponseWriter, tok string, clear bool) {
	c := &http.Cookie{Name: cookieName, Value: tok, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode}
	if clear {
		c.MaxAge, c.Expires = -1, time.Unix(1, 0)
	}
	http.SetCookie(w, c)
}

type sessionsBody struct {
	Sessions []appliance.Session `json:"sessions"`
}

func (s *Server) listSessions(w http.ResponseWriter, r *http.Request) {
	c, ok := r.Context().Value(callerKey{}).(Caller)
	if !ok {
		writeJSON(w, http.StatusOK, sessionsBody{Sessions: []appliance.Session{}})
		return
	}
	l, err := c.Sessions()
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sessionsBody{l})
}

func (s *Server) endSession(w http.ResponseWriter, r *http.Request) {
	c, ok := r.Context().Value(callerKey{}).(Caller)
	if !ok {
		writeError(w, http.StatusNotFound, &appliance.Error{Code: appliance.CodeNotFound, Message: "no such session"})
		return
	}
	if err := c.EndSession(r.PathValue("id")); err != nil {
		fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// AuthOf makes an Auth from a sign-in function and one making callers,
// such as privsep.Client's Login and WithToken.
func AuthOf[C Caller](login func(user, password, source string) (string, *appliance.Session, error), as func(token string, active bool) C) Auth {
	return authFuncs[C]{login, as}
}

type authFuncs[C Caller] struct {
	login func(user, password, source string) (string, *appliance.Session, error)
	as    func(token string, active bool) C
}

func (a authFuncs[C]) Login(user, password, source string) (string, *appliance.Session, error) {
	return a.login(user, password, source)
}

func (a authFuncs[C]) As(token string, active bool) Caller { return a.as(token, active) }

// caller is the request's Caller, or answers that there are no
// accounts.
func (s *Server) caller(w http.ResponseWriter, r *http.Request) (Caller, bool) {
	c, ok := r.Context().Value(callerKey{}).(Caller)
	if !ok {
		writeError(w, http.StatusNotFound, &appliance.Error{Code: appliance.CodeUnsupported, Message: "this server has no accounts"})
	}
	return c, ok
}

func source(r *http.Request) string {
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return h
	}
	return r.RemoteAddr
}

func (s *Server) reauth(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	var req struct {
		Password string `json:"password"`
	}
	if !ok || !decode(w, r, &req) {
		return
	}
	if err := c.Reauth(req.Password, source(r)); err != nil {
		fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) ownPassword(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	var req struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if !ok || !decode(w, r, &req) {
		return
	}
	if err := c.ChangeOwnPassword(req.Current, req.New, source(r)); err != nil {
		fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type usersBody struct {
	Users      []auth.Account `json:"users"`
	Candidates []auth.Account `json:"candidates"`
}

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	m, cands, err := c.Users()
	if err != nil {
		fail(w, err)
		return
	}
	if m == nil {
		m = []auth.Account{}
	}
	if cands == nil {
		cands = []auth.Account{}
	}
	writeJSON(w, http.StatusOK, usersBody{m, cands})
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	var req auth.NewAccount
	if !ok || !decode(w, r, &req) {
		return
	}
	if err := c.CreateUser(req); err != nil {
		fail(w, err)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (s *Server) setUserRole(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	var req struct {
		Role string `json:"role"`
	}
	if !ok || !decode(w, r, &req) {
		return
	}
	if err := c.SetUserRole(r.PathValue("name"), req.Role); err != nil {
		fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) setUserPassword(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	var req struct {
		Password string `json:"password"`
	}
	if !ok || !decode(w, r, &req) {
		return
	}
	if err := c.SetUserPassword(r.PathValue("name"), req.Password); err != nil {
		fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) lockUser(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	var req struct {
		Locked bool `json:"locked"`
	}
	if !ok || !decode(w, r, &req) {
		return
	}
	if err := c.LockUser(r.PathValue("name"), req.Locked); err != nil {
		fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) removeUser(w http.ResponseWriter, r *http.Request) {
	c, ok := s.caller(w, r)
	if !ok {
		return
	}
	note, err := c.RemoveUser(r.PathValue("name"))
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Note string `json:"note,omitempty"`
	}{note})
}
