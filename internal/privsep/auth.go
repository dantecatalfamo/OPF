package privsep

import (
	"context"
	"errors"
	"time"

	"github.com/dantecatalfamo/OPF/internal/appliance"
	"github.com/dantecatalfamo/OPF/internal/auth"
)

// Every call but Login and Wait carries the token of whoever made the
// request, and the parent checks it, and that their role allows the
// method, before doing anything. The web process only passes tokens
// on: compromised, it can't make one or raise a role, only reuse the
// tokens of people signing in meanwhile.

// Call is a method's arguments with the caller's token.
type Call[T any] struct {
	Token string
	// Active says someone used the page: only then does the call count
	// as the session being used (auth.Sessions.Peek).
	Active bool
	Args   T
}

// methodRoles is the least role each method needs. A method missing
// here can't be called (TestEveryMethodHasARole).
var methodRoles = map[string]auth.Role{
	// Looking.
	"Status": auth.RoleView, "LeaseNames": auth.RoleView, "DHCPLeases": auth.RoleView,
	"ARPTable": auth.RoleView, "RoutingTable": auth.RoleView, "System": auth.RoleView,
	"Interfaces": auth.RoleView, "Gateways": auth.RoleView, "Updates": auth.RoleView,
	"PfStatus": auth.RoleView, "PfStates": auth.RoleView, "RuleCounters": auth.RoleView,
	"FirewallLog": auth.RoleView, "Tables": auth.RoleView, "DNSLists": auth.RoleView,
	"Webhooks": auth.RoleView, "SystemLog": auth.RoleView, "Events": auth.RoleView,
	"Metrics": auth.RoleView, "DNSStats": auth.RoleView, "DNSBlocked": auth.RoleView,
	"Live": auth.RoleView, "Staged": auth.RoleView, "Commits": auth.RoleView,
	"GetCommit": auth.RoleView, "CommitConfig": auth.RoleView,
	"DNSTool": auth.RoleView, // forgetting cached answers needs operator (DNSTool)
	"Session": auth.RoleView, "Sessions": auth.RoleView, "EndSession": auth.RoleView, "Logout": auth.RoleView,
	// Running things, and keeping or undoing a commit.
	"CheckUpdates": auth.RoleOperator, "KillState": auth.RoleOperator,
	"StartTool": auth.RoleOperator, "ToolRun": auth.RoleOperator, "CancelTool": auth.RoleOperator,
	"RefreshAlias": auth.RoleOperator, "RefreshDNSList": auth.RoleOperator, "TestWebhook": auth.RoleOperator,
	"Confirm": auth.RoleOperator, "Revert": auth.RoleOperator,
	// Changing the configuration.
	"Stage": auth.RoleAdmin, "Discard": auth.RoleAdmin, "Commit": auth.RoleAdmin,
	"SetWebhookSecret": auth.RoleAdmin,
}

// allow checks the token and the method's role, returning the session,
// or nil with r saying why not.
func (s *Service) allow(method string, c callInfo, r *Result) *auth.Session {
	need, ok := methodRoles[method]
	if !ok {
		r.Err = &appliance.Error{Code: appliance.CodeForbidden, Message: "not allowed"}
		return nil
	}
	if s.sessions == nil {
		r.Err = &appliance.Error{Code: appliance.CodeUnauthorized, Message: "this server has no accounts"}
		return nil
	}
	check := s.sessions.Peek
	if c.active() {
		check = s.sessions.Check
	}
	sess, err := check(c.token())
	if err != nil {
		r.Err = &appliance.Error{Code: appliance.CodeUnauthorized, Message: "sign in first"}
		return nil
	}
	if sess.Role < need {
		r.Err = &appliance.Error{Code: appliance.CodeForbidden, Message: "your role (" + sess.Role.String() + ") can't do this; it needs " + need.String()}
		return nil
	}
	return sess
}

func sessionOf(s *auth.Session) *appliance.Session {
	return &appliance.Session{ID: s.ID, User: s.User, Role: s.Role.String(), Source: s.Source, Created: s.Created, LastUsed: s.LastUsed}
}

type (
	LoginArgs struct {
		User, Password string
		// Source is the address the attempt came from, as the web
		// process saw it: only used to slow down guessing from one place.
		Source string
	}
	LoginReply struct {
		Result
		Token   string
		Session *appliance.Session
	}
	SessionReply struct {
		Result
		Session *appliance.Session
	}
	SessionsReply struct {
		Result
		Sessions []appliance.Session
	}
)

// Login checks a name and password and starts a session.
func (s *Service) Login(a LoginArgs, r *LoginReply) error {
	if s.sessions == nil {
		r.Err = &appliance.Error{Code: appliance.CodeUnsupported, Message: "this server has no accounts"}
		return nil
	}
	if len(a.User) > auth.MaxUser || len(a.Password) > auth.MaxPassword || len(a.Source) > 64 {
		r.Err = &appliance.Error{Code: appliance.CodeUnauthorized, Message: auth.ErrBadLogin.Error()}
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tok, sess, err := s.sessions.Login(ctx, a.User, a.Password, a.Source)
	var wait *auth.WaitError
	switch {
	case errors.As(err, &wait):
		r.Err = &appliance.Error{Code: appliance.CodeRateLimited, Message: wait.Error()}
	case errors.Is(err, auth.ErrBadLogin):
		r.Err = &appliance.Error{Code: appliance.CodeUnauthorized, Message: err.Error()}
	case err != nil:
		r.set("Login", err)
	default:
		r.Token, r.Session = tok, sessionOf(sess)
	}
	return nil
}

func (s *Service) Logout(c Call[None], r *EmptyReply) error {
	if s.allow("Logout", c, &r.Result) == nil {
		return nil
	}
	s.sessions.Logout(c.Token)
	return nil
}

// Session is the caller's own session.
func (s *Service) Session(c Call[None], r *SessionReply) error {
	sess := s.allow("Session", c, &r.Result)
	if sess == nil {
		return nil
	}
	r.Session = sessionOf(sess)
	return nil
}

// Sessions lists the caller's sessions, or for an admin everyone's.
func (s *Service) Sessions(c Call[None], r *SessionsReply) error {
	sess := s.allow("Sessions", c, &r.Result)
	if sess == nil {
		return nil
	}
	for _, x := range s.sessions.List(sess.User, sess.Role >= auth.RoleAdmin) {
		r.Sessions = append(r.Sessions, *sessionOf(&x))
	}
	return nil
}

// EndSession ends one of the caller's sessions, or for an admin
// anyone's.
func (s *Service) EndSession(c Call[IDArgs], r *EmptyReply) error {
	sess := s.allow("EndSession", c, &r.Result)
	if sess == nil {
		return nil
	}
	if !s.sessions.End(c.Args.ID, sess.User, sess.Role >= auth.RoleAdmin) {
		r.Err = &appliance.Error{Code: appliance.CodeNotFound, Message: "no such session"}
	}
	return nil
}

// callInfo is a Call's token and activity, whatever its arguments.
type callInfo interface {
	token() string
	active() bool
}

func (c Call[T]) token() string { return c.Token }
func (c Call[T]) active() bool  { return c.Active }

// WithToken is the client calling as whoever the token's session is;
// active as in Call.
func (c *Client) WithToken(token string, active bool) *Client {
	return &Client{rpc: c.rpc, token: token, active: active}
}

func (c *Client) Login(user, password, source string) (string, *appliance.Session, error) {
	var r LoginReply
	if err := c.rpc.Call("OPF.Login", LoginArgs{User: user, Password: password, Source: source}, &r); err != nil {
		return "", nil, &appliance.Error{Code: appliance.CodeInternal, Message: "privileged process: " + err.Error()}
	}
	if err := r.remoteErr(); err != nil {
		return "", nil, err
	}
	return r.Token, r.Session, nil
}

func (c *Client) Logout() error {
	var r EmptyReply
	return c.call("Logout", None{}, &r)
}

func (c *Client) Session() (*appliance.Session, error) {
	var r SessionReply
	err := c.call("Session", None{}, &r)
	return r.Session, err
}

func (c *Client) Sessions() ([]appliance.Session, error) {
	var r SessionsReply
	err := c.call("Sessions", None{}, &r)
	return nonNil(r.Sessions), err
}

func (c *Client) EndSession(id string) error {
	var r EmptyReply
	return c.call("EndSession", IDArgs{ID: id}, &r)
}

// TLSPair is a certificate and its key, PEM.
type TLSPair struct{ Cert, Key []byte }

type TLSReply struct {
	Result
	TLS *TLSPair
}

// TLS gives the web process the certificate it serves, once per
// connection: it asks as it starts, before it answers anyone.
func (s *Service) TLS(_ None, r *TLSReply) error {
	if s.tlsGiven.Swap(true) {
		r.Err = &appliance.Error{Code: appliance.CodeForbidden, Message: "already given"}
		return nil
	}
	r.TLS = s.tls
	return nil
}

// TLS is the certificate to serve, or nil for plain HTTP.
func (c *Client) TLS() (*TLSPair, error) {
	var r TLSReply
	if err := c.rpc.Call("OPF.TLS", None{}, &r); err != nil {
		return nil, err
	}
	return r.TLS, r.remoteErr()
}
