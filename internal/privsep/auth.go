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
	"Interfaces": auth.RoleView, "Gateways": auth.RoleView, "Files": auth.RoleView, "File": auth.RoleView, "Updates": auth.RoleView,
	"PfStatus": auth.RoleView, "PfStates": auth.RoleView, "RuleCounters": auth.RoleView,
	"FirewallLog": auth.RoleView, "Tables": auth.RoleView, "DNSLists": auth.RoleView,
	"Webhooks": auth.RoleView, "SystemLog": auth.RoleView, "Events": auth.RoleView,
	"Metrics": auth.RoleView, "DNSStats": auth.RoleView, "DNSBlocked": auth.RoleView,
	// The names a network and each device look up: the most personal
	// data OPF keeps.
	"DNSActivity": auth.RoleAdmin, "DNSDeviceActivity": auth.RoleAdmin, "ForgetDNSActivity": auth.RoleAdmin,
	"Live": auth.RoleView, "Staged": auth.RoleView, "Commits": auth.RoleView,
	"GetCommit": auth.RoleView, "CommitConfig": auth.RoleView,
	"DNSTool": auth.RoleView, // forgetting cached answers needs operator (DNSTool)
	"Session": auth.RoleView, "Sessions": auth.RoleView, "EndSession": auth.RoleView, "Logout": auth.RoleView,
	"Reauth": auth.RoleView, "ChangeOwnPassword": auth.RoleView,
	// Running things, and keeping or undoing a commit.
	"CheckUpdates": auth.RoleOperator, "KillState": auth.RoleOperator,
	"StartTool": auth.RoleOperator, "ToolRun": auth.RoleOperator, "CancelTool": auth.RoleOperator,
	"RefreshAlias": auth.RoleOperator, "RefreshDNSList": auth.RoleOperator, "TestWebhook": auth.RoleOperator,
	"Confirm": auth.RoleOperator, "Revert": auth.RoleOperator,
	// Changing the configuration.
	"Stage": auth.RoleAdmin, "Discard": auth.RoleAdmin, "Commit": auth.RoleAdmin,
	"SetWebhookSecret": auth.RoleAdmin, "NewTunnelKey": auth.RoleAdmin, "ImportTunnelKey": auth.RoleAdmin, "NewDeviceKey": auth.RoleAdmin, "SetPresharedKey": auth.RoleAdmin,
	// Who can sign in, which also asks for the password again
	// (allowRecent).
	"Users": auth.RoleAdmin, "CreateUser": auth.RoleAdmin, "SetUserRole": auth.RoleAdmin,
	"SetUserPassword": auth.RoleAdmin, "LockUser": auth.RoleAdmin, "RemoveUser": auth.RoleAdmin,
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

// Managing accounts (auth.Admin), each change by an admin who gave
// their password within auth.ReauthWindow.

type (
	UsersReply struct {
		Result
		Users      []auth.Account
		Candidates []auth.Account
	}
	UserRoleArgs     struct{ Name, Role string }
	UserPasswordArgs struct{ Name, Password string }
	UserLockArgs     struct {
		Name   string
		Locked bool
	}
	NameOnlyArgs struct{ Name string }
	ReauthArgs   struct{ Password, Source string }
	OwnPassword  struct{ Current, New, Source string }
	// NoteReply is done, with something to say: removing an account
	// OPF didn't make only takes away its role.
	NoteReply struct {
		Result
		Note string
	}
)

// allowRecent is allow, and the password given lately.
func (s *Service) allowRecent(method string, c callInfo, r *Result) *auth.Session {
	sess := s.allow(method, c, r)
	if sess == nil {
		return nil
	}
	if !s.sessions.Recent(c.token()) {
		r.Err = &appliance.Error{Code: appliance.CodeReauth, Message: auth.ErrReauth.Error()}
		return nil
	}
	if s.admin == nil {
		r.Err = &appliance.Error{Code: appliance.CodeUnsupported, Message: "accounts can't be changed here"}
		return nil
	}
	return sess
}

// accountErr makes an auth error the API's.
func accountErr(err error) *appliance.Error {
	var wait *auth.WaitError
	switch {
	case err == nil:
		return nil
	case errors.As(err, &wait):
		return &appliance.Error{Code: appliance.CodeRateLimited, Message: wait.Error()}
	case errors.Is(err, auth.ErrBadLogin):
		return &appliance.Error{Code: appliance.CodeInvalid, Message: "that isn't your password", Details: []appliance.Detail{{Path: "current", Message: "that isn't your password"}}}
	case errors.Is(err, auth.ErrNoAccount):
		return &appliance.Error{Code: appliance.CodeNotFound, Message: err.Error()}
	case errors.Is(err, auth.ErrLastAdmin), errors.Is(err, auth.ErrSelf), errors.Is(err, auth.ErrSystem), errors.Is(err, auth.ErrExists):
		return &appliance.Error{Code: appliance.CodeConflict, Message: err.Error()}
	case errors.Is(err, auth.ErrBadName):
		return &appliance.Error{Code: appliance.CodeInvalid, Message: err.Error(), Details: []appliance.Detail{{Path: "name", Message: err.Error()}}}
	case errors.Is(err, auth.ErrBadFull):
		return &appliance.Error{Code: appliance.CodeInvalid, Message: err.Error(), Details: []appliance.Detail{{Path: "fullName", Message: err.Error()}}}
	case errors.Is(err, auth.ErrBadRole):
		return &appliance.Error{Code: appliance.CodeInvalid, Message: err.Error(), Details: []appliance.Detail{{Path: "role", Message: err.Error()}}}
	case errors.Is(err, auth.ErrWeak):
		return &appliance.Error{Code: appliance.CodeInvalid, Message: err.Error(), Details: []appliance.Detail{{Path: "password", Message: err.Error()}}}
	}
	return nil
}

func (s *Service) setAccountErr(method string, r *Result, err error) {
	if e := accountErr(err); e != nil {
		r.Err = e
		return
	}
	r.set(method, err)
}

func (s *Service) audit(by, msg string) {
	if s.auditf != nil {
		s.auditf(false, by, by+" "+msg)
	}
}

func accountCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), time.Minute)
}

// Users lists who can sign in, and the accounts that could be given a
// role.
func (s *Service) Users(c Call[None], r *UsersReply) error {
	if s.allow("Users", c, &r.Result) == nil {
		return nil
	}
	if s.admin == nil {
		return nil
	}
	var err error
	r.Users, r.Candidates, err = s.admin.List()
	r.set("Users", err)
	return nil
}

func (s *Service) CreateUser(c Call[auth.NewAccount], r *EmptyReply) error {
	sess := s.allowRecent("CreateUser", c, &r.Result)
	if sess == nil {
		return nil
	}
	ctx, cancel := accountCtx()
	defer cancel()
	a := c.Args
	err := s.admin.Create(ctx, a)
	s.setAccountErr("CreateUser", &r.Result, err)
	if err == nil {
		s.audit(sess.User, "made the account "+a.Name+", "+a.Role)
	}
	return nil
}

func (s *Service) SetUserRole(c Call[UserRoleArgs], r *EmptyReply) error {
	sess := s.allowRecent("SetUserRole", c, &r.Result)
	if sess == nil {
		return nil
	}
	ctx, cancel := accountCtx()
	defer cancel()
	a := c.Args
	err := s.admin.SetRole(ctx, a.Name, a.Role, sess.User)
	s.setAccountErr("SetUserRole", &r.Result, err)
	if err == nil {
		// Their sessions get the new role, or end, on their next request.
		s.sessions.Recheck(a.Name)
		if a.Role == "" {
			s.audit(sess.User, "took away "+a.Name+"'s role")
		} else {
			s.audit(sess.User, "made "+a.Name+" "+a.Role)
		}
	}
	return nil
}

func (s *Service) SetUserPassword(c Call[UserPasswordArgs], r *EmptyReply) error {
	sess := s.allowRecent("SetUserPassword", c, &r.Result)
	if sess == nil {
		return nil
	}
	ctx, cancel := accountCtx()
	defer cancel()
	a := c.Args
	err := s.admin.SetPassword(ctx, a.Name, a.Password)
	s.setAccountErr("SetUserPassword", &r.Result, err)
	if err == nil {
		keep := ""
		if a.Name == sess.User {
			keep = c.Token
		}
		s.sessions.EndUser(a.Name, keep, "the password was changed")
		s.audit(sess.User, "set "+a.Name+"'s password")
	}
	return nil
}

func (s *Service) LockUser(c Call[UserLockArgs], r *EmptyReply) error {
	sess := s.allowRecent("LockUser", c, &r.Result)
	if sess == nil {
		return nil
	}
	ctx, cancel := accountCtx()
	defer cancel()
	a := c.Args
	err := s.admin.Lock(ctx, a.Name, a.Locked, sess.User)
	s.setAccountErr("LockUser", &r.Result, err)
	if err == nil {
		if a.Locked {
			s.sessions.EndUser(a.Name, "", "the account was locked")
			s.audit(sess.User, "locked "+a.Name)
		} else {
			s.audit(sess.User, "unlocked "+a.Name)
		}
	}
	return nil
}

func (s *Service) RemoveUser(c Call[NameOnlyArgs], r *NoteReply) error {
	sess := s.allowRecent("RemoveUser", c, &r.Result)
	if sess == nil {
		return nil
	}
	ctx, cancel := accountCtx()
	defer cancel()
	a := c.Args
	err := s.admin.Remove(ctx, a.Name, sess.User)
	switch {
	case errors.Is(err, auth.ErrNotCreated):
		r.Note = "OPF didn't make " + a.Name + ", so it took away their role and left the account."
		s.sessions.EndUser(a.Name, "", "the account's role was taken away")
		s.audit(sess.User, "took away "+a.Name+"'s role")
	case err == nil:
		s.sessions.EndUser(a.Name, "", "the account was removed")
		s.audit(sess.User, "removed the account "+a.Name)
	default:
		s.setAccountErr("RemoveUser", &r.Result, err)
	}
	return nil
}

// Reauth checks the caller's password again, for the changes above.
func (s *Service) Reauth(c Call[ReauthArgs], r *EmptyReply) error {
	if s.allow("Reauth", c, &r.Result) == nil {
		return nil
	}
	ctx, cancel := accountCtx()
	defer cancel()
	err := s.sessions.Reauthenticate(ctx, c.Token, c.Args.Password, c.Args.Source)
	if errors.Is(err, auth.ErrBadLogin) {
		r.Err = &appliance.Error{Code: appliance.CodeInvalid, Message: "that isn't your password", Details: []appliance.Detail{{Path: "password", Message: "that isn't your password"}}}
		return nil
	}
	s.setAccountErr("Reauth", &r.Result, err)
	return nil
}

// ChangeOwnPassword is anyone changing their own, with the current one.
func (s *Service) ChangeOwnPassword(c Call[OwnPassword], r *EmptyReply) error {
	sess := s.allow("ChangeOwnPassword", c, &r.Result)
	if sess == nil {
		return nil
	}
	if s.admin == nil {
		r.Err = &appliance.Error{Code: appliance.CodeUnsupported, Message: "passwords can't be changed here"}
		return nil
	}
	ctx, cancel := accountCtx()
	defer cancel()
	a := c.Args
	if err := s.sessions.CheckPassword(ctx, sess.User, a.Current, a.Source); err != nil {
		s.setAccountErr("ChangeOwnPassword", &r.Result, err)
		return nil
	}
	err := s.admin.SetPassword(ctx, sess.User, a.New)
	if errors.Is(err, auth.ErrWeak) {
		r.Err = &appliance.Error{Code: appliance.CodeInvalid, Message: err.Error(), Details: []appliance.Detail{{Path: "new", Message: err.Error()}}}
		return nil
	}
	s.setAccountErr("ChangeOwnPassword", &r.Result, err)
	if err == nil {
		s.sessions.EndUser(sess.User, c.Token, "the password was changed")
		s.audit(sess.User, "changed their own password")
	}
	return nil
}

func (c *Client) Users() ([]auth.Account, []auth.Account, error) {
	var r UsersReply
	err := c.call("Users", None{}, &r)
	return nonNil(r.Users), nonNil(r.Candidates), err
}

func (c *Client) CreateUser(a auth.NewAccount) error {
	var r EmptyReply
	return c.call("CreateUser", a, &r)
}

func (c *Client) SetUserRole(name, role string) error {
	var r EmptyReply
	return c.call("SetUserRole", UserRoleArgs{name, role}, &r)
}

func (c *Client) SetUserPassword(name, password string) error {
	var r EmptyReply
	return c.call("SetUserPassword", UserPasswordArgs{name, password}, &r)
}

func (c *Client) LockUser(name string, locked bool) error {
	var r EmptyReply
	return c.call("LockUser", UserLockArgs{name, locked}, &r)
}

func (c *Client) RemoveUser(name string) (string, error) {
	var r NoteReply
	err := c.call("RemoveUser", NameOnlyArgs{name}, &r)
	return r.Note, err
}

func (c *Client) Reauth(password, source string) error {
	var r EmptyReply
	return c.call("Reauth", ReauthArgs{password, source}, &r)
}

func (c *Client) ChangeOwnPassword(current, new, source string) error {
	var r EmptyReply
	return c.call("ChangeOwnPassword", OwnPassword{current, new, source}, &r)
}

type (
	TunnelKeyReply struct {
		Result
		PublicKey string
	}
	DeviceKeyReply struct {
		Result
		Key *appliance.DeviceKey
	}
)

func (s *Service) NewTunnelKey(c Call[None], r *TunnelKeyReply) error {
	if s.allow("NewTunnelKey", c, &r.Result) == nil {
		return nil
	}
	var err error
	r.PublicKey, err = s.api.NewTunnelKey()
	r.set("NewTunnelKey", err)
	return nil
}

// ImportKeyArgs is a tunnel's private key made elsewhere.
type ImportKeyArgs struct{ PrivateKey string }

func (s *Service) ImportTunnelKey(c Call[ImportKeyArgs], r *TunnelKeyReply) error {
	if s.allow("ImportTunnelKey", c, &r.Result) == nil {
		return nil
	}
	var err error
	r.PublicKey, err = s.api.ImportTunnelKey(c.Args.PrivateKey)
	r.set("ImportTunnelKey", err)
	return nil
}

func (s *Service) NewDeviceKey(c Call[None], r *DeviceKeyReply) error {
	if s.allow("NewDeviceKey", c, &r.Result) == nil {
		return nil
	}
	var err error
	r.Key, err = s.api.NewDeviceKey()
	r.set("NewDeviceKey", err)
	return nil
}

func (c *Client) NewTunnelKey() (string, error) {
	var r TunnelKeyReply
	err := c.call("NewTunnelKey", None{}, &r)
	return r.PublicKey, err
}

func (c *Client) ImportTunnelKey(privateKey string) (string, error) {
	var r TunnelKeyReply
	err := c.call("ImportTunnelKey", ImportKeyArgs{privateKey}, &r)
	return r.PublicKey, err
}

func (c *Client) NewDeviceKey() (*appliance.DeviceKey, error) {
	var r DeviceKeyReply
	err := c.call("NewDeviceKey", None{}, &r)
	return r.Key, err
}

type PresharedKeyReply struct {
	Result
	Key *appliance.PresharedKey
}

func (s *Service) SetPresharedKey(c Call[appliance.PresharedKeyRequest], r *PresharedKeyReply) error {
	if s.allow("SetPresharedKey", c, &r.Result) == nil {
		return nil
	}
	var err error
	r.Key, err = s.api.SetPresharedKey(c.Args)
	r.set("SetPresharedKey", err)
	return nil
}

func (c *Client) SetPresharedKey(req appliance.PresharedKeyRequest) (*appliance.PresharedKey, error) {
	var r PresharedKeyReply
	err := c.call("SetPresharedKey", req, &r)
	return r.Key, err
}
