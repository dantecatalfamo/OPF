package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"
)

// Role is what someone signed in may do. Each includes the ones
// before it.
type Role int

const (
	RoleNone     Role = iota
	RoleView          // see everything
	RoleOperator      // and confirm or revert a commit, run tools, refresh lists
	RoleAdmin         // and change the configuration
)

func (r Role) String() string {
	switch r {
	case RoleView:
		return "view"
	case RoleOperator:
		return "operator"
	case RoleAdmin:
		return "admin"
	}
	return "none"
}

// Groups give roles: membership of one lets someone sign in. Anyone
// else, root and wheel included, can't.
var Groups = map[string]Role{"_opfadmin": RoleAdmin, "_opfoperator": RoleOperator, "_opfview": RoleView}

// Session is someone signed in. ID names it in lists; the token that
// proves it is never shown again after signing in.
type Session struct {
	ID       string    `json:"id"`
	User     string    `json:"user"`
	Role     Role      `json:"-"`
	Source   string    `json:"source"`
	Created  time.Time `json:"created"`
	LastUsed time.Time `json:"lastUsed"`
}

var (
	// ErrBadLogin never says which part was wrong, or whether the
	// account exists or may sign in.
	ErrBadLogin  = errors.New("the name or password is wrong")
	ErrNoSession = errors.New("not signed in, or the session ended")
)

// WaitError says to try again later: too many failed attempts.
type WaitError struct{ For time.Duration }

func (e *WaitError) Error() string {
	return fmt.Sprintf("too many failed attempts; try again in %d s", int(e.For.Round(time.Second)/time.Second)+1)
}

// Event is something to record: a sign-in, a refusal, a sign-out.
type Event struct {
	Kind    string // "login", "refused", "logout", "ended"
	User    string
	Source  string
	Message string
}

// Sessions keeps who's signed in, in memory: a restart signs everyone
// out.
type Sessions struct {
	Checker Checker
	Passwd  string // master.passwd
	Group   string // /etc/group
	Idle    time.Duration
	Max     time.Duration
	// MinFail is the least a failed attempt takes, so the time doesn't
	// say whether the account exists.
	MinFail time.Duration
	Now     func() time.Time
	Log     func(Event)

	mu       sync.Mutex
	sessions map[[32]byte]*entry
	fails    map[string]*backoff
}

type entry struct {
	Session
	pass    [32]byte // the password hash's fingerprint at sign-in
	checked time.Time
	// authed is when the password was last given: signing in, or
	// asked again for a sensitive change (Reauthenticate).
	authed time.Time
}

type backoff struct {
	n    int
	next time.Time
}

// NewSessions is sessions of the system's accounts: 30 minutes idle, 12
// hours in all.
func NewSessions(c Checker) *Sessions {
	return &Sessions{Checker: c, Passwd: "/etc/master.passwd", Group: "/etc/group", Idle: 30 * time.Minute, Max: 12 * time.Hour, MinFail: time.Second}
}

const (
	firstWait = time.Second
	maxWait   = 5 * time.Minute
	recheck   = time.Minute // how often a session's account is read again
)

func (s *Sessions) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Sessions) log(e Event) {
	if s.Log != nil {
		s.Log(e)
	}
}

func tokenKey(token string) [32]byte { return sha256.Sum256([]byte(token)) }

// Login checks a name and password and starts a session. source is
// where the attempt came from, as the web process saw it: only used to
// slow down guessing from one place.
func (s *Sessions) Login(ctx context.Context, user, password, source string) (string, *Session, error) {
	start := s.now()
	if wait := s.waiting(user, source, start); wait > 0 {
		s.log(Event{Kind: "refused", User: user, Source: source, Message: "too many failed attempts"})
		return "", nil, &WaitError{For: wait}
	}
	tok, sess, why, err := s.login(ctx, user, password, source)
	if err != nil {
		return "", nil, err
	}
	if sess == nil {
		s.failed(user, source)
		s.log(Event{Kind: "refused", User: user, Source: source, Message: why})
		if d := s.MinFail - s.now().Sub(start); d > 0 {
			select {
			case <-time.After(d):
			case <-ctx.Done():
			}
		}
		return "", nil, ErrBadLogin
	}
	s.mu.Lock()
	delete(s.fails, "user:"+user)
	delete(s.fails, "addr:"+source)
	s.mu.Unlock()
	s.log(Event{Kind: "login", User: user, Source: source, Message: "signed in as " + sess.Role.String()})
	return tok, sess, nil
}

func (s *Sessions) login(ctx context.Context, user, password, source string) (string, *Session, string, error) {
	ok, err := s.Checker.Check(ctx, user, password)
	if err != nil {
		return "", nil, "", err
	}
	if !ok {
		return "", nil, "wrong name or password", nil
	}
	acct, role, err := s.account(user)
	if err != nil {
		return "", nil, "", err
	}
	if acct == nil || role == RoleNone {
		return "", nil, "not in " + groupList(), nil
	}
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", nil, "", err
	}
	tok := base64.RawURLEncoding.EncodeToString(b[:])
	var id [9]byte
	rand.Read(id[:])
	now := s.now()
	e := &entry{
		Session: Session{ID: base64.RawURLEncoding.EncodeToString(id[:]), User: user, Role: role, Source: source, Created: now, LastUsed: now},
		pass:    acct.Pass, checked: now, authed: now,
	}
	s.mu.Lock()
	if s.sessions == nil {
		s.sessions = map[[32]byte]*entry{}
	}
	s.sessions[tokenKey(tok)] = e
	s.mu.Unlock()
	sess := e.Session
	return tok, &sess, "", nil
}

// groupList names OPF's groups: "_opfadmin, _opfoperator or _opfview".
func groupList() string {
	var g []string
	for n := range Groups {
		g = append(g, n)
	}
	slices.Sort(g)
	return strings.Join(g[:len(g)-1], ", ") + " or " + g[len(g)-1]
}

// account reads the user's account and role from the system's files.
func (s *Sessions) account(user string) (*account, Role, error) {
	acct, err := lookupUser(s.Passwd, user)
	if err != nil || acct == nil {
		return nil, RoleNone, err
	}
	var names []string
	for n := range Groups {
		names = append(names, n)
	}
	in, err := groupMembers(s.Group, names, user, acct.GID)
	if err != nil {
		return nil, RoleNone, err
	}
	role := RoleNone
	for _, g := range in {
		role = max(role, Groups[g])
	}
	return acct, role, nil
}

func (s *Sessions) waiting(user, source string, now time.Time) time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	var wait time.Duration
	for _, k := range []string{"user:" + user, "addr:" + source} {
		if b := s.fails[k]; b != nil && b.next.After(now) {
			wait = max(wait, b.next.Sub(now))
		}
	}
	return wait
}

// failed doubles the wait after each failure, from a second up to five
// minutes, for the name and for the source.
func (s *Sessions) failed(user, source string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fails == nil {
		s.fails = map[string]*backoff{}
	}
	now := s.now()
	for _, k := range []string{"user:" + user, "addr:" + source} {
		b := s.fails[k]
		if b == nil {
			b = &backoff{}
			s.fails[k] = b
		}
		d := firstWait << min(b.n, 20)
		b.n++
		b.next = now.Add(min(d, maxWait))
	}
	// Forget old failures, so the map can't grow without end.
	if len(s.fails) > 10000 {
		for k, b := range s.fails {
			if now.Sub(b.next) > maxWait {
				delete(s.fails, k)
			}
		}
	}
}

// Check returns the session a token proves, and counts it as used. A
// session ends when it's been idle too long or is too old, and when its
// account changes: a new password, leaving the groups, expiring.
func (s *Sessions) Check(token string) (*Session, error) { return s.check(token, true) }

// Peek is Check without counting the session as used: for a page
// polling while nobody's there.
func (s *Sessions) Peek(token string) (*Session, error) { return s.check(token, false) }

func (s *Sessions) check(token string, use bool) (*Session, error) {
	if token == "" {
		return nil, ErrNoSession
	}
	k := tokenKey(token)
	now := s.now()
	s.mu.Lock()
	e := s.sessions[k]
	if e == nil {
		s.mu.Unlock()
		return nil, ErrNoSession
	}
	why := ""
	switch {
	case now.Sub(e.LastUsed) > s.Idle:
		why = "idle too long"
	case now.Sub(e.Created) > s.Max:
		why = "too old"
	}
	recheck := why == "" && now.Sub(e.checked) >= recheck
	s.mu.Unlock()
	if recheck {
		acct, role, err := s.account(e.User)
		switch {
		case err != nil:
			why = "the account couldn't be read"
		case acct == nil:
			why = "the account was removed"
		case acct.Pass != e.pass:
			why = "the password changed"
		case acct.expired(now):
			why = "the account expired"
		case role == RoleNone:
			why = "the account isn't in " + groupList() + " any more"
		}
		s.mu.Lock()
		e.checked = now
		if why == "" {
			e.Role = role
		}
		s.mu.Unlock()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if why != "" {
		if s.sessions[k] == e {
			delete(s.sessions, k)
			go s.log(Event{Kind: "ended", User: e.User, Source: e.Source, Message: "session ended: " + why})
		}
		return nil, ErrNoSession
	}
	if use {
		e.LastUsed = now
	}
	sess := e.Session
	return &sess, nil
}

// Logout ends the token's session.
func (s *Sessions) Logout(token string) {
	k := tokenKey(token)
	s.mu.Lock()
	e := s.sessions[k]
	delete(s.sessions, k)
	s.mu.Unlock()
	if e != nil {
		s.log(Event{Kind: "logout", User: e.User, Source: e.Source, Message: "signed out"})
	}
}

// List returns the sessions, oldest first: a user's own, or with all
// everyone's.
func (s *Sessions) List(user string, all bool) []Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Session
	for _, e := range s.sessions {
		if all || e.User == user {
			out = append(out, e.Session)
		}
	}
	slices.SortFunc(out, func(a, b Session) int { return a.Created.Compare(b.Created) })
	return out
}

// End ends a session by its ID: the user's own, or with all anyone's.
func (s *Sessions) End(id, user string, all bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, e := range s.sessions {
		if e.ID == id && (all || e.User == user) {
			delete(s.sessions, k)
			go s.log(Event{Kind: "ended", User: e.User, Source: e.Source, Message: "session ended by " + user})
			return true
		}
	}
	return false
}

// ReauthWindow is how long giving the password again lasts for
// sensitive changes (who can sign in).
const ReauthWindow = 5 * time.Minute

// ErrReauth asks for the password again.
var ErrReauth = errors.New("enter your password again to do this")

// Reauthenticate checks the session's user's password again, for a
// sensitive change; failures back off like signing in.
func (s *Sessions) Reauthenticate(ctx context.Context, token, password, source string) error {
	sess, err := s.Check(token)
	if err != nil {
		return err
	}
	if wait := s.waiting(sess.User, source, s.now()); wait > 0 {
		return &WaitError{For: wait}
	}
	ok, err := s.Checker.Check(ctx, sess.User, password)
	if err != nil {
		return err
	}
	if !ok {
		s.failed(sess.User, source)
		s.log(Event{Kind: "refused", User: sess.User, Source: source, Message: "wrong password asked again"})
		return ErrBadLogin
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.sessions[tokenKey(token)]; e != nil {
		e.authed = s.now()
	}
	return nil
}

// Recent says whether the token's password was given within
// ReauthWindow.
func (s *Sessions) Recent(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.sessions[tokenKey(token)]
	return e != nil && s.now().Sub(e.authed) <= ReauthWindow
}

// EndUser ends a user's sessions, but the one with keep (their own,
// changing their password).
func (s *Sessions) EndUser(user, keep, why string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := tokenKey(keep)
	for key, e := range s.sessions {
		if e.User == user && (keep == "" || key != k) {
			delete(s.sessions, key)
			go s.log(Event{Kind: "ended", User: e.User, Source: e.Source, Message: "session ended: " + why})
		}
	}
}

// CheckPassword says whether password is the user's, for changing your
// own (which asks for the current one). It backs off like signing in.
func (s *Sessions) CheckPassword(ctx context.Context, user, password, source string) error {
	if wait := s.waiting(user, source, s.now()); wait > 0 {
		return &WaitError{For: wait}
	}
	ok, err := s.Checker.Check(ctx, user, password)
	if err != nil {
		return err
	}
	if !ok {
		s.failed(user, source)
		return ErrBadLogin
	}
	return nil
}

// Recheck has the user's sessions read their account again on their
// next use: a role changed, so they get the new one straight away.
func (s *Sessions) Recheck(user string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.sessions {
		if e.User == user {
			e.checked = time.Time{}
		}
	}
}
