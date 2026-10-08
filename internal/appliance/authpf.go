package appliance

import (
	"context"
	"fmt"
	"log"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dantecatalfamo/OPF/internal/pf"
)

// Sign-in access's accounts and sessions (pf.Authpf). Each sign-in user
// is a system account OPF makes: authpf as its shell, in the authpf
// group (sshd's block for them), no password, home /var/empty, and its
// comment starting with pf.AuthpfAccountMark. OPF keeps those accounts
// to the model, after each commit and every collector tick, and never
// touches an account without the mark: a login some other account has
// is reported, not taken over.
//
// A session is an authpf process, "-authpf: <user>@<address>", with
// its rules in the anchor authpf/<user>(<pid>). Ending one signals that
// process, which takes its rules and its address out and ends every
// connection from the address.

type authpfState struct {
	mu sync.Mutex
	// taken are logins another account has, reported once each.
	taken map[string]bool
	// sessions are those last seen, by pid, for the event log.
	sessions map[int]AuthpfSession
	seen     bool
}

// passwdEntry is a line of /etc/passwd.
type passwdEntry struct {
	name, gecos, shell string
	uid                int
}

func (m *Manager) readPasswd() (map[string]passwdEntry, error) {
	data, err := os.ReadFile(m.store.SystemPath("/etc/passwd"))
	if err != nil {
		return nil, err
	}
	out := map[string]passwdEntry{}
	for _, l := range strings.Split(string(data), "\n") {
		f := strings.Split(l, ":")
		if len(f) < 7 || strings.HasPrefix(l, "#") {
			continue
		}
		uid, _ := strconv.Atoi(f[2])
		out[f[0]] = passwdEntry{name: f[0], uid: uid, gecos: f[4], shell: f[6]}
	}
	return out, nil
}

// ours is whether OPF made an account for sign-in access.
func (e passwdEntry) ours() bool {
	return strings.HasPrefix(e.gecos, pf.AuthpfAccountMark) && e.shell == pf.AuthpfShell && e.uid >= 1000
}

// authpfGecos is an account's comment: the mark, then its description
// without what passwd(5) or a GECOS field can't hold.
func authpfGecos(u pf.AuthpfUser) string {
	d := strings.Map(func(r rune) rune {
		if r == ':' || r == ',' || r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, u.Description)
	if d = strings.TrimSpace(d); d != "" {
		return pf.AuthpfAccountMark + " - " + d // never ":", passwd(5)'s separator
	}
	return pf.AuthpfAccountMark
}

// syncAuthpfAccounts keeps the sign-in accounts to the model: makes the
// missing, takes out OPF's no longer there.
func (m *Manager) syncAuthpfAccounts(model *pf.Model) {
	if model == nil {
		return
	}
	a := &m.authpf
	a.mu.Lock()
	defer a.mu.Unlock()
	accounts, err := m.readPasswd()
	if err != nil {
		return
	}
	var want []pf.AuthpfUser
	if pf.AuthpfOn(model) {
		want = model.Firewall.Authpf.Users
	}
	if a.taken == nil {
		a.taken = map[string]bool{}
	}
	run := func(argv ...string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		out, err := m.actions().Run(ctx, argv...)
		if err != nil {
			return fmt.Errorf("%s: %v %s", strings.Join(argv[:1], " "), err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	for _, u := range want {
		e, exists := accounts[u.Name]
		switch {
		case !exists:
			// No password ("*"): signing in takes a key.
			if err := run("useradd", "-c", authpfGecos(u), "-d", "/var/empty", "-s", pf.AuthpfShell, "-G", pf.AuthpfGroup, "-L", "default", u.Name); err != nil {
				log.Printf("sign-in access: couldn't make the account %s: %v", u.Name, err)
				continue
			}
			m.RecordEvent(Event{Time: time.Now(), Kind: EventAuthpf, Subject: u.Name, Message: fmt.Sprintf("Made the sign-in account %s", u.Name)})
		case !e.ours():
			if !a.taken[u.Name] {
				a.taken[u.Name] = true
				m.RecordEvent(Event{Time: time.Now(), Kind: EventAuthpf, Warning: true, Subject: u.Name, Message: fmt.Sprintf("Can't make the sign-in account %s: an account OPF didn't make has that login", u.Name)})
			}
		case e.gecos != authpfGecos(u):
			if err := run("usermod", "-c", authpfGecos(u), u.Name); err != nil {
				log.Printf("sign-in access: %v", err)
			}
		}
	}
	for name, e := range accounts {
		if !e.ours() || slices.ContainsFunc(want, func(u pf.AuthpfUser) bool { return u.Name == name }) {
			continue
		}
		// Its home is /var/empty: never userdel -r.
		if err := run("userdel", name); err != nil {
			log.Printf("sign-in access: couldn't remove the account %s: %v", name, err)
			continue
		}
		m.RecordEvent(Event{Time: time.Now(), Kind: EventAuthpf, Subject: name, Message: fmt.Sprintf("Removed the sign-in account %s", name)})
	}
	for name := range a.taken {
		if !slices.ContainsFunc(want, func(u pf.AuthpfUser) bool { return u.Name == name }) {
			delete(a.taken, name)
		}
	}
}

// AuthpfSession is someone signed in now.
type AuthpfSession struct {
	User    string    `json:"user"`
	Address string    `json:"address"`
	PID     int       `json:"pid"`
	Since   time.Time `json:"since"`
	// Rules is whether their rules are loaded (the anchor is there).
	Rules bool `json:"rules"`
}

// AuthpfSessions is who's signed in.
type AuthpfSessions struct {
	Enabled  bool            `json:"enabled"`
	Sessions []AuthpfSession `json:"sessions"`
}

// parseAuthpfPs reads ps -axww -o pid,lstart,command for authpf
// processes: "34725 Thu Oct  8 01:02:42 2026 -authpf: alice@10.0.0.5 (authpf)".
func parseAuthpfPs(out string, loc *time.Location) []AuthpfSession {
	var res []AuthpfSession
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) < 8 || f[6] != "-authpf:" {
			continue
		}
		pid, err := strconv.Atoi(f[0])
		if err != nil || pid <= 1 {
			continue
		}
		since, err := time.ParseInLocation("Mon Jan _2 15:04:05 2006", strings.Join(f[1:6], " "), loc)
		if err != nil {
			continue
		}
		at := strings.LastIndex(f[7], "@")
		if at <= 0 {
			continue
		}
		res = append(res, AuthpfSession{User: f[7][:at], Address: f[7][at+1:], PID: pid, Since: since})
	}
	return res
}

// authpfSessions reads who's signed in.
func (m *Manager) authpfSessions() ([]AuthpfSession, error) {
	out, err := m.read("ps", "-axww", "-o", "pid,lstart,command")
	if err != nil {
		return nil, fmt.Errorf("ps: %v", err)
	}
	sessions := parseAuthpfPs(out, time.Local)
	if anchors, err := m.read("pfctl", "-a", pf.AuthpfAnchor, "-s", "Anchors"); err == nil {
		for i := range sessions {
			s := &sessions[i]
			s.Rules = strings.Contains(anchors, fmt.Sprintf("%s/%s(%d)", pf.AuthpfAnchor, s.User, s.PID))
		}
	}
	sort.Slice(sessions, func(i, j int) bool { return sessions[i].Since.After(sessions[j].Since) })
	return sessions, nil
}

// AuthpfSessions is who's signed in now.
func (m *Manager) AuthpfSessions() (*AuthpfSessions, error) {
	model, err := m.liveOrEmpty()
	if err != nil {
		return nil, apiError(err)
	}
	out := &AuthpfSessions{Enabled: pf.AuthpfOn(model), Sessions: []AuthpfSession{}}
	s, err := m.authpfSessions()
	if err != nil {
		return nil, errorf(CodeInternal, "%v", err)
	}
	out.Sessions = append(out.Sessions, s...)
	return out, nil
}

// AuthpfEndRequest ends a session, by its process.
type AuthpfEndRequest struct {
	PID int `json:"pid"`
	// By is who asked; the privileged side sets it from the session.
	By string `json:"-"`
}

// AuthpfEnd ends a session: only an authpf process that's signed in now,
// never any other pid.
func (m *Manager) AuthpfEnd(req AuthpfEndRequest) error {
	sessions, err := m.authpfSessions()
	if err != nil {
		return errorf(CodeInternal, "%v", err)
	}
	i := slices.IndexFunc(sessions, func(s AuthpfSession) bool { return s.PID == req.PID })
	if i < 0 {
		return errorf(CodeNotFound, "no one is signed in with process %d", req.PID)
	}
	s := sessions[i]
	ctx, cancel := context.WithTimeout(context.Background(), readTimeout)
	defer cancel()
	if out, err := m.actions().Run(ctx, "kill", "-TERM", strconv.Itoa(s.PID)); err != nil {
		return errorf(CodeInternal, "kill %d: %v %s", s.PID, err, strings.TrimSpace(string(out)))
	}
	who := req.By
	if who == "" {
		who = "Someone"
	}
	m.RecordEvent(Event{Time: time.Now(), Kind: EventAuthpf, Subject: s.User, Message: fmt.Sprintf("%s ended %s's session from %s", who, s.User, s.Address)})
	return nil
}

// watchAuthpfSessions records sign-ins and sign-outs, every collector
// tick.
func (m *Manager) watchAuthpfSessions(model *pf.Model) {
	a := &m.authpf
	a.mu.Lock()
	defer a.mu.Unlock()
	if model == nil || !pf.AuthpfOn(model) {
		a.sessions, a.seen = nil, false
		return
	}
	list, err := m.authpfSessions()
	if err != nil {
		return
	}
	now := map[int]AuthpfSession{}
	for _, s := range list {
		now[s.PID] = s
	}
	if a.seen {
		for pid, s := range now {
			if _, ok := a.sessions[pid]; !ok {
				m.RecordEvent(Event{Time: s.Since, Kind: EventAuthpf, Subject: s.User, Message: fmt.Sprintf("%s signed in from %s", s.User, s.Address)})
			}
		}
		for pid, s := range a.sessions {
			if _, ok := now[pid]; !ok {
				m.RecordEvent(Event{Time: time.Now(), Kind: EventAuthpf, Subject: s.User, Message: fmt.Sprintf("%s signed out (from %s, after %s)", s.User, s.Address, time.Since(s.Since).Round(time.Second))})
			}
		}
	}
	a.sessions, a.seen = now, true
}
