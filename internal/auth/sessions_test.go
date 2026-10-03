package auth

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type fixture struct {
	t      *testing.T
	dir    string
	now    time.Time
	s      *Sessions
	mu     sync.Mutex // Log is called from goroutines too
	logged []Event
}

func (f *fixture) events() []Event {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.logged)
}

func newFixture(t *testing.T) *fixture {
	f := &fixture{t: t, dir: t.TempDir(), now: time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)}
	f.passwd(map[string]string{"alice": "$2b$10$a", "bob": "$2b$10$b", "carol": "$2b$10$c", "dave": "$2b$10$d", "root": "$2b$10$r"})
	f.groups("_opfadmin:*:900:alice\n_opfoperator:*:901:bob,carol\n_opfview:*:902:carol\nwheel:*:0:root,dave\n")
	f.s = &Sessions{
		Checker: Static{"alice": "a-pass", "bob": "b-pass", "carol": "c-pass", "dave": "d-pass", "root": "r-pass", "erin": "e-pass"},
		Passwd:  filepath.Join(f.dir, "master.passwd"), Group: filepath.Join(f.dir, "group"),
		Idle: 30 * time.Minute, Max: 12 * time.Hour,
		Now: func() time.Time { return f.now },
		Log: func(e Event) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.logged = append(f.logged, e)
		},
	}
	return f
}

func (f *fixture) passwd(hashes map[string]string) {
	var b strings.Builder
	uid := 1000
	for _, u := range []string{"root", "alice", "bob", "carol", "dave"} {
		h, ok := hashes[u]
		if !ok {
			continue
		}
		gid := uid
		if u == "dave" {
			gid = 900 // primary group _opfadmin
		}
		b.WriteString(strings.Join([]string{u, h, strconv.Itoa(uid), strconv.Itoa(gid), "", "0", "0", u, "/home/" + u, "/bin/ksh"}, ":") + "\n")
		uid++
	}
	os.WriteFile(filepath.Join(f.dir, "master.passwd"), []byte(b.String()), 0600)
}

func (f *fixture) groups(s string) { os.WriteFile(filepath.Join(f.dir, "group"), []byte(s), 0644) }

func (f *fixture) login(user, pass string) (string, *Session, error) {
	return f.s.Login(context.Background(), user, pass, "192.0.2.10")
}

func TestLoginRoles(t *testing.T) {
	f := newFixture(t)
	for _, c := range []struct {
		user, pass string
		role       Role
	}{
		{"alice", "a-pass", RoleAdmin},
		{"bob", "b-pass", RoleOperator},
		{"carol", "c-pass", RoleOperator}, // in two: the more powerful
	} {
		tok, s, err := f.login(c.user, c.pass)
		if err != nil || s.Role != c.role || len(tok) < 40 {
			t.Errorf("%s: %v %+v", c.user, err, s)
			continue
		}
		if got, err := f.s.Check(tok); err != nil || got.User != c.user || got.Role != c.role {
			t.Errorf("%s: check %v %+v", c.user, err, got)
		}
	}
}

func TestLoginRefused(t *testing.T) {
	f := newFixture(t)
	for _, c := range [][2]string{
		{"alice", "wrong"},
		{"root", "r-pass"}, // root, but in none of the groups
		{"dave", "d-pass"}, // _opfadmin's id as his primary group, but not listed in it
		{"erin", "e-pass"}, // a password, but no account
		{"nobody", "x"},
	} {
		f.now = f.now.Add(10 * time.Minute) // past any backoff
		if tok, s, err := f.login(c[0], c[1]); !errors.Is(err, ErrBadLogin) || tok != "" || s != nil {
			t.Errorf("%s: %q %v %v", c[0], tok, s, err)
		}
	}
	// The same answer whatever was wrong; the reason is only logged.
	for _, e := range f.events() {
		if e.Kind != "refused" {
			t.Errorf("event %+v", e)
		}
	}
	if !strings.Contains(f.events()[1].Message, "not in") || !strings.Contains(f.events()[2].Message, "not in") {
		t.Errorf("root's refusal: %+v", f.events()[1])
	}
}

func TestBackoff(t *testing.T) {
	f := newFixture(t)
	f.login("alice", "wrong")
	// Straight away, even the right password waits: it isn't checked.
	if _, _, err := f.login("alice", "a-pass"); !isWait(err) {
		t.Fatalf("no wait: %v", err)
	}
	f.now = f.now.Add(2 * time.Second)
	f.login("alice", "wrong")
	f.now = f.now.Add(1500 * time.Millisecond) // the wait doubled to 2 s
	if _, _, err := f.login("alice", "a-pass"); !isWait(err) {
		t.Errorf("wait didn't double: %v", err)
	}
	// From the same address, another name waits too.
	if _, _, err := f.login("bob", "b-pass"); !isWait(err) {
		t.Errorf("no wait by address: %v", err)
	}
	f.now = f.now.Add(time.Second)
	if _, _, err := f.login("alice", "a-pass"); err != nil {
		t.Fatalf("after the wait: %v", err)
	}
	// Success clears it.
	f.login("alice", "wrong")
	f.now = f.now.Add(1100 * time.Millisecond)
	if _, _, err := f.login("alice", "a-pass"); err != nil {
		t.Errorf("didn't start again from a second: %v", err)
	}
	// It stops growing at five minutes.
	for i := 0; i < 30; i++ {
		f.now = f.now.Add(maxWait)
		f.login("bob", "wrong")
	}
	f.now = f.now.Add(maxWait + time.Second)
	if _, _, err := f.login("bob", "b-pass"); err != nil {
		t.Errorf("waits more than %v: %v", maxWait, err)
	}
}

func isWait(err error) bool {
	var w *WaitError
	return errors.As(err, &w)
}

func TestSessionEnds(t *testing.T) {
	f := newFixture(t)
	tok, _, _ := f.login("alice", "a-pass")
	// Used within the idle limit, it lasts.
	for i := 0; i < 4; i++ {
		f.now = f.now.Add(25 * time.Minute)
		if _, err := f.s.Check(tok); err != nil {
			t.Fatalf("after %d uses: %v", i, err)
		}
	}
	f.now = f.now.Add(31 * time.Minute)
	if _, err := f.s.Check(tok); !errors.Is(err, ErrNoSession) {
		t.Error("idle session still valid")
	}

	// Twelve hours at most, however busy.
	tok, _, _ = f.login("alice", "a-pass")
	for i := 0; i < 12*3; i++ {
		f.now = f.now.Add(20 * time.Minute)
		f.s.Check(tok)
	}
	f.now = f.now.Add(time.Minute)
	if _, err := f.s.Check(tok); !errors.Is(err, ErrNoSession) {
		t.Error("session older than 12 hours still valid")
	}

	// A new password ends it.
	tok, _, _ = f.login("alice", "a-pass")
	f.passwd(map[string]string{"alice": "$2b$10$new", "bob": "$2b$10$b", "carol": "$2b$10$c", "dave": "$2b$10$d", "root": "$2b$10$r"})
	f.now = f.now.Add(recheck)
	if _, err := f.s.Check(tok); !errors.Is(err, ErrNoSession) {
		t.Error("session survived a password change")
	}

	// Leaving the groups ends it; moving between them changes the role.
	tok, _, _ = f.login("bob", "b-pass")
	f.groups("_opfadmin:*:900:alice,bob\n_opfoperator:*:901:carol\n")
	f.now = f.now.Add(recheck)
	if s, err := f.s.Check(tok); err != nil || s.Role != RoleAdmin {
		t.Errorf("role after moving groups: %+v %v", s, err)
	}
	f.groups("_opfadmin:*:900:alice\n")
	f.now = f.now.Add(recheck)
	if _, err := f.s.Check(tok); !errors.Is(err, ErrNoSession) {
		t.Error("session survived leaving the groups")
	}

	// Signing out ends it; the token never works again.
	tok, _, _ = f.login("alice", "a-pass")
	f.s.Logout(tok)
	if _, err := f.s.Check(tok); !errors.Is(err, ErrNoSession) {
		t.Error("session survived signing out")
	}
	if _, err := f.s.Check(""); !errors.Is(err, ErrNoSession) {
		t.Error("an empty token is a session")
	}
}

func TestListAndEnd(t *testing.T) {
	f := newFixture(t)
	a1, _, _ := f.login("alice", "a-pass")
	f.now = f.now.Add(time.Second)
	f.login("alice", "a-pass")
	b, _, _ := f.login("bob", "b-pass")
	if l := f.s.List("alice", false); len(l) != 2 {
		t.Errorf("alice's: %+v", l)
	}
	if l := f.s.List("bob", true); len(l) != 3 {
		t.Errorf("everyone's: %+v", l)
	}
	bob := f.s.List("bob", false)[0]
	if f.s.End(bob.ID, "alice", false) {
		t.Error("ended someone else's session without being allowed to")
	}
	if !f.s.End(bob.ID, "alice", true) {
		t.Error("an admin couldn't end someone's session")
	}
	if _, err := f.s.Check(b); err == nil {
		t.Error("ended session still valid")
	}
	if _, err := f.s.Check(a1); err != nil {
		t.Error(err)
	}
}

func TestMinFail(t *testing.T) {
	f := newFixture(t)
	f.s.Now = nil
	f.s.MinFail = 200 * time.Millisecond
	start := time.Now()
	f.login("nobody", "x")
	if d := time.Since(start); d < 200*time.Millisecond {
		t.Errorf("a failure took %v", d)
	}
}

func TestLoginStyle(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "login.conf")
	os.WriteFile(conf, []byte(`# comment
auth-defaults:auth=passwd,skey:
default:\
	:path=/usr/bin /bin:\
	:tc=auth-defaults:
staff:\
	:auth-opf=yubikey:\
	:tc=default:
daemon:\
	:auth@:tc=default:
`), 0644)
	for class, want := range map[string]string{"default": "passwd", "staff": "yubikey", "nosuch": "passwd", "daemon": ""} {
		if got, err := loginStyle(conf, class); err != nil || got != want {
			t.Errorf("%s: %q %v, want %q", class, got, err, want)
		}
	}
	if got, _ := loginStyle(filepath.Join(dir, "none"), "default"); got != "" {
		t.Errorf("no login.conf: %q", got)
	}
}

func TestBSDAuthRefusesBadInput(t *testing.T) {
	b := BSDAuth{Dir: "/nonexistent", Timeout: time.Second}
	for _, c := range [][2]string{{"../../bin/sh", "x"}, {"a b", "x"}, {"alice", ""}, {"alice", "a\x00b"}, {"alice", strings.Repeat("x", MaxPassword+1)}, {strings.Repeat("a", 40), "x"}} {
		if ok, err := b.Check(context.Background(), c[0], c[1]); ok || err != nil {
			t.Errorf("%q: %v %v", c[0], ok, err)
		}
	}
}
