package auth

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/dantecatalfamo/OPF/internal/run"
)

// Managing who can sign in. Accounts are the system's; OPF only adds
// and removes members of its own three groups, creates and removes the
// accounts it made itself, and sets passwords and locks. It never
// changes another group, root, or a system account.

// Account is an account that can sign in, or could be given a role.
type Account struct {
	Name     string `json:"name"`
	FullName string `json:"fullName"`
	Role     string `json:"role"` // admin, operator, view, or "" for none
	Locked   bool   `json:"locked,omitempty"`
	Expired  bool   `json:"expired,omitempty"`
	Class    string `json:"class,omitempty"`
	// Shell: it can also log in over SSH or at the console.
	Shell bool `json:"shell"`
	// Created by OPF, so removing it removes the account; otherwise only
	// its role.
	Created bool `json:"created,omitempty"`
}

// NewAccount is an account to create.
type NewAccount struct {
	Name     string `json:"name"`
	FullName string `json:"fullName"`
	Role     string `json:"role"`
	Password string `json:"password"`
	Shell    bool   `json:"shell"`
}

// Writer makes the changes: the system's commands (System), or editing
// the files themselves (Files, for the mock server and tests).
type Writer interface {
	EnsureGroup(ctx context.Context, name string) error
	AddUser(ctx context.Context, name, fullName, shell, hash string, groups []string) error
	SetGroups(ctx context.Context, name string, groups []string) error
	SetHash(ctx context.Context, name, hash string) error
	Lock(ctx context.Context, name string, locked bool) error
	Remove(ctx context.Context, name string) error
	Hash(ctx context.Context, password string) (string, error)
}

// Admin manages accounts. Reading is from the files; changes go
// through W, one at a time.
type Admin struct {
	Passwd, Group string
	// Created lists the accounts OPF made, so it only ever deletes
	// those (a file in its state directory).
	Created string
	W       Writer
	mu      sync.Mutex
}

// Errors an admin sees.
var (
	ErrNoAccount  = errors.New("no such account")
	ErrLastAdmin  = errors.New("that would leave nobody who can change the configuration")
	ErrSelf       = errors.New("you can't take away your own admin role, or lock or remove yourself")
	ErrSystem     = errors.New("root and the system's own accounts can't be given a role")
	ErrExists     = errors.New("there's already an account with that name")
	ErrBadName    = errors.New("a name is 1 to 31 lowercase letters, digits and hyphens, starting with a letter")
	ErrBadFull    = errors.New("the full name can't contain : , or control characters, and is at most 64 characters")
	ErrBadRole    = errors.New("the role is admin, operator or view")
	ErrWeak       = fmt.Errorf("a password is %d to %d characters", MinPassword, MaxPassword)
	ErrNotCreated = errors.New("OPF didn't create that account, so it only takes away its role")
)

// MinPassword is the shortest password OPF sets.
const MinPassword = 12

var newNameRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}$`)

func roleOf(s string) (Role, bool) {
	switch s {
	case "admin":
		return RoleAdmin, true
	case "operator":
		return RoleOperator, true
	case "view":
		return RoleView, true
	case "":
		return RoleNone, true
	}
	return RoleNone, false
}

func groupFor(r Role) string {
	for g, gr := range Groups {
		if gr == r {
			return g
		}
	}
	return ""
}

func checkPassword(p string) error {
	if utf8.RuneCountInString(p) < MinPassword || len(p) > MaxPassword || strings.ContainsRune(p, 0) || !utf8.ValidString(p) {
		return ErrWeak
	}
	return nil
}

func checkFullName(s string) error {
	if utf8.RuneCountInString(s) > 64 || !utf8.ValidString(s) || strings.ContainsAny(s, ":,") || strings.ContainsFunc(s, unicode.IsControl) {
		return ErrBadFull
	}
	return nil
}

type pwEntry struct {
	name, hash, class, gecos, shell string
	uid, gid                        int
	expire                          int64
}

func readPasswd(path string) ([]pwEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []pwEntry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fs := strings.Split(sc.Text(), ":")
		if len(fs) != 10 {
			continue
		}
		uid, _ := strconv.Atoi(fs[2])
		gid, _ := strconv.Atoi(fs[3])
		exp, _ := strconv.ParseInt(fs[6], 10, 64)
		out = append(out, pwEntry{name: fs[0], hash: fs[1], uid: uid, gid: gid, class: fs[4], expire: exp, gecos: fs[7], shell: fs[9]})
	}
	return out, sc.Err()
}

// groupsOf is the secondary groups each user is in.
func groupsOf(path string) (map[string][]string, map[string]bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	members, exists := map[string][]string{}, map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fs := strings.Split(sc.Text(), ":")
		if len(fs) != 4 {
			continue
		}
		exists[fs[0]] = true
		for _, u := range strings.Split(fs[3], ",") {
			if u != "" {
				members[u] = append(members[u], fs[0])
			}
		}
	}
	return members, exists, sc.Err()
}

// eligible is an account a role can be given: not root, not a system
// account.
func eligible(e pwEntry) bool {
	return e.uid >= 1000 && e.name != "root" && !strings.HasPrefix(e.name, "_") && e.uid < 60000
}

func (a *Admin) created() map[string]bool {
	out := map[string]bool{}
	data, err := os.ReadFile(a.Created)
	if err != nil {
		return out
	}
	var names []string
	json.Unmarshal(data, &names)
	for _, n := range names {
		out[n] = true
	}
	return out
}

func (a *Admin) setCreated(name string, made bool) error {
	c := a.created()
	if made {
		c[name] = true
	} else {
		delete(c, name)
	}
	names := make([]string, 0, len(c))
	for n := range c {
		names = append(names, n)
	}
	slices.Sort(names)
	data, _ := json.Marshal(names)
	tmp := a.Created + ".new"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, a.Created)
}

// List is everyone who can sign in, and the accounts that could be
// given a role.
func (a *Admin) List() (members, candidates []Account, err error) {
	users, err := readPasswd(a.Passwd)
	if err != nil {
		return nil, nil, err
	}
	groups, _, err := groupsOf(a.Group)
	if err != nil {
		return nil, nil, err
	}
	gids := map[int]string{}
	if f, err := os.ReadFile(a.Group); err == nil {
		for _, l := range strings.Split(string(f), "\n") {
			fs := strings.Split(l, ":")
			if len(fs) == 4 {
				if g, err := strconv.Atoi(fs[2]); err == nil {
					gids[g] = fs[0]
				}
			}
		}
	}
	made := a.created()
	now := time.Now().Unix()
	for _, u := range users {
		role := RoleNone
		for _, g := range append(slices.Clone(groups[u.name]), gids[u.gid]) {
			role = max(role, Groups[g])
		}
		acct := Account{
			Name: u.name, FullName: u.gecos, Class: u.class,
			Locked:  strings.HasPrefix(u.hash, "*") || strings.HasPrefix(u.shell, "-"),
			Expired: u.expire != 0 && now >= u.expire,
			Shell:   !strings.HasSuffix(u.shell, "nologin"),
			Created: made[u.name],
		}
		if role != RoleNone {
			acct.Role = role.String()
			members = append(members, acct)
		} else if eligible(u) {
			candidates = append(candidates, acct)
		}
	}
	return members, candidates, nil
}

// EnsureGroups makes OPF's groups if they're missing.
func (a *Admin) EnsureGroups(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	_, exists, err := groupsOf(a.Group)
	if err != nil {
		return err
	}
	for _, g := range []string{"_opfadmin", "_opfoperator", "_opfview"} {
		if !exists[g] {
			if err := a.W.EnsureGroup(ctx, g); err != nil {
				return fmt.Errorf("making group %s: %w", g, err)
			}
		}
	}
	return nil
}

func (a *Admin) find(name string) (*pwEntry, []string, error) {
	users, err := readPasswd(a.Passwd)
	if err != nil {
		return nil, nil, err
	}
	groups, _, err := groupsOf(a.Group)
	if err != nil {
		return nil, nil, err
	}
	for _, u := range users {
		if u.name == name {
			return &u, groups[name], nil
		}
	}
	return nil, nil, ErrNoAccount
}

// admins counts who'd be an admin, not counting except.
func (a *Admin) admins(except string) (int, error) {
	members, _, err := a.List()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, m := range members {
		if m.Role == "admin" && !m.Locked && !m.Expired && m.Name != except {
			n++
		}
	}
	return n, nil
}

// Create makes an account, OPF's, with a role.
func (a *Admin) Create(ctx context.Context, n NewAccount) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	role, ok := roleOf(n.Role)
	switch {
	case !newNameRE.MatchString(n.Name):
		return ErrBadName
	case !ok || role == RoleNone:
		return ErrBadRole
	}
	if err := checkFullName(n.FullName); err != nil {
		return err
	}
	if err := checkPassword(n.Password); err != nil {
		return err
	}
	if _, _, err := a.find(n.Name); err == nil {
		return ErrExists
	} else if !errors.Is(err, ErrNoAccount) {
		return err
	}
	hash, err := a.W.Hash(ctx, n.Password)
	if err != nil {
		return err
	}
	shell := "/sbin/nologin"
	if n.Shell {
		shell = "/bin/ksh"
	}
	if err := a.W.AddUser(ctx, n.Name, n.FullName, shell, hash, []string{groupFor(role)}); err != nil {
		return err
	}
	return a.setCreated(n.Name, true)
}

// SetRole gives an account a role, or with "" takes it away, changing
// only its membership of OPF's groups. by is who's asking.
func (a *Admin) SetRole(ctx context.Context, name, role, by string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	r, ok := roleOf(role)
	if !ok {
		return ErrBadRole
	}
	u, groups, err := a.find(name)
	if err != nil {
		return err
	}
	if !eligible(*u) {
		return ErrSystem
	}
	if name == by && r != RoleAdmin {
		return ErrSelf
	}
	if r != RoleAdmin {
		if n, err := a.admins(name); err != nil {
			return err
		} else if n == 0 {
			return ErrLastAdmin
		}
	}
	keep := slices.DeleteFunc(slices.Clone(groups), func(g string) bool { _, ours := Groups[g]; return ours })
	if r != RoleNone {
		keep = append(keep, groupFor(r))
	}
	return a.W.SetGroups(ctx, name, keep)
}

// SetPassword sets an account's password.
func (a *Admin) SetPassword(ctx context.Context, name, password string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := checkPassword(password); err != nil {
		return err
	}
	u, _, err := a.find(name)
	if err != nil {
		return err
	}
	if !eligible(*u) {
		return ErrSystem
	}
	hash, err := a.W.Hash(ctx, password)
	if err != nil {
		return err
	}
	return a.W.SetHash(ctx, name, hash)
}

// Lock locks or unlocks an account.
func (a *Admin) Lock(ctx context.Context, name string, locked bool, by string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	u, _, err := a.find(name)
	if err != nil {
		return err
	}
	if !eligible(*u) {
		return ErrSystem
	}
	if locked {
		if name == by {
			return ErrSelf
		}
		if n, err := a.admins(name); err != nil {
			return err
		} else if n == 0 {
			return ErrLastAdmin
		}
	}
	return a.W.Lock(ctx, name, locked)
}

// Remove removes an account OPF created; one it didn't only loses its
// role (ErrNotCreated says so, after doing that).
func (a *Admin) Remove(ctx context.Context, name, by string) error {
	a.mu.Lock()
	u, groups, err := a.find(name)
	if err != nil {
		a.mu.Unlock()
		return err
	}
	if !eligible(*u) {
		a.mu.Unlock()
		return ErrSystem
	}
	if name == by {
		a.mu.Unlock()
		return ErrSelf
	}
	if n, err := a.admins(name); err != nil {
		a.mu.Unlock()
		return err
	} else if n == 0 {
		a.mu.Unlock()
		return ErrLastAdmin
	}
	if !a.created()[name] {
		keep := slices.DeleteFunc(slices.Clone(groups), func(g string) bool { _, ours := Groups[g]; return ours })
		err := a.W.SetGroups(ctx, name, keep)
		a.mu.Unlock()
		if err != nil {
			return err
		}
		return ErrNotCreated
	}
	defer a.mu.Unlock()
	if err := a.W.Remove(ctx, name); err != nil {
		return err
	}
	return a.setCreated(name, false)
}

// System changes accounts with OpenBSD's commands. Passwords go to
// encrypt(1) on stdin; only their hash is ever on a command line.
type System struct {
	Runner run.Runner // changes: run.Dry logs them
	Feeder run.Feeder // encrypt, which changes nothing
}

func (s System) do(ctx context.Context, argv ...string) error {
	out, err := s.Runner.Run(ctx, argv...)
	if err != nil {
		return fmt.Errorf("%s: %w: %s", argv[0], err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (s System) EnsureGroup(ctx context.Context, name string) error {
	return s.do(ctx, "groupadd", name)
}

func (s System) AddUser(ctx context.Context, name, fullName, shell, hash string, groups []string) error {
	argv := []string{"useradd", "-m", "-c", fullName, "-s", shell, "-L", "default", "-p", hash}
	if len(groups) > 0 {
		argv = append(argv, "-G", strings.Join(groups, ","))
	}
	return s.do(ctx, append(argv, name)...)
}

func (s System) SetGroups(ctx context.Context, name string, groups []string) error {
	return s.do(ctx, "usermod", "-S", strings.Join(groups, ","), name)
}

func (s System) SetHash(ctx context.Context, name, hash string) error {
	return s.do(ctx, "usermod", "-p", hash, name)
}

func (s System) Lock(ctx context.Context, name string, locked bool) error {
	if locked {
		return s.do(ctx, "usermod", "-Z", name)
	}
	return s.do(ctx, "usermod", "-U", name)
}

func (s System) Remove(ctx context.Context, name string) error {
	return s.do(ctx, "userdel", "-r", name)
}

func (s System) Hash(ctx context.Context, password string) (string, error) {
	out, err := s.Feeder.RunInput(ctx, []byte(password+"\n"), []string{}, "encrypt")
	if err != nil {
		return "", fmt.Errorf("encrypt: %w", err)
	}
	h := strings.TrimSpace(string(out))
	if !strings.HasPrefix(h, "$2") || strings.ContainsAny(h, ": \n") {
		return "", errors.New("encrypt gave something that isn't a hash")
	}
	return h, nil
}

// Files changes the account files directly, for the mock server and
// tests. Its hashes are "mock$" and a SHA-256, which FileChecker checks
// and nothing real would take.
type Files struct {
	Passwd, Group string
	mu            sync.Mutex
}

// MockHash is Files' hash of a password.
func MockHash(password string) string {
	s := sha256.Sum256([]byte(password))
	return "mock$" + hex.EncodeToString(s[:])
}

func (f *Files) edit(path string, fn func(lines []string) ([]string, error)) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) == 1 && lines[0] == "" {
		lines = nil
	}
	lines, err = fn(lines)
	if err != nil {
		return err
	}
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0600)
}

func (f *Files) EnsureGroup(_ context.Context, name string) error {
	return f.edit(f.Group, func(l []string) ([]string, error) {
		return append(l, fmt.Sprintf("%s:*:%d:", name, 900+len(l))), nil
	})
}

func (f *Files) AddUser(ctx context.Context, name, fullName, shell, hash string, groups []string) error {
	err := f.edit(f.Passwd, func(l []string) ([]string, error) {
		uid := 1000 + len(l)
		return append(l, strings.Join([]string{name, hash, strconv.Itoa(uid), strconv.Itoa(uid), "default", "0", "0", fullName, "/home/" + name, shell}, ":")), nil
	})
	if err != nil {
		return err
	}
	return f.SetGroups(ctx, name, groups)
}

func (f *Files) SetGroups(_ context.Context, name string, groups []string) error {
	return f.edit(f.Group, func(l []string) ([]string, error) {
		for i, line := range l {
			fs := strings.Split(line, ":")
			if len(fs) != 4 {
				continue
			}
			members := slices.DeleteFunc(strings.Split(fs[3], ","), func(m string) bool { return m == "" || m == name })
			if slices.Contains(groups, fs[0]) {
				members = append(members, name)
			}
			fs[3] = strings.Join(members, ",")
			l[i] = strings.Join(fs, ":")
		}
		return l, nil
	})
}

func (f *Files) setField(name string, fn func(fs []string)) error {
	return f.edit(f.Passwd, func(l []string) ([]string, error) {
		for i, line := range l {
			fs := strings.Split(line, ":")
			if len(fs) == 10 && fs[0] == name {
				fn(fs)
				l[i] = strings.Join(fs, ":")
				return l, nil
			}
		}
		return nil, ErrNoAccount
	})
}

func (f *Files) SetHash(_ context.Context, name, hash string) error {
	return f.setField(name, func(fs []string) { fs[1] = hash })
}

func (f *Files) Lock(_ context.Context, name string, locked bool) error {
	return f.setField(name, func(fs []string) {
		fs[1] = strings.TrimPrefix(fs[1], "*")
		fs[9] = strings.TrimPrefix(fs[9], "-")
		if locked {
			fs[1], fs[9] = "*"+fs[1], "-"+fs[9]
		}
	})
}

func (f *Files) Remove(ctx context.Context, name string) error {
	if err := f.SetGroups(ctx, name, nil); err != nil {
		return err
	}
	return f.edit(f.Passwd, func(l []string) ([]string, error) {
		return slices.DeleteFunc(l, func(line string) bool { return strings.HasPrefix(line, name+":") }), nil
	})
}

func (f *Files) Hash(_ context.Context, password string) (string, error) {
	return MockHash(password), nil
}

// FileChecker checks passwords against Files' hashes.
type FileChecker struct{ Passwd string }

func (c FileChecker) Check(_ context.Context, user, password string) (bool, error) {
	users, err := readPasswd(c.Passwd)
	if err != nil {
		return false, err
	}
	for _, u := range users {
		if u.name == user {
			return u.hash == MockHash(password), nil
		}
	}
	return false, nil
}
