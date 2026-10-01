package auth

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type adminFixture struct {
	a     *Admin
	files *Files
	dir   string
}

func newAdmin(t *testing.T) *adminFixture {
	dir := t.TempDir()
	passwd, group := filepath.Join(dir, "master.passwd"), filepath.Join(dir, "group")
	os.WriteFile(passwd, []byte(strings.Join([]string{
		"root:$2b$r:0:0:daemon:0:0:Charlie &:/root:/bin/ksh",
		"_unbound:*:53:53::0:0:Unbound:/var/unbound:/sbin/nologin",
		"alice:" + MockHash("alice-password") + ":1000:1000::0:0:Alice:/home/alice:/bin/ksh",
		"bob:" + MockHash("bob-password!") + ":1001:1001::0:0:Bob:/home/bob:/bin/ksh",
	}, "\n")+"\n"), 0600)
	os.WriteFile(group, []byte("wheel:*:0:root,alice\nstaff:*:20:bob\n"), 0644)
	f := &Files{Passwd: passwd, Group: group}
	a := &Admin{Passwd: passwd, Group: group, Created: filepath.Join(dir, "created.json"), W: f}
	if err := a.EnsureGroups(context.Background()); err != nil {
		t.Fatal(err)
	}
	return &adminFixture{a: a, files: f, dir: dir}
}

func (f *adminFixture) roles(t *testing.T) map[string]string {
	t.Helper()
	members, _, err := f.a.List()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, m := range members {
		out[m.Name] = m.Role
	}
	return out
}

func TestAdminRoles(t *testing.T) {
	f := newAdmin(t)
	ctx := context.Background()
	_, cands, _ := f.a.List()
	names := []string{}
	for _, c := range cands {
		names = append(names, c.Name)
	}
	// Root and system accounts aren't offered.
	if strings.Join(names, ",") != "alice,bob" {
		t.Errorf("candidates %v", names)
	}
	if err := f.a.SetRole(ctx, "alice", "admin", "console"); err != nil {
		t.Fatal(err)
	}
	if err := f.a.SetRole(ctx, "bob", "operator", "alice"); err != nil {
		t.Fatal(err)
	}
	if r := f.roles(t); r["alice"] != "admin" || r["bob"] != "operator" {
		t.Fatalf("roles %v", r)
	}
	// Only OPF's groups change: alice stays in wheel, bob in staff.
	g, _ := os.ReadFile(f.files.Group)
	if !strings.Contains(string(g), "wheel:*:0:root,alice\n") || !strings.Contains(string(g), "staff:*:20:bob\n") {
		t.Errorf("other groups changed:\n%s", g)
	}
	// Moving between roles leaves one.
	f.a.SetRole(ctx, "bob", "view", "alice")
	if strings.Count(string(must(os.ReadFile(f.files.Group))), "bob") != 2 {
		t.Errorf("bob in more than staff and _opfview:\n%s", must(os.ReadFile(f.files.Group)))
	}

	// The guards.
	for _, c := range []struct {
		name string
		err  error
		do   func() error
	}{
		{"root", ErrSystem, func() error { return f.a.SetRole(ctx, "root", "admin", "alice") }},
		{"a daemon", ErrSystem, func() error { return f.a.SetRole(ctx, "_unbound", "view", "alice") }},
		{"your own admin role", ErrSelf, func() error { return f.a.SetRole(ctx, "alice", "view", "alice") }},
		{"locking yourself", ErrSelf, func() error { return f.a.Lock(ctx, "alice", true, "alice") }},
		{"removing yourself", ErrSelf, func() error { return f.a.Remove(ctx, "alice", "alice") }},
		{"the last admin, by someone else", ErrLastAdmin, func() error { return f.a.SetRole(ctx, "alice", "", "bob") }},
		{"locking the last admin", ErrLastAdmin, func() error { return f.a.Lock(ctx, "alice", true, "bob") }},
		{"an unknown role", ErrBadRole, func() error { return f.a.SetRole(ctx, "bob", "root", "alice") }},
		{"no such account", ErrNoAccount, func() error { return f.a.SetRole(ctx, "nobody", "view", "alice") }},
	} {
		if err := c.do(); !errors.Is(err, c.err) {
			t.Errorf("%s: %v, want %v", c.name, err, c.err)
		}
	}
	if r := f.roles(t); r["alice"] != "admin" {
		t.Errorf("a refused change changed something: %v", r)
	}
}

func TestAdminCreate(t *testing.T) {
	f := newAdmin(t)
	ctx := context.Background()
	f.a.SetRole(ctx, "alice", "admin", "console")
	for _, c := range []struct {
		n   NewAccount
		err error
	}{
		{NewAccount{Name: "Carol", Role: "view", Password: "long enough pw"}, ErrBadName},
		{NewAccount{Name: "_carol", Role: "view", Password: "long enough pw"}, ErrBadName},
		{NewAccount{Name: "carol;rm", Role: "view", Password: "long enough pw"}, ErrBadName},
		{NewAccount{Name: "carol", Role: "root", Password: "long enough pw"}, ErrBadRole},
		{NewAccount{Name: "carol", Role: "view", Password: "short"}, ErrWeak},
		{NewAccount{Name: "carol", Role: "view", Password: "long enough\x00pw"}, ErrWeak},
		{NewAccount{Name: "carol", FullName: "Carol:0:0", Role: "view", Password: "long enough pw"}, ErrBadFull},
		{NewAccount{Name: "carol", FullName: "Carol\nroot", Role: "view", Password: "long enough pw"}, ErrBadFull},
		{NewAccount{Name: "bob", Role: "view", Password: "long enough pw"}, ErrExists},
	} {
		if err := f.a.Create(ctx, c.n); !errors.Is(err, c.err) {
			t.Errorf("%+v: %v, want %v", c.n, err, c.err)
		}
	}
	if err := f.a.Create(ctx, NewAccount{Name: "carol", FullName: "Carol C", Role: "operator", Password: "carol's long password"}); err != nil {
		t.Fatal(err)
	}
	members, _, _ := f.a.List()
	var carol *Account
	for i := range members {
		if members[i].Name == "carol" {
			carol = &members[i]
		}
	}
	if carol == nil || carol.Role != "operator" || carol.Shell || !carol.Created || carol.FullName != "Carol C" {
		t.Fatalf("carol %+v", carol)
	}
	if ok, _ := (FileChecker{f.files.Passwd}).Check(ctx, "carol", "carol's long password"); !ok {
		t.Error("carol's password doesn't work")
	}
	f.a.SetPassword(ctx, "carol", "a new long password")
	if ok, _ := (FileChecker{f.files.Passwd}).Check(ctx, "carol", "a new long password"); !ok {
		t.Error("the new password doesn't work")
	}
	// Locked: listed as such, and the password no longer works.
	f.a.Lock(ctx, "carol", true, "alice")
	if ok, _ := (FileChecker{f.files.Passwd}).Check(ctx, "carol", "a new long password"); ok {
		t.Error("a locked account's password works")
	}
	f.a.Lock(ctx, "carol", false, "alice")
	if ok, _ := (FileChecker{f.files.Passwd}).Check(ctx, "carol", "a new long password"); !ok {
		t.Error("unlocking didn't")
	}

	// Removing an account OPF made removes it; one it didn't only loses
	// its role.
	if err := f.a.Remove(ctx, "carol", "alice"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(must(os.ReadFile(f.files.Passwd))), "carol:") {
		t.Error("carol is still there")
	}
	f.a.SetRole(ctx, "bob", "view", "alice")
	if err := f.a.Remove(ctx, "bob", "alice"); !errors.Is(err, ErrNotCreated) {
		t.Errorf("removing bob: %v", err)
	}
	if !strings.Contains(string(must(os.ReadFile(f.files.Passwd))), "bob:") || f.roles(t)["bob"] != "" {
		t.Error("bob was deleted, or kept his role")
	}
}

func must(b []byte, _ error) []byte { return b }
