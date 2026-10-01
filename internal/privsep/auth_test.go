package privsep

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/dantecatalfamo/OPF/internal/appliance"
)

// Methods anyone may call: signing in, the child noticing the parent
// go, and the child's certificate, once.
var open = []string{"Login", "Wait", "TLS"}

// Every method but those refuses a call without a session, and has a
// role, so a method added later can't be called by anyone who isn't
// signed in.
func TestEveryMethodNeedsASession(t *testing.T) {
	c := newConn(t, newAPI(t))
	typ := reflect.TypeOf(&Service{})
	for i := range typ.NumMethod() {
		m := typ.Method(i)
		if slices.Contains(open, m.Name) || m.Type.NumIn() != 3 {
			continue
		}
		if _, ok := methodRoles[m.Name]; !ok {
			t.Errorf("%s has no role", m.Name)
		}
		arg := reflect.New(m.Type.In(1)).Elem()
		if !strings.HasPrefix(arg.Type().Name(), "Call[") {
			t.Errorf("%s takes %s, not a Call", m.Name, arg.Type())
			continue
		}
		for _, tok := range []string{"", "not-a-token"} {
			arg.FieldByName("Token").SetString(tok)
			reply := reflect.New(m.Type.In(2).Elem())
			if err := c.rpc.Call("OPF."+m.Name, arg.Interface(), reply.Interface()); err != nil {
				t.Errorf("%s: %v", m.Name, err)
				continue
			}
			res := reply.Elem().FieldByName("Result").Interface().(Result)
			if res.Err == nil || res.Err.Code != appliance.CodeUnauthorized {
				t.Errorf("%s with token %q: %+v", m.Name, tok, res.Err)
			}
		}
	}
	for name := range methodRoles {
		if _, ok := typ.MethodByName(name); !ok {
			t.Errorf("a role for %s, which isn't a method", name)
		}
	}
}

func TestRoles(t *testing.T) {
	api := newAPI(t)
	conn := newConn(t, api)
	admin, op, viewer := signIn(t, conn, "admin"), signIn(t, conn, "op"), signIn(t, conn, "viewer")

	// Root isn't in OPF's groups: no session, and the same answer as a
	// wrong password.
	if _, _, err := conn.Login("root", "root-pass", "192.0.2.2"); code(err) != appliance.CodeUnauthorized {
		t.Errorf("root signed in: %v", err)
	}
	if _, _, err := conn.Login("admin", "wrong", "192.0.2.3"); code(err) != appliance.CodeUnauthorized {
		t.Errorf("wrong password: %v", err)
	}
	// Straight after a failure, even the right one waits.
	if _, _, err := conn.Login("admin", "admin-pass", "192.0.2.3"); code(err) != appliance.CodeRateLimited {
		t.Errorf("no backoff: %v", err)
	}

	live, err := viewer.Live()
	if err != nil {
		t.Fatal(err)
	}
	m := live.Model
	m.Firewall.Rules[0].Description += " (edited)"
	req := appliance.StageRequest{Base: live.Version, Model: m}
	for _, c := range []*Client{viewer, op} {
		if _, err := c.Stage(req); code(err) != appliance.CodeForbidden {
			t.Errorf("stage by a non-admin: %v", err)
		}
	}
	staged, err := admin.Stage(req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := op.Commit(appliance.CommitRequest{Staged: staged.Version}); code(err) != appliance.CodeForbidden {
		t.Errorf("commit by an operator: %v", err)
	}
	commit, err := admin.Commit(appliance.CommitRequest{Staged: staged.Version, Author: "someone-else"})
	if err != nil || commit.Author != "admin" {
		t.Fatalf("author: %+v %v", commit, err)
	}
	if commit.Status != appliance.StatusPending {
		t.Fatalf("status %s", commit.Status)
	}
	if _, err := viewer.Confirm(commit.ID); code(err) != appliance.CodeForbidden {
		t.Errorf("confirm by a viewer: %v", err)
	}
	if _, err := op.Confirm(commit.ID); err != nil {
		t.Errorf("confirm by an operator: %v", err)
	}
	d, _ := viewer.GetCommit(commit.ID)
	if !strings.Contains(d.Log, "Confirmed by op.") {
		t.Errorf("log doesn't say who confirmed:\n%s", d.Log)
	}

	// Looking at the cache is anyone's; forgetting it is an operator's.
	if _, err := viewer.DNSTool(appliance.DNSToolRequest{Tool: "flush_bogus"}); code(err) != appliance.CodeForbidden {
		t.Errorf("flush by a viewer: %v", err)
	}

	// Signed out, the token's done.
	if err := viewer.Logout(); err != nil {
		t.Fatal(err)
	}
	if _, err := viewer.Live(); code(err) != appliance.CodeUnauthorized {
		t.Errorf("after signing out: %v", err)
	}
	// An admin sees everyone's sessions; others, their own.
	if l, _ := admin.Sessions(); len(l) != 2 {
		t.Errorf("admin sees %d sessions", len(l))
	}
	if l, _ := op.Sessions(); len(l) != 1 || l[0].User != "op" {
		t.Errorf("operator sees %+v", l)
	}
}

func TestTLSGivenOnce(t *testing.T) {
	c := newConn(t, newAPI(t))
	p, err := c.TLS()
	if err != nil || string(p.Key) != "key" {
		t.Fatalf("%+v %v", p, err)
	}
	if p, err := c.TLS(); err == nil || p != nil {
		t.Errorf("given twice: %+v", p)
	}
}
