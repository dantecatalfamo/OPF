package appliance

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dantecatalfamo/OPF/internal/pf"
)

const testKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINQ9WEF+N8iMv6e+NjdG7K1KLPDKQtTuFwr+0w8Y435m test@example"

// ps -axww -o pid,lstart,command with a session, from the test VM.
const authpfPs = `  PID STARTED                      COMMAND
    1 Wed Oct  7 14:02:11 2026     /sbin/init
34725 Thu Oct  8 01:02:42 2026     -authpf: alice@100.64.1.2 (authpf)
34730 Thu Oct  8 01:02:50 2026     /bin/ksh -c echo -authpf: mallory@1.2.3.4
`

func TestParseAuthpfPs(t *testing.T) {
	s := parseAuthpfPs(authpfPs, time.UTC)
	if len(s) != 1 || s[0].User != "alice" || s[0].Address != "100.64.1.2" || s[0].PID != 34725 || !s[0].Since.Equal(time.Date(2026, 10, 8, 1, 2, 42, 0, time.UTC)) {
		t.Errorf("%+v", s)
	}
}

// authpfRunner answers ps and pf's anchors with alice's session and
// records the rest.
type authpfRunner struct {
	mu   sync.Mutex
	cmds []string
}

func (r *authpfRunner) Run(_ context.Context, argv ...string) ([]byte, error) {
	cmd := strings.Join(argv, " ")
	switch cmd {
	case "ps -axww -o pid,lstart,command":
		return []byte(authpfPs), nil
	case "pfctl -a authpf -s Anchors":
		return []byte("  authpf/alice(34725)\n"), nil
	}
	r.mu.Lock()
	r.cmds = append(r.cmds, cmd)
	r.mu.Unlock()
	return nil, nil
}

func TestAuthpfAccounts(t *testing.T) {
	e := newEnv(t, time.Minute)
	r := &authpfRunner{}
	e.m.Runner, e.m.Actions = r, r
	passwd := "root:*:0:0:Charlie &:/root:/bin/ksh\n" +
		"carol:*:1001:1001:OPF sign-in:/var/empty:/usr/sbin/authpf\n" + // OPF's, no longer wanted
		"dave:*:1002:1002:Dave:/home/dave:/bin/ksh\n" + // someone else's, whose login a user wants
		"erin:*:1003:1003:OPF sign-in - old note:/var/empty:/usr/sbin/authpf\n" + // OPF's, wanted, described anew
		"frank:*:1004:1004:Frank:/var/empty:/usr/sbin/authpf\n" // an authpf account OPF didn't make
	if err := os.MkdirAll(filepath.Join(e.root, "etc"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.root, "etc/passwd"), []byte(passwd), 0644); err != nil {
		t.Fatal(err)
	}
	m := sample(t)
	m.Firewall.Authpf = &pf.Authpf{Enabled: true, SignIn: []string{"lan"}, Users: []pf.AuthpfUser{
		{ID: "a", Name: "alice", Description: "Contractor: site, b", Keys: []string{testKey}},
		{ID: "d", Name: "dave", Keys: []string{testKey}},
		{ID: "e", Name: "erin", Description: "new note", Keys: []string{testKey}},
	}}
	e.m.syncAuthpfAccounts(m)
	want := []string{
		"useradd -c OPF sign-in - Contractor  site  b -d /var/empty -s /usr/sbin/authpf -G authpf -L default alice",
		"usermod -c OPF sign-in - new note erin",
		"userdel carol",
	}
	if got := strings.Join(r.cmds, "\n"); got != strings.Join(want, "\n") {
		t.Errorf("ran\n%s\nwant\n%s", got, strings.Join(want, "\n"))
	}
	ev, _ := e.m.Events(EventsRequest{Kinds: []string{EventAuthpf}})
	warned := 0
	for _, x := range ev.Events {
		if x.Warning && strings.Contains(x.Message, "dave") {
			warned++
		}
	}
	if warned != 1 {
		t.Errorf("events %+v", ev.Events)
	}
	// Again: dave's taken login isn't reported twice.
	r.cmds = nil
	e.m.syncAuthpfAccounts(m)
	ev, _ = e.m.Events(EventsRequest{Kinds: []string{EventAuthpf}})
	n := 0
	for _, x := range ev.Events {
		if x.Warning {
			n++
		}
	}
	if n != 1 {
		t.Errorf("dave reported %d times", n)
	}
	// Off: every account of OPF's goes, never anyone else's.
	r.cmds = nil
	m.Firewall.Authpf.Enabled = false
	e.m.syncAuthpfAccounts(m)
	for _, c := range r.cmds {
		if strings.Contains(c, "dave") || strings.Contains(c, "frank") || strings.Contains(c, "root") || strings.Contains(c, "-r") {
			t.Errorf("ran %q", c)
		}
	}
}

func TestAuthpfEnd(t *testing.T) {
	e := newEnv(t, time.Minute)
	r := &authpfRunner{}
	e.m.Runner, e.m.Actions = r, r
	got, err := e.m.AuthpfSessions()
	if err != nil || len(got.Sessions) != 1 || !got.Sessions[0].Rules {
		t.Fatalf("%+v %v", got, err)
	}
	// Only a signed-in session's process: not mallory's ksh, not init.
	for _, pid := range []int{34730, 1, 99999} {
		if err := e.m.AuthpfEnd(AuthpfEndRequest{PID: pid}); code(err) != CodeNotFound {
			t.Errorf("pid %d: %v", pid, err)
		}
	}
	if err := e.m.AuthpfEnd(AuthpfEndRequest{PID: 34725, By: "admin"}); err != nil {
		t.Fatal(err)
	}
	if strings.Join(r.cmds, "\n") != "kill -TERM 34725" {
		t.Errorf("ran %q", r.cmds)
	}
	ev, _ := e.m.Events(EventsRequest{Kinds: []string{EventAuthpf}})
	if len(ev.Events) != 1 || ev.Events[0].Message != "admin ended alice's session from 100.64.1.2" {
		t.Errorf("events %+v", ev.Events)
	}
}
