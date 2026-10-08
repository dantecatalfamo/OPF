package main

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dantecatalfamo/OPF/internal/pf"
)

// Sign-in access in the mock: useradd, usermod and userdel change the
// mock's /etc/passwd as they would the system's, and the first sign-in
// user who isn't banned is signed in (an authpf process, its anchor)
// until a kill ends the session.

const mockPasswd = "root:*:0:0:Charlie &:/root:/bin/ksh\ndaemon:*:1:1:The devil himself:/root:/sbin/nologin\n_sshd:*:27:27:sshd privsep:/var/empty:/sbin/nologin\nopfdev:*:1000:1000:OPF developer:/home/opfdev:/bin/ksh\n"

const mockSshdConfig = "#\t$OpenBSD: sshd_config,v 1.105 2024/12/03 14:12:47 dtucker Exp $\n\n#PermitRootLogin prohibit-password\nAuthorizedKeysFile\t.ssh/authorized_keys\n\n# override default of no subsystems\nSubsystem\tsftp\t/usr/libexec/sftp-server\n"

type mockAuthpf struct {
	mu    sync.Mutex
	root  string
	ended map[string]bool // users whose session was ended
	start time.Time
}

func (a *mockAuthpf) passwdPath() string { return filepath.Join(a.root, "etc/passwd") }

// account handles useradd, usermod -c and userdel; ok is false for
// anything else.
func (a *mockAuthpf) account(argv []string) (string, bool, error) {
	if len(argv) < 2 || !slices.Contains([]string{"useradd", "usermod", "userdel"}, argv[0]) {
		return "", false, nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	name := argv[len(argv)-1]
	data, _ := os.ReadFile(a.passwdPath())
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	idx := slices.IndexFunc(lines, func(l string) bool { return strings.HasPrefix(l, name+":") })
	opt := func(flag string) string {
		if i := slices.Index(argv, flag); i >= 0 && i+1 < len(argv) {
			return argv[i+1]
		}
		return ""
	}
	switch argv[0] {
	case "useradd":
		if idx >= 0 {
			return "useradd: Can't add user `" + name + "': user already exists\n", true, fmt.Errorf("exit status 1")
		}
		uid := 1000 + len(lines)
		lines = append(lines, fmt.Sprintf("%s:*:%d:%d:%s:%s:%s", name, uid, uid, opt("-c"), opt("-d"), opt("-s")))
	case "usermod":
		if idx < 0 {
			return "", true, fmt.Errorf("exit status 1")
		}
		f := strings.Split(lines[idx], ":")
		f[4] = opt("-c")
		lines[idx] = strings.Join(f, ":")
	case "userdel":
		if idx < 0 {
			return "", true, fmt.Errorf("exit status 1")
		}
		lines = slices.Delete(lines, idx, idx+1)
	}
	return "", true, os.WriteFile(a.passwdPath(), []byte(strings.Join(lines, "\n")+"\n"), 0644)
}

// signedIn is the mock's session: the first user who may sign in.
func (a *mockAuthpf) signedIn(m *pf.Model) (user string, pid int, ok bool) {
	if !pf.AuthpfOn(m) {
		return "", 0, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for i, u := range m.Firewall.Authpf.Users {
		if u.Banned == "" && !a.ended[u.Name] {
			return u.Name, 41200 + i, true
		}
	}
	return "", 0, false
}

func (a *mockAuthpf) ps(m *pf.Model, now time.Time) string {
	out := "  PID STARTED                      COMMAND\n    1 " + a.start.Add(-72*time.Hour).Format("Mon Jan _2 15:04:05 2006") + " /sbin/init\n"
	if user, pid, ok := a.signedIn(m); ok {
		out += fmt.Sprintf("%5d %s -authpf: %s@192.168.20.104 (authpf)\n", pid, now.Add(-23*time.Minute).Format("Mon Jan _2 15:04:05 2006"), user)
	}
	return out
}

func (a *mockAuthpf) anchors(m *pf.Model) string {
	if user, pid, ok := a.signedIn(m); ok {
		return fmt.Sprintf("  authpf/%s(%d)\n", user, pid)
	}
	return ""
}

// kill ends the mock's session when it's that process.
func (a *mockAuthpf) kill(m *pf.Model, pid string) (string, error) {
	user, p, ok := a.signedIn(m)
	if !ok || strconv.Itoa(p) != pid {
		return "kill: " + pid + ": No such process\n", fmt.Errorf("exit status 1")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.ended == nil {
		a.ended = map[string]bool{}
	}
	a.ended[user] = true
	return "", nil
}
