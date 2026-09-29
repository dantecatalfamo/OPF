package config

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// RcReconcile run for real under sh, against a fake rcctl that records
// what it's asked and says which services are running.
func TestRcReconcile(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	dir := t.TempDir()
	calls := filepath.Join(dir, "calls")
	fake := `#!/bin/sh
echo "$*" >> "` + calls + `"
if [ "$1" = check ]; then
	case " $RUNNING " in *" $2 "*) exit 0;; esac
	exit 1
fi
exit 0
`
	if err := os.WriteFile(filepath.Join(dir, "rcctl"), []byte(fake), 0755); err != nil {
		t.Fatal(err)
	}
	run := func(conf, running string) []string {
		t.Helper()
		os.Remove(calls)
		path := filepath.Join(dir, "rc.conf.local")
		if conf == "" {
			os.Remove(path)
		} else if err := os.WriteFile(path, []byte(conf), 0644); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("sh", "-c", RcReconcile, "sh", path)
		cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "RUNNING="+running)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("reconcile: %v\n%s", err, out)
		}
		data, _ := os.ReadFile(calls)
		var acts []string
		for _, l := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			if l != "" && !strings.HasPrefix(l, "check ") {
				acts = append(acts, l)
			}
		}
		return acts
	}
	for _, c := range []struct {
		name, conf, running string
		want                []string
	}{
		{"newly enabled start", "dhcpd_flags=\"em1\"\nunbound_flags=\"\"\n", "", []string{"start dhcpd", "start unbound"}},
		{"running ones restart for new flags", "dhcpd_flags=\"em1 vlan20\"\nunbound_flags=\"\"\n", "dhcpd unbound", []string{"restart dhcpd", "restart unbound"}},
		{"disabled ones stop", "dhcpd_flags=\"NO\"\nunbound_flags=\"NO\"\n", "dhcpd unbound", []string{"stop dhcpd", "stop unbound"}},
		{"disabled and stopped: nothing", "dhcpd_flags=\"NO\"\nunbound_flags=\"NO\"\n", "", nil},
		{"file removed by a revert: all off", "", "dhcpd", []string{"stop dhcpd"}},
		{"other lines kept in the file", "pkg_scripts=\"postgresql\"\nntpd_flags=\"-s\"\ndhcpd_flags=\"em1\"\n", "", []string{"start dhcpd"}},
	} {
		if got := run(c.conf, c.running); !slices.Equal(got, c.want) {
			t.Errorf("%s: rcctl %q, want %q", c.name, got, c.want)
		}
	}

	// The file's other lines aren't run: it's read, not sourced.
	mark := filepath.Join(dir, "sourced")
	if got := run("touch \""+mark+"\"\ndhcpd_flags=\"NO\"\n", ""); got != nil {
		t.Errorf("actions %q", got)
	}
	if _, err := os.Stat(mark); err == nil {
		t.Error("the reconcile ran a line of rc.conf.local that isn't OPF's")
	}

	// A failing rcctl fails the commit.
	if err := os.WriteFile(filepath.Join(dir, "rcctl"), []byte("#!/bin/sh\n[ \"$1\" = check ] && exit 1\nexit 1\n"), 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "rc.conf.local")
	os.WriteFile(path, []byte("dhcpd_flags=\"em1\"\n"), 0644)
	cmd := exec.Command("sh", "-c", RcReconcile, "sh", path)
	cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"))
	if err := cmd.Run(); err == nil {
		t.Error("a failed start didn't fail the reconcile")
	}
}

func TestRcConfLocalIsAppliedLast(t *testing.T) {
	files := DefaultFiles()
	i := slices.IndexFunc(files, func(f File) bool { return f.Name == "rc.conf.local" })
	for _, f := range files[i+1:] {
		if f.Service != "" {
			t.Errorf("%s comes after rc.conf.local, so a service it enables would start with the old %s", f.Name, f.Name)
		}
	}
	if !files[i].ApplyWhenRemoved {
		t.Error("rc.conf.local must be reconciled when a revert removes it")
	}
}

// A commit that creates a file marked ApplyWhenRemoved still applies it
// when a revert removes it again, so services it started are stopped.
func TestRevertAppliesRemovedFile(t *testing.T) {
	root := t.TempDir()
	r := &fakeRunner{}
	files := []File{
		{Name: "pf", Path: "/etc/pf.conf", Apply: []string{"pfctl", "-f", "{}"}, Confirm: true, Mode: 0600},
		{Name: "rc", Path: "/etc/rc.conf.local", Apply: []string{"reconcile", "{}"}, ApplyWhenRemoved: true, Mode: 0644},
	}
	s, err := New(Options{Root: root, StateDir: t.TempDir(), Files: files, Runner: r, ConfirmTimeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	writeLive(t, root, "/etc/pf.conf", "pass\n")
	stage(t, s, "pf", "block\n")
	stage(t, s, "rc", "dhcpd_flags=\"em1\"\n") // didn't exist before
	if _, err := s.Commit(context.Background(), CommitInfo{}); err != nil {
		t.Fatal(err)
	}
	if err := s.Revert(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "/etc/rc.conf.local")); !os.IsNotExist(err) {
		t.Fatalf("rc.conf.local wasn't removed: %v", err)
	}
	n := 0
	for _, c := range r.commands() {
		if strings.HasPrefix(c, "reconcile ") {
			n++
		}
	}
	if n != 2 { // on commit, and again after the revert removed it
		t.Errorf("reconciled %d times, want 2: %v", n, r.commands())
	}
}
