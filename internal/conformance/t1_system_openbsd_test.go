package conformance

// ######################################################################
// #                                                                    #
// #  WARNING: THE TESTS IN THE *_openbsd_test.go FILES DESTROY THE     #
// #  SYSTEM THEY RUN ON.                                               #
// #                                                                    #
// #  They take total control of the machine: they rewrite pf, network  #
// #  interfaces, routes, services, users, groups and files under /etc  #
// #  and /var, and may cut the machine off the network. Each one calls #
// #  owns(t) first, which skips it unless the environment has          #
// #  OPF_CONFORMANCE_DISPOSABLE=I-WILL-LOSE-THIS-SYSTEM, and fails it   #
// #  unless the machine has /etc/opf-conformance-disposable, which     #
// #  only scripts/conformance/vm.sh puts on the disposable guest it    #
// #  makes. Never run them anywhere else.                              #
// #                                                                    #
// ######################################################################

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/dantecatalfamo/OPF/internal/pf"
)

const (
	disposableEnv   = "OPF_CONFORMANCE_DISPOSABLE"
	disposableValue = "I-WILL-LOSE-THIS-SYSTEM"
	markerPath      = "/etc/opf-conformance-disposable"
)

const warning = `
######################################################################
#  OPF's conformance suite is taking over this machine. It rewrites  #
#  pf, network interfaces, routes, services, users, groups and files #
#  under /etc and /var, and may cut the machine off the network.     #
######################################################################
`

var gate struct {
	once sync.Once
	err  error
}

// owns lets a test change the system only on a machine made for the
// suite: it skips without OPF_CONFORMANCE_DISPOSABLE, and fails without
// the marker file or root.
func owns(t *testing.T) {
	t.Helper()
	if os.Getenv(disposableEnv) != disposableValue {
		t.Skipf("this test takes over the machine it runs on; it runs only on a disposable instance made by scripts/conformance/vm.sh, with %s=%s", disposableEnv, disposableValue)
	}
	gate.once.Do(func() {
		if _, err := os.Stat(markerPath); err != nil {
			gate.err = fmt.Errorf("%s is set, but this machine has no %s: refusing to touch a machine that wasn't made for the suite", disposableEnv, markerPath)
			return
		}
		if os.Geteuid() != 0 {
			gate.err = errors.New("the suite runs as root")
			return
		}
		fmt.Fprint(os.Stderr, warning)
	})
	if gate.err != nil {
		t.Fatal(gate.err)
	}
}

// outDir is where the suite saves what it captured.
func outDir() string {
	if d := os.Getenv("OPF_CONFORMANCE_OUT"); d != "" {
		return d
	}
	return "out"
}

// save writes a capture: what the release printed or has, for the
// ordinary suite to check on any machine (testdata/openbsd-<release>).
func save(t *testing.T, name, content string) {
	t.Helper()
	dir := filepath.Join(outDir(), "captures")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

// execCommand is a command with rc.d's PATH.
func execCommand(argv ...string) *exec.Cmd {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = append(os.Environ(), "PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin")
	return cmd
}

// run runs a command and returns its combined output and exit status
// (-1 when it couldn't start).
func run(argv ...string) (string, int) {
	out, err := execCommand(argv...).CombinedOutput()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return string(out), 0
	case errors.As(err, &ee):
		return string(out), ee.ExitCode()
	default:
		return string(out) + err.Error(), -1
	}
}

// must runs a command that has to succeed.
func must(t *testing.T, argv ...string) string {
	t.Helper()
	out, code := run(argv...)
	if code != 0 {
		t.Fatalf("%s: exit %d:\n%s", strings.Join(argv, " "), code, out)
	}
	return out
}

// checkOutput checks a command's output against its Format and saves it
// as the Format's fixture.
func checkOutput(t *testing.T, key, out string) {
	t.Helper()
	f, ok := Formats[key]
	if !ok {
		t.Errorf("%s: no Format declares this output (formats_*.go)", key)
		save(t, fixtureName(key), out)
		return
	}
	save(t, f.Fixture, out)
	for _, p := range f.Check(out) {
		t.Errorf("%s: %s", key, p)
	}
}

func fixtureName(key string) string {
	return strings.NewReplacer(" ", "_", "/", "", "*", "x").Replace(key) + ".txt"
}

var release = sync.OnceValue(func() string {
	out, _ := run("sysctl", "-n", "kern.osrelease")
	return strings.TrimSpace(out)
})

// rcPath is the PATH rc.d gives daemons (rc.subr), so the one OPF's
// commands are looked up on.
var rcPath = []string{"/sbin", "/bin", "/usr/sbin", "/usr/bin"}

// ScriptPrograms are the programs OPF's shell scripts run
// (config.HostnameApply, UnboundCheck, RcReconcile and the Apply
// one-liners in config's registry).
var ScriptPrograms = []string{"sh", "hostname", "cat", "ifconfig", "head", "grep", "sleep", "route", "sed", "tail",
	"sysctl", "pkill", "mktemp", "cmp", "rm", "awk", "rcctl", "unbound-checkconf"}

// sets lists the files in each of the release's install sets, read from
// the sets disk vm.sh attaches (sd1).
var sets = sync.OnceValues(func() (map[string]string, error) {
	const mnt = "/mnt/conformance-sets"
	if err := os.MkdirAll(mnt, 0755); err != nil {
		return nil, err
	}
	if out, code := run("mount", "-r", "/dev/sd1a", mnt); code != 0 && !strings.Contains(out, "busy") {
		return nil, fmt.Errorf("mounting the sets disk: %s", out)
	}
	rr := strings.ReplaceAll(release(), ".", "")
	set := map[string]string{}
	for _, s := range []string{"base", "comp", "man"} {
		p := filepath.Join("/mnt/conformance-sets", release(), "amd64", s+rr+".tgz")
		out, code := run("tar", "-tzf", p)
		if code != 0 {
			return nil, fmt.Errorf("listing %s: %s", p, out)
		}
		for _, l := range strings.Split(out, "\n") {
			if l = strings.TrimPrefix(strings.TrimSpace(l), "."); l != "" {
				set[l] = s
			}
		}
	}
	return set, nil
})

// TestBase checks that every program OPF runs is in the base set (not
// comp, which a firewall may leave out, nor a package) on rc.d's PATH,
// and that the files, accounts, login classes and interface kinds OPF
// relies on are there.
func TestBase(t *testing.T) {
	owns(t)
	set, err := sets()
	if err != nil {
		t.Fatal(err)
	}
	progs := map[string]bool{}
	for _, c := range Commands {
		progs[c.Program()] = true
	}
	for _, tl := range Tools {
		progs[tl.Program] = true
	}
	for _, p := range ScriptPrograms {
		progs[p] = true
	}
	for _, p := range slices.Sorted(maps.Keys(progs)) {
		var found string
		for _, d := range rcPath {
			if fi, err := os.Stat(filepath.Join(d, p)); err == nil && fi.Mode()&0111 != 0 {
				found = filepath.Join(d, p)
				break
			}
		}
		switch {
		case found == "" && isBuiltin(p):
		case found == "":
			t.Errorf("%s isn't on rc.d's PATH (%s)", p, strings.Join(rcPath, ":"))
		case set[found] == "":
			t.Errorf("%s isn't in any install set", found)
		case set[found] != "base":
			t.Errorf("%s is in the %s set, which a firewall may not have; OPF may only use base", found, set[found])
		}
	}
	var base []string
	for f, s := range set {
		if d := filepath.Dir(f); s == "base" && slices.Contains(rcPath, d) {
			base = append(base, filepath.Base(f))
		}
	}
	sort.Strings(base)
	save(t, "programs.txt", strings.Join(slices.Compact(base), "\n")+"\n")

	for _, p := range Paths {
		fi, err := os.Stat(p.Path)
		switch {
		case err != nil:
			t.Errorf("%s (%s): %v", p.Path, p.Why, err)
		case p.Kind == "dir" && !fi.IsDir(), p.Kind != "dir" && !fi.Mode().IsRegular():
			t.Errorf("%s (%s) isn't a %s", p.Path, p.Why, p.Kind)
		case p.Kind == "exec" && fi.Mode()&0111 == 0:
			t.Errorf("%s (%s) isn't executable", p.Path, p.Why)
		}
	}

	for _, a := range Accounts {
		if a.User != "" {
			u, err := user.Lookup(a.User)
			if err != nil {
				t.Errorf("no user %s (%s)", a.User, a.Why)
				continue
			}
			if a.UID >= 0 && u.Uid != strconv.Itoa(a.UID) {
				t.Errorf("%s has uid %s, not %d (%s)", a.User, u.Uid, a.UID, a.Why)
			}
		}
		if a.Group != "" {
			if _, err := user.LookupGroup(a.Group); err != nil {
				t.Errorf("no group %s (%s)", a.Group, a.Why)
			}
		}
	}

	conf, err := os.ReadFile("/etc/login.conf")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range LoginClasses {
		if !regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(c) + `[:|]`).Match(conf) {
			t.Errorf("/etc/login.conf has no class %s", c)
		}
	}

	cloners := strings.Fields(must(t, "ifconfig", "-C"))
	save(t, "ifconfig_-C.txt", strings.Join(cloners, " ")+"\n")
	for _, c := range Cloners {
		if !slices.Contains(cloners, c) {
			t.Errorf("ifconfig -C doesn't list %s", c)
		}
	}
	for _, c := range cloners {
		if pf.PhysicalDevice(c + "0") {
			t.Errorf("OPF takes %s0 for a physical port (pf.PhysicalDevice), but %s is a kind of interface ifconfig makes", c, c)
		}
	}
}

// isBuiltin says whether a shell script's command is the shell's own.
func isBuiltin(p string) bool { return p == "printf" || p == "echo" || p == "read" || p == "trap" }

// TestHeaders compiles the release's headers (the comp set, on the
// suite's guest) to check the limits OPF hard-codes.
func TestHeaders(t *testing.T) {
	owns(t)
	var b bytes.Buffer
	// The headers the others need first, then each constant's.
	headers := []string{"sys/types.h", "sys/param.h", "sys/socket.h", "net/if.h", "netinet/in.h", "stdio.h"}
	for _, c := range Constants {
		if !slices.Contains(headers, c.Header) {
			headers = append(headers, c.Header)
		}
	}
	for _, h := range headers {
		fmt.Fprintf(&b, "#include <%s>\n", h)
	}
	b.WriteString("int main(void) {\n")
	for _, c := range Constants {
		fmt.Fprintf(&b, "\tprintf(\"%s %%lld\\n\", (long long)(%s));\n", c.Name, c.Name)
	}
	b.WriteString("\treturn 0;\n}\n")
	dir := t.TempDir()
	src := filepath.Join(dir, "constants.c")
	if err := os.WriteFile(src, b.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}
	must(t, "cc", "-o", filepath.Join(dir, "constants"), src)
	out := must(t, filepath.Join(dir, "constants"))
	save(t, "constants.txt", out)
	got := map[string]int{}
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		f := strings.Fields(l)
		n, _ := strconv.Atoi(f[1])
		got[f[0]] = n
	}
	for _, c := range Constants {
		if got[c.Name] != c.Value {
			t.Errorf("%s (%s) is %d on %s, OPF assumes %d: %s", c.Name, c.Header, got[c.Name], release(), c.Value, c.Why)
		}
	}
}

// srcFile reads a file of the release's source, which vm.sh copies
// into the guest (SourceDirs).
func srcFile(t *testing.T, rel string) string {
	t.Helper()
	dir := os.Getenv("OPF_CONFORMANCE_SRC")
	if dir == "" {
		t.Fatal("no OPF_CONFORMANCE_SRC: the release's source isn't here")
	}
	data, err := os.ReadFile(filepath.Join(dir, rel))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
