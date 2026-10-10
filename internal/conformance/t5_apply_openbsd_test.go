package conformance

// The end to end part: OPF installed as the README says, running from
// rc.d with privilege separation, pledge and unveil, driven through its
// HTTPS API as an admin. It starts read-only on the stock system, takes
// it over (import), and then applies a model with nearly every feature
// on, so the rest of the suite reads a configured firewall with traffic
// through it.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dantecatalfamo/OPF/internal/appliance"
	"github.com/dantecatalfamo/OPF/internal/pf"
)

const (
	opfURL      = "https://127.0.0.1:8443"
	opfFlags    = "-listen 127.0.0.1:8443 -tls on"
	adminUser   = "conform"
	adminPass   = "Conformance-Test-Password-1"
	clientRdom  = "9"            // the test client's routing domain
	clientAddr  = "192.168.1.60" // on the models' LAN (lanIface)
	clientNet   = "192.168.1.0/24"
	clientRoute = "192.168.1.1"
)

// The machine's devices as the models see them (VMDevices): vio0 is
// vmd's local network (the WAN, by DHCP, where the suite is driven from);
// pair0, the LAN, is the side of a patched pair whose other end is the
// test client, in its own routing domain; vio1, a port leading nowhere,
// carries the VLANs.
var devices = VMDevices

// api is a signed-in session with OPF.
type api struct {
	c *http.Client
}

func newAPI(t *testing.T) *api {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	a := &api{c: &http.Client{Jar: jar, Timeout: 3 * time.Minute, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // OPF's own certificate
	}}}
	for i := 0; ; i++ {
		err := a.signIn()
		if err == nil {
			return a
		}
		if i == 60 {
			t.Fatalf("signing in: %v", err)
		}
		time.Sleep(2 * time.Second)
	}
}

func (a *api) signIn() error {
	return a.do("POST", "/api/session", map[string]string{"user": adminUser, "password": adminPass}, nil)
}

// apiError is an error OPF answered with.
type apiError struct {
	status int
	body   appliance.Error
}

func (e *apiError) Error() string {
	var d []string
	for _, x := range e.body.Details {
		d = append(d, fmt.Sprintf("%s: %s %s", x.Path, x.Message, x.Output))
	}
	return fmt.Sprintf("%d %s: %s %s", e.status, e.body.Code, e.body.Message, strings.Join(d, "; "))
}

func (a *api) do(method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, opfURL+path, rd)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := a.c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		// OPF answers {"error": {...}} (web.errorBody).
		e := &apiError{status: resp.StatusCode}
		var wrapped struct {
			Error *appliance.Error `json:"error"`
		}
		if json.Unmarshal(data, &wrapped) != nil || wrapped.Error == nil {
			e.body.Message = string(data)
		} else {
			e.body = *wrapped.Error
		}
		return e
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

func (a *api) get(t *testing.T, path string, out any) {
	t.Helper()
	if err := a.do("GET", path, nil, out); err != nil {
		t.Errorf("GET %s: %v", path, err)
	}
}

// apply stages a model on top of what's live, commits it and confirms
// it: the same requests the UI makes.
func (a *api) apply(t testing.TB, model *pf.Model, message string) {
	t.Helper()
	a.keys(t, model)
	var st appliance.Status
	if err := a.do("GET", "/api/status", nil, &st); err != nil {
		t.Fatal(err)
	}
	req := appliance.StageRequest{Base: st.Live, Model: model}
	var staged appliance.Staged
	err := a.do("PUT", "/api/config/staged", req, &staged)
	var ae *apiError
	if errors.As(err, &ae) && ae.body.Code == appliance.CodeModifiedOutside {
		// The stock files: replace them, as the UI asks the admin to.
		for _, d := range ae.body.Details {
			req.Overwrite = append(req.Overwrite, d.Path)
		}
		err = a.do("PUT", "/api/config/staged", req, &staged)
	}
	if err != nil {
		t.Fatalf("staging %s: %v", message, err)
	}
	a.commit(t, staged.Version, message)
}

func (a *api) commit(t testing.TB, version, message string) {
	t.Helper()
	var c appliance.Commit
	if err := a.do("POST", "/api/commits", appliance.CommitRequest{Staged: version, Message: message}, &c); err != nil {
		t.Fatalf("committing %s: %v", message, err)
	}
	if c.Status == appliance.StatusConfirmed || c.Status == appliance.StatusApplied {
		return // nothing in it waits for confirmation
	}
	if c.Status != appliance.StatusPending {
		var d appliance.CommitDetail
		a.do("GET", "/api/commits/"+c.ID, nil, &d)
		t.Fatalf("committing %s: commit %s is %s, not waiting for confirmation:\n%s", message, c.ID, c.Status, d.Log)
	}
	if err := a.do("POST", "/api/commits/"+c.ID+"/confirm", nil, &c); err != nil {
		t.Fatalf("confirming %s: %v", message, err)
	}
	if c.Status != appliance.StatusConfirmed {
		t.Fatalf("%s: commit %s is %s", message, c.ID, c.Status)
	}
}

var setup struct {
	once sync.Once
	api  *api
	err  string
	// What the take-over found on the stock system.
	report appliance.ImportReport
}

// configured brings the machine to the state the read tests expect:
// OPF installed, the everything model applied, traffic through pf.
func configured(t *testing.T) *api {
	t.Helper()
	owns(t)
	setup.once.Do(func() {
		// A failure inside the Once is recorded rather than lost.
		sub := &recorder{T: t}
		func() {
			defer func() {
				if r := recover(); r != nil && r != errStop {
					panic(r)
				}
			}()
			setup.api = bringUp(sub)
		}()
		setup.err = sub.failure
		if setup.err == "" && setup.api == nil {
			setup.err = "setup stopped without saying why"
		}
		if setup.err != "" {
			setupFailure(t)
		}
	})
	if setup.err != "" {
		t.Fatalf("setting the machine up failed: %s", setup.err)
	}
	return setup.api
}

var errStop = errors.New("stop")

// setupFailure saves what OPF and the system logged, to see why.
func setupFailure(t *testing.T) {
	var b strings.Builder
	for _, argv := range [][]string{
		{"rcctl", "check", "opf"},
		{"rcctl", "get", "opf", "flags"},
		{"sh", "-c", "ps -axww | grep '[o]pf'"},
		{"tail", "-n", "200", "/var/log/daemon"},
		{"tail", "-n", "100", "/var/log/messages"},
		{"sh", "-c", `for f in $(ls -t /var/opf/history/*/manifest.json 2>/dev/null | head -n 3); do echo "== $f"; cat "$f"; done`},
	} {
		out, code := run(argv...)
		fmt.Fprintf(&b, "$ %s (exit %d)\n%s\n", strings.Join(argv, " "), code, out)
	}
	save(t, "setup-failure.txt", b.String())
}

// recorder is a testing.T whose Fatal stops setup without ending the
// test that happened to run it first.
type recorder struct {
	*testing.T
	failure string
}

func (r *recorder) Fatalf(format string, args ...any) {
	r.failure = fmt.Sprintf(format, args...)
	r.T.Errorf(format, args...)
	panic(errStop)
}

func (r *recorder) Fatal(args ...any) {
	r.failure = fmt.Sprint(args...)
	r.T.Error(args...)
	panic(errStop)
}

func bringUp(t *recorder) *api {
	opf := os.Getenv("OPF_CONFORMANCE_OPF")
	if opf == "" {
		t.Fatal("no OPF_CONFORMANCE_OPF: the opf binary to install")
	}
	// The README's installation, read-only first: monitoring the stock
	// machine as configured by hand.
	rcd := filepath.Join(filepath.Dir(opf), "rc.d-opf")
	for _, argv := range [][]string{
		{"useradd", "-s", "/sbin/nologin", "-d", "/var/empty", "-L", "daemon", "-c", "OPF web", "_opf"},
		{"install", "-m", "555", opf, "/usr/local/sbin/opf"},
		{"install", "-m", "555", rcd, "/etc/rc.d/opf"},
		{"rcctl", "enable", "opf"},
		{"rcctl", "set", "opf", "flags", "-readonly " + opfFlags},
		{"rcctl", "start", "opf"},
	} {
		mustT(t, argv...)
	}
	// OPF made its sign-in groups when it started.
	waitFor(t, "OPF's sign-in groups", func() bool { _, code := run("grep", "-q", "^_opfadmin:", "/etc/group"); return code == 0 })
	hash := strings.TrimSpace(mustInput(t, adminPass+"\n", "encrypt"))
	mustT(t, "useradd", "-m", "-G", "_opfadmin", "-p", hash, "-s", "/sbin/nologin", adminUser)
	a := newAPI(t.T)

	var st appliance.Status
	if err := a.do("GET", "/api/status", nil, &st); err != nil || !st.ReadOnly || st.Managed {
		t.Fatalf("status before take-over: %+v, %v", st, err)
	}
	before := mustT(t, "pfctl", "-sr")

	// Take over the stock machine.
	if err := a.do("POST", "/api/import", appliance.ImportRequest{}, &setup.report); err != nil {
		t.Fatalf("import: %v", err)
	}
	if len(setup.report.Problems) > 0 || setup.report.Ruleset == nil || !setup.report.Ruleset.Same {
		t.Errorf("the import of the stock system: problems %v, ruleset %+v, error %q", setup.report.Problems, setup.report.Ruleset, setup.report.RulesetError)
	}
	var res appliance.TakeOverResult
	if err := a.do("POST", "/api/takeover", appliance.TakeOverRequest{Fingerprint: setup.report.Fingerprint}, &res); err != nil || !res.Restarting {
		t.Fatalf("take over: %+v, %v", res, err)
	}
	// OPF starts again, out of read-only mode. A session made before
	// the old process went is gone with it, so a refusal signs in again.
	a = newAPI(t.T)
	last := ""
	for i := 0; ; i++ {
		st = appliance.Status{} // a field OPF leaves out (omitempty) is false, not the last answer's
		err := a.do("GET", "/api/status", nil, &st)
		if err == nil && st.Staged != "" && !st.ReadOnly {
			break
		}
		if last = fmt.Sprintf("%+v", st); err != nil {
			last = err.Error()
			if ae, ok := err.(*apiError); ok && ae.status == http.StatusUnauthorized {
				last += "; signing in again: " + fmt.Sprint(a.signIn())
			}
		}
		if i == 120 {
			t.Fatalf("waited two minutes for the import staged; last: %s", last)
		}
		time.Sleep(time.Second)
	}
	if flags := strings.TrimSpace(mustT(t, "rcctl", "get", "opf", "flags")); strings.Contains(flags, "-readonly") {
		t.Errorf("rc.conf.local still has -readonly in opf_flags: %q", flags)
	}
	a.commit(t, st.Staged, "Take over the stock system")
	if after := mustT(t, "pfctl", "-sr"); !sameRules(before, after) {
		t.Errorf("taking over changed pf's rules:\nbefore:\n%s\nafter:\n%s", before, after)
	}

	// Everything on.
	m := modelNamed(t, "everything")
	listServer(t)
	a.apply(t, m, "Everything")
	traffic(t)
	return a
}

// keys makes the keys a model's tunnels and devices need on the
// firewall, as the UI does when one is added: the models' own are made
// up, and OPF refuses a tunnel whose private key it doesn't have.
func (a *api) keys(t testing.TB, model *pf.Model) {
	t.Helper()
	for i := range model.Interfaces {
		wg := model.Interfaces[i].WireGuard
		if wg == nil {
			continue
		}
		if _, err := os.Stat(pf.WGKeyPath(wg.PublicKey)); err != nil {
			var k struct {
				PublicKey string `json:"publicKey"`
			}
			if err := a.do("POST", "/api/wireguard/keys", struct{}{}, &k); err != nil {
				t.Fatalf("making %s's key: %v", model.Interfaces[i].Device, err)
			}
			wg.PublicKey = k.PublicKey
		}
		psk := func(id *string) {
			if *id == "" {
				return
			}
			if _, err := os.Stat(pf.WGPSKPath(*id)); err == nil {
				return
			}
			var k appliance.PresharedKey
			if err := a.do("POST", "/api/wireguard/preshared-keys", appliance.PresharedKeyRequest{}, &k); err != nil {
				t.Fatalf("making a preshared key: %v", err)
			}
			*id = k.ID
		}
		for j := range wg.Peers {
			psk(&wg.Peers[j].PresharedKey)
		}
		if wg.Exit != nil {
			psk(&wg.Exit.PresharedKey)
		}
	}
}

// sameRules compares pfctl -sr outputs without OPF's labels, and
// without the built-in rules OPF puts first when they aren't quick: pf
// takes the last rule that matches, so the stock rules after them, down
// to their own catch-all, still decide every packet.
func sameRules(before, after string) bool {
	strip := func(s string, builtins bool) string {
		var out []string
		leading := true
		for _, l := range strings.Split(s, "\n") {
			builtin := strings.Contains(l, ` label "opf:builtin:`)
			if builtins && leading && builtin && !strings.Contains(l, " quick ") {
				continue
			}
			leading = leading && builtin
			if i := strings.Index(l, ` label "opf:`); i >= 0 {
				l = l[:i]
			}
			out = append(out, l)
		}
		return strings.Join(out, "\n")
	}
	return strip(before, false) == strip(after, true)
}

func modelNamed(t *recorder, name string) *pf.Model {
	for _, m := range Models(devices) {
		if m.Name == name {
			return m.Model
		}
	}
	t.Fatalf("no model %q", name)
	return nil
}

// traffic puts a client behind pair0, in its own routing domain, and
// sends traffic through the firewall: some passed, some blocked and
// logged, DNS lookups, and a DHCP lease.
func traffic(t *recorder) {
	mustT(t, "ifconfig", "pair1", "create")
	mustT(t, "ifconfig", "pair1", "rdomain", clientRdom)
	mustT(t, "ifconfig", "pair1", "inet", clientAddr+"/24", "up")
	mustT(t, "ifconfig", "pair1", "patch", "pair0")
	run("route", "-T"+clientRdom, "-qn", "add", "default", clientRoute)
	waitFor(t, "the client reaching the firewall", func() bool {
		_, code := run("route", "-T"+clientRdom, "exec", "ping", "-c", "1", "-w", "1", clientRoute)
		return code == 0
	})
	gw := defaultGateway(t)
	for _, argv := range [][]string{
		{"ping", "-c", "5", "-i", "0.2", clientRoute}, // to the firewall
		{"ping", "-c", "5", "-i", "0.2", gw},          // through it, out the WAN with NAT
		{"nc", "-z", "-w", "1", clientRoute, "22"},    // the firewall's SSH from inside
		{"nc", "-z", "-w", "1", clientRoute, "9"},     // blocked
		{"nc", "-zu", "-w", "1", gw, "9"},             // out, and nothing there
		{"dig", "@" + clientRoute, "example.com", "+tries=1", "+time=2"},
		{"dig", "@" + clientRoute, "blocked.example", "+tries=1", "+time=2"},
		{"dig", "@" + clientRoute, "-x", clientRoute, "+tries=1", "+time=2"},
	} {
		run(append([]string{"route", "-T" + clientRdom, "exec"}, argv...)...)
	}
}

func defaultGateway(t *recorder) string {
	out := mustT(t, "route", "-n", "get", "default")
	for _, l := range strings.Split(out, "\n") {
		if f := strings.Fields(l); len(f) == 2 && f[0] == "gateway:" {
			return f[1]
		}
	}
	t.Fatalf("no default gateway in:\n%s", out)
	return ""
}

func waitFor(t *recorder, what string, ok func() bool) {
	for i := 0; i < 120; i++ {
		if ok() {
			return
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("waited two minutes for %s", what)
}

func mustT(t *recorder, argv ...string) string {
	out, code := run(argv...)
	if code != 0 {
		t.Fatalf("%s: exit %d:\n%s", strings.Join(argv, " "), code, out)
	}
	return out
}

func mustInput(t *recorder, input string, argv ...string) string {
	cmd := execCommand(argv...)
	cmd.Stdin = strings.NewReader(input)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v:\n%s", strings.Join(argv, " "), err, out)
	}
	return string(out)
}

// TestApply checks the end to end run: the take-over left the stock
// system as it was, and the everything model is live, with its services
// running and every file as OPF wrote it.
func TestApply(t *testing.T) {
	a := configured(t)
	var st appliance.Status
	a.get(t, "/api/status", &st)
	if !st.Managed || st.ReadOnly || st.Pending != nil || st.Staged != "" {
		t.Errorf("status: %+v", st)
	}
	var files struct {
		Files []appliance.ConfigFile `json:"files"`
	}
	a.get(t, "/api/files", &files)
	if len(files.Files) == 0 {
		t.Error("OPF lists no files")
	}
	for _, f := range files.Files {
		if f.Outside {
			t.Errorf("%s changed outside OPF right after it was applied", f.Path)
		}
	}
	for _, svc := range []string{"dhcpd", "unbound", "ntpd", "pflogd", "opf"} {
		if out, code := run("rcctl", "check", svc); code != 0 {
			t.Errorf("%s isn't running: %s", svc, out)
		}
	}
	if !slices.ContainsFunc(strings.Split(mustT(&recorder{T: t}, "pfctl", "-sr"), "\n"), func(l string) bool { return strings.Contains(l, `label "opf:`) }) {
		t.Error("pf has no rule of OPF's")
	}
	// The commands each commit ran, from its log ("$ argv" lines), count
	// as run: OPF ran them for real and the commit was confirmed.
	var commits []appliance.Commit
	a.get(t, "/api/commits", &commits)
	for _, c := range commits {
		var d appliance.CommitDetail
		a.get(t, "/api/commits/"+c.ID, &d)
		save(t, "commit-"+c.ID+".log", d.Log)
		for _, l := range strings.Split(d.Log, "\n") {
			cmdline, ok := strings.CutPrefix(l, "$ ")
			if !ok {
				continue
			}
			argv := strings.Fields(cmdline)
			for _, cmd := range Commands {
				if cmd.Matches(argv) || len(argv) > 1 && argv[0] == "sh" && argv[1] == "-c" && cmd.Argv[0] == "sh" && cmd.Argv[1] == "-c" {
					markRan(strings.Join(cmd.Argv, " "), t.Name())
				}
			}
		}
	}
}

// listHost serves the lists the models download.
const listHost = "lists.example.com"

// listBodies are what it serves, by path.
var listBodies = map[string]string{
	"/drop.txt": "# a list of networks\n198.51.100.0/24\n203.0.113.66 ; a host\n",
	"/ads.txt":  "# a list of names\nads.example.net\n0.0.0.0 tracker.example.net\n",
	"/old.txt":  "old.example.net\n",
}

// listServer stands in for listHost: https on 127.0.0.1:443 with a
// certificate from a CA of its own, which goes into the system's
// /etc/ssl/cert.pem, and the name in /etc/hosts. So OPF's real download
// (ftp, as its unprivileged user) runs, with no internet.
func listServer(t *recorder) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "OPF conformance CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ = x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: listHost}, DNSNames: []string{listHost},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	appendFile := func(path, text string) {
		f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if _, err := f.WriteString(text); err != nil {
			t.Fatal(err)
		}
	}
	appendFile("/etc/ssl/cert.pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})))
	// The tunnels' peers by name too: with no DNS, netstart would
	// wait on each lookup until the commit ran out of time.
	appendFile("/etc/hosts", "127.0.0.1 "+listHost+"\n192.0.2.80 warehouse.example.net\n192.0.2.81 vpn.example.net\n")
	ln, err := tls.Listen("tcp", "127.0.0.1:443", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER}, PrivateKey: key}}})
	if err != nil {
		t.Fatal(err)
	}
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := listBodies[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		io.WriteString(w, body)
	}))
}
