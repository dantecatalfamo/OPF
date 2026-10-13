package conformance

import (
	"bufio"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/dantecatalfamo/OPF/internal/pf"
)

func TestModelsValid(t *testing.T) {
	inRepo(t)
	models := Models(VMDevices)
	names := map[string]bool{}
	for _, nm := range models {
		if names[nm.Name] {
			t.Errorf("two models are named %q", nm.Name)
		}
		names[nm.Name] = true
		for _, e := range pf.Validate(nm.Model) {
			t.Errorf("%s: %s", nm.Name, e)
		}
		if !hasSSHIn(nm.Model) {
			t.Errorf("%s doesn't let SSH in on %s from %s", nm.Name, VMDevices.WAN, ManagementNet)
		}
		for _, i := range nm.Model.Interfaces {
			if i.Device != VMDevices.WAN && i.Device != VMDevices.LAN && !slices.Contains(VMDevices.Spare, i.Device) &&
				!strings.HasPrefix(i.Device, "vlan") && !strings.HasPrefix(i.Device, "wg") && i.Aggregate == nil {
				t.Errorf("%s: %s isn't one of the machine's devices", nm.Name, i.Device)
			}
			// An aggregate (made by its file) of the machine's spare ports.
			if a := i.Aggregate; a != nil && slices.ContainsFunc(a.Ports, func(p string) bool { return !slices.Contains(VMDevices.Spare, p) }) {
				t.Errorf("%s: %s's ports %v aren't spare ports", nm.Name, i.Device, a.Ports)
			}
			if i.Device == VMDevices.WAN && (!i.Enabled || i.IPv4.Mode != pf.IPv4DHCP) {
				t.Errorf("%s: the WAN the suite comes in on must stay up by DHCP", nm.Name)
			}
		}
		// Files run for every model, so a panic shows here too.
		if len(Files(nm.Model, nil)) == 0 {
			t.Errorf("%s: no files", nm.Name)
		}
	}
	if len(models) == 0 || models[0].Name != "everything" {
		t.Error(`the first model isn't "everything"`)
	}
}

// hasSSHIn is whether a model's first rule on the suite's device lets
// SSH in from the management network, quick, before the rest.
func hasSSHIn(m *pf.Model) bool {
	wanID := ""
	for _, i := range m.Interfaces {
		if i.Device == VMDevices.WAN {
			wanID = i.ID
		}
	}
	for _, r := range m.Firewall.Rules {
		on := slices.Equal(r.Interfaces, []string{wanID}) && wanID != "" || slices.Equal(r.Groups, []string{VMDevices.WAN})
		if r.Enabled && on && r.Action == pf.ActionPass && r.Quick && r.Direction == pf.DirectionIn &&
			r.Protocol == pf.ProtoTCP && r.Port == "22" && r.Source.Type == pf.EndpointNetwork && r.Source.Value == ManagementNet {
			for _, i := range m.Interfaces {
				// The WAN protections come before every rule; bogons
				// include the management network.
				if i.Device == VMDevices.WAN && i.BlockBogons {
					return false
				}
			}
			return true
		}
	}
	return false
}

// ---------- generator coverage ----------

const coverageHelperEnv = "OPF_CONFORMANCE_COVERAGE_HELPER"

// liveFiles are machines' shared files the helper merges OPF's lines
// into: none, a stock install's, and ones OPF has written before, in
// the states the merges handle.
var liveFiles = []map[string]string{
	nil,
	{
		pf.SysctlPath: "net.inet6.ip6.forwarding=1\n",
		pf.HostsPath:  "127.0.0.1\tlocalhost\n::1\t\tlocalhost\n",
		pf.SshdPath:   "PermitRootLogin no\nAuthorizedKeysFile\t.ssh/authorized_keys\nSubsystem\tsftp\t/usr/libexec/sftp-server\n",
	},
	{
		pf.RcPath:     "pkg_scripts=postgresql\nunbound_flags=\"-v\"\nntpd_flags=\"-s\"\n" + pf.RcMarker + "\ndhcpd_flags=\"vio1\"\npflogd_flags=\"\" # set by OPF\n\n\n",
		pf.SysctlPath: "net.inet.ip.forwarding=1\nkern.maxfiles=10000\n\n# Set by OPF from its web interface; the lines above are kept as they are.\nnet.inet.ip.forwarding=0\n\n",
		pf.HostsPath:  "127.0.0.1\tlocalhost\n192.168.9.1\tfw.office.arpa fw\t# set by OPF\n\n",
		pf.SshdPath: "PermitRootLogin no\n\n# Begin OPF: sign-in access (authpf). OPF rewrites what's between these lines.\nMatch Group authpf\n" +
			"\tPermitTunnel no\nMatch all\n# End OPF\nSubsystem\tsftp\t/usr/libexec/sftp-server\n\n",
	},
	// Only OPF's block, and lines it can't set its own in.
	{
		pf.RcPath:   "unbound_flags=\"-v \\\n  -d\"\n",
		pf.SshdPath: "# Begin OPF: sign-in access (authpf). OPF rewrites what's between these lines.\nMatch Group authpf\n# End OPF\n",
	},
	{pf.RcPath: "ntpd_flags='-s\n"},
}

// TestGeneratorCoverageHelper generates every file for every model; it
// runs only under TestGeneratorCoverage, which measures it.
func TestGeneratorCoverageHelper(t *testing.T) {
	if os.Getenv(coverageHelperEnv) == "" {
		t.Skip("run by TestGeneratorCoverage")
	}
	for _, nm := range Models(VMDevices) {
		for _, live := range liveFiles {
			Files(nm.Model, live)
		}
	}
}

// genFile is a file of package pf with generator code: every function
// in it is counted but for those in except, each with why.
type genFile struct {
	except map[string]string
}

// generatorFiles are package pf's files with generator code. Every
// other file of the package must be in notGenerators, so a new one is
// classified when it's added.
var generatorFiles = map[string]genFile{
	"generate.go": {except: map[string]string{
		"ParseLabel":       "reads pfctl's labels back; writes nothing",
		"WantsTrustAnchor": "decides a step before the commit's checks (appliance); writes nothing",
	}},
	"gwgroups.go": {except: map[string]string{
		"GroupInUse":          "chooses the gateways in use as their health changes (appliance); writes nothing",
		"GatewayGroup.TierOf": "for the UI's and the event log's words (appliance)",
		"GatewayNames":        "for the event log's words (appliance)",
	}},
	"pflow.go": {except: map[string]string{
		"validator.flowExports":   "validation",
		"validator.ifaceByDevice": "validation",
		"parseHostnamePflow":      "import (reads hostname.pflowN)",
		"importFlowExports":       "import",
	}},
	"ntpd.go": {except: map[string]string{
		"validator.ntp":              "validation",
		"validator.ntpWeight":        "validation",
		"validator.ntpConstraintURL": "validation",
		"ntpTokens":                  "import (reads ntpd.conf)",
		"ntpLexWord":                 "import",
		"parseNTPStatement":          "import",
		"importNTP":                  "import",
		"NTPSettings.empty":          "import",
		"ntpSources":                 "validation and import",
		"NTPKeywords":                "ntpd's keywords, for the suite to compare with parse.y",
	}},
	"dnsrecords.go": {except: map[string]string{
		"zoneType":             "validation (dnsAlias)",
		"IsTopLevel":           "validation",
		"isRecordName":         "validation",
		"isHostTarget":         "validation",
		"recordText":           "validation",
		"validator.dnsRecords": "validation",
		"validator.dnsAlias":   "validation",
	}},
	"dhcpleased.go": {},
	"authpf.go": {except: map[string]string{
		"SshdValues":  "reads sshd_config back to tell whether someone changed OPF's lines",
		"checkSSHKey": "validation",
		"printable":   "validation messages",
	}},
	"services.go": {except: map[string]string{
		"BaseService":     "the catalogue of base services (validation and the UI)",
		"BaseServices":    "the catalogue, for the UI",
		"RcServiceValues": "reads rc.conf.local back to tell whether someone changed OPF's lines",
	}},
	"rcconf.go": {except: map[string]string{
		"shellWord":  "reads rc.conf.local back",
		"RcValues":   "reads rc.conf.local back",
		"RcOwnNames": "reads rc.conf.local back",
	}},
	"sysctlconf.go": {except: map[string]string{
		"SysctlValues": "reads sysctl.conf back",
	}},
	"hostsfile.go": {except: map[string]string{
		"HostsValues": "reads /etc/hosts back",
	}},
	"unmanaged.go": {},
	"model.go": {except: map[string]string{
		"TrafficAccounting.DeviceCap": "the traffic collector's, not a file's",
		"DNSActivity.DeviceCap":       "the DNS activity collector's",
		"DNSActivity.Retention":       "the DNS activity collector's",
		"Rule.IsForm":                 "the UI's and import's",
		"Model.hasInterface":          "import",
		"Model.deviceID":              "import",
	}},
}

// notGenerators are package pf's other files, none of whose code writes
// a file.
var notGenerators = map[string]string{
	"derive.go":       "what the UI shows while a model is edited",
	"empty.go":        "an empty model for the UI",
	"importpf.go":     "import",
	"importsys.go":    "import",
	"keywords.go":     "pf's keywords, for the suite to compare with parse.y",
	"keywords_gen.go": "pf's keywords, for validation",
	"parser.go":       "reads pf.conf",
	"pfcompare.go":    "compares pfctl's ruleset with OPF's",
	"tokenizer.go":    "reads pf.conf",
	"upgrade.go":      "upgrades older models",
	"validate.go":     "validation",
}

// allowed is generator code no valid model reaches. Each entry names the
// file, the function and a piece of the block's code, and says why.
type allowed struct {
	file, fn, code, why string
}

var allowlist = []allowed{
	{"generate.go", "gatewayAddr", `return ""`, "validation: every gateway a rule names exists, and the model is never nil"},
	{"generate.go", "endpoint", `return "any"`, "validation: every endpoint has a known type (the default case)"},
	{"generate.go", "ifaceDynamic", "return false", "self with no model; only the UI's previews generate without one"},
	{"generate.go", "portExpr", `return ""`, "validation: a port alias a rule names exists, and the model is never nil"},
	{"generate.go", "label", `return ""`, "validation: every id that becomes a label fits one"},
	{"generate.go", "comment", "return ' '", "validation: descriptions and names have no control characters"},
	{"generate.go", "insideIfaces", "return out", "the model is never nil"},
	{"generate.go", "GenerateDHCPdConf", "continue", "validation: a DHCP scope's interface exists and has a fixed address"},
	{"generate.go", "networkAddr", "return address", "validation: interface addresses are IPv4 addresses"},
	{"generate.go", "generateFormRule", `s += fmt.Sprintf(" rtable %d", *r.RTable)`, "validation refuses a rule's routing table; only Upgrade writes one, into a raw rule (TestUpgradeRoutingTables)"},
	{"gwgroups.go", "FindGateway", "return nil", "validation: every gateway a rule or group names exists"},
	{"generate.go", "ExitRTable", "return 0, false", "validation: a way out's device is wg0 to wg55"},
	{"dnsrecords.go", "firewallName", `return ""`, "validation: the host name and domain are required"},
	{"dnsrecords.go", "firewallViewLines", "return nil", "validation: the host name and domain are required"},
	{"dnsrecords.go", "firewallViews", "return nil", "validation: the host name and domain are required"},
	{"dnsrecords.go", "deref", "return 0", "validation: MX and SRV records have their numbers"},
	{"authpf.go", "ifaceByID", "return nil", "validation: every sign-in interface exists"},
	{"generate.go", "BareParents", "strings.Compare", "sorting needs two physical ports outside the model carrying VLANs; the test machine has one to spare (the other is the WAN it's reached on)"},
	{"hostsfile.go", "HostsLines", "return nil", "validation: the host name and domain are required"},
}

// TestGeneratorCoverage fails on generator code that no model reaches,
// so a new branch can't be added without a model that writes it (and so
// without the suite checking what it writes on OpenBSD).
func TestGeneratorCoverage(t *testing.T) {
	inRepo(t)
	if testing.Short() {
		t.Skip("runs go test again with coverage")
	}
	if os.Getenv(coverageHelperEnv) != "" {
		t.Skip("inside the helper")
	}
	pfDir, err := filepath.Abs(filepath.Join("..", "pf"))
	if err != nil {
		t.Fatal(err)
	}

	// Every file of package pf is classified.
	entries, err := os.ReadDir(pfDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		n := e.Name()
		if !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		_, gen := generatorFiles[n]
		_, other := notGenerators[n]
		if gen == other {
			t.Errorf("internal/pf/%s: list it in generatorFiles or notGenerators", n)
		}
	}

	profile := filepath.Join(t.TempDir(), "cover.out")
	cmd := exec.Command("go", "test", "-count=1", "-run", "^TestGeneratorCoverageHelper$",
		"-coverpkg=github.com/dantecatalfamo/OPF/internal/pf", "-coverprofile="+profile, ".")
	cmd.Env = append(os.Environ(), coverageHelperEnv+"=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go test with coverage: %v\n%s", err, out)
	}
	blocks, err := readProfile(profile)
	if err != nil {
		t.Fatal(err)
	}

	used := map[int]bool{}
	var total, covered int
	var uncovered []string
	for name, spec := range generatorFiles {
		path := filepath.Join(pfDir, name)
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		funcs, err := funcRanges(path, src)
		if err != nil {
			t.Fatal(err)
		}
		for fn := range spec.except {
			if !slices.ContainsFunc(funcs, func(f funcRange) bool { return f.name == fn }) {
				t.Errorf("%s: no function %s to leave out", name, fn)
			}
		}
		lines := strings.Split(string(src), "\n")
		for _, b := range blocks["github.com/dantecatalfamo/OPF/internal/pf/"+name] {
			k := slices.IndexFunc(funcs, func(f funcRange) bool { return f.start <= b.startLine && b.endLine <= f.end })
			if k < 0 {
				continue // package-level initialization
			}
			fn := funcs[k].name
			if _, ok := spec.except[fn]; ok {
				continue
			}
			total += b.stmts
			if b.count > 0 {
				covered += b.stmts
				continue
			}
			code := blockCode(lines, b)
			if a := slices.IndexFunc(allowlist, func(a allowed) bool {
				return a.file == name && a.fn == fn && strings.Contains(code, a.code)
			}); a >= 0 {
				used[a] = true
				continue
			}
			uncovered = append(uncovered, fmt.Sprintf("internal/pf/%s:%d (%s): %s", name, b.startLine, fn, code))
		}
	}
	sort.Strings(uncovered)
	pct := 100 * float64(covered) / float64(max(total, 1))
	t.Logf("generator statements reached: %d of %d (%.1f%%); %d allowlisted blocks", covered, total, pct, len(used))
	for _, u := range uncovered {
		t.Errorf("no model reaches %s", u)
	}
	for i, a := range allowlist {
		if !used[i] {
			t.Errorf("allowlist: %s %s %q no longer matches unreached code; take it out", a.file, a.fn, a.code)
		}
	}
}

type coverBlock struct {
	startLine, startCol, endLine, endCol int
	stmts, count                         int
}

// readProfile reads a coverage profile into blocks by file, adding up
// counts of a block listed more than once.
func readProfile(path string) (map[string][]coverBlock, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	type key struct {
		file string
		b    coverBlock
	}
	counts := map[key]int{}
	var order []key
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "mode:") || line == "" {
			continue
		}
		// file:startLine.startCol,endLine.endCol stmts count
		colon := strings.LastIndex(line, ":")
		var b coverBlock
		var count int
		if colon < 0 {
			return nil, fmt.Errorf("profile line %q", line)
		}
		if _, err := fmt.Sscanf(line[colon+1:], "%d.%d,%d.%d %d %d", &b.startLine, &b.startCol, &b.endLine, &b.endCol, &b.stmts, &count); err != nil {
			return nil, fmt.Errorf("profile line %q: %v", line, err)
		}
		k := key{line[:colon], b}
		if _, ok := counts[k]; !ok {
			order = append(order, k)
		}
		counts[k] += count
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	out := map[string][]coverBlock{}
	for _, k := range order {
		b := k.b
		b.count = counts[k]
		out[k.file] = append(out[k.file], b)
	}
	return out, nil
}

type funcRange struct {
	name       string
	start, end int
}

// funcRanges are a file's functions and methods (Type.Method), by line.
func funcRanges(path string, src []byte) ([]funcRange, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	var out []funcRange
	for _, d := range file.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok {
			continue
		}
		name := fd.Name.Name
		if fd.Recv != nil && len(fd.Recv.List) > 0 {
			t := fd.Recv.List[0].Type
			if s, ok := t.(*ast.StarExpr); ok {
				t = s.X
			}
			if id, ok := t.(*ast.Ident); ok {
				name = id.Name + "." + name
			}
		}
		out = append(out, funcRange{name, fset.Position(fd.Pos()).Line, fset.Position(fd.End()).Line})
	}
	return out, nil
}

// blockCode is a block's source, on one line.
func blockCode(lines []string, b coverBlock) string {
	var parts []string
	for l := b.startLine; l <= b.endLine && l <= len(lines); l++ {
		s := lines[l-1]
		if l == b.endLine && b.endCol-1 <= len(s) {
			s = s[:b.endCol-1]
		}
		if l == b.startLine && b.startCol-1 <= len(s) {
			s = s[b.startCol-1:]
		}
		parts = append(parts, strings.TrimSpace(s))
	}
	return strings.Join(strings.Fields(strings.Join(parts, " ")), " ")
}
