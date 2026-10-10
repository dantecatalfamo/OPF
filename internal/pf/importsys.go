package pf

import (
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// Importing the rest of a machine configured by hand: its interfaces
// (hostname.if), name, default gateway, time servers, DHCP server and
// resolver. Whatever an import can't model exactly is left alone: an
// interface stays out of the model, and an area (unmanaged.go) keeps its
// file and daemon, unless the admin asks for it to be managed anyway.

// ImportSources are what an import reads from the machine.
type ImportSources struct {
	// Files are the contents of the files that exist, by path: the ones
	// in ImportPaths, and every /etc/hostname.*.
	Files map[string]string
	// Egress are the devices in the egress interface group: those with
	// the default route, so the WAN.
	Egress []string
}

// ImportPaths are the files an import reads, besides /etc/hostname.*.
var ImportPaths = []string{"/etc/myname", "/etc/mygate", "/etc/pf.conf", DHCPdConfPath, UnboundConfPath, NTPdConfPath, RcPath, SysctlPath}

// ImportOptions are the admin's choices.
type ImportOptions struct {
	// Manage says, for an area, whether OPF should manage it; an area
	// not in it gets the import's suggestion (ImportArea.Suggested).
	Manage map[string]bool `json:"manage,omitempty"`
	Pf     ImportPfOptions `json:"-"`
}

// ImportArea is how an area was imported.
type ImportArea struct {
	Area string `json:"area"`
	// Running: its daemon is enabled in rc.conf.local.
	Running bool `json:"running"`
	// Exact: the model writes its file meaning what the machine's means.
	Exact bool `json:"exact"`
	// Suggested is whether the import suggests OPF manage it: when it's
	// exact, or the daemon isn't running so there's nothing to change.
	Suggested bool `json:"suggested"`
	// Managed is what the import did: the admin's choice, or the
	// suggestion.
	Managed bool `json:"managed"`
	// Summary says what it found.
	Summary string `json:"summary"`
}

// ImportResult is a machine's configuration as OPF's model, and what the
// import found on the way.
type ImportResult struct {
	Model *Model       `json:"model"`
	Notes []ImportNote `json:"notes"`
	Areas []ImportArea `json:"areas"`
}

// Import reads a machine's configuration into a model.
func Import(src ImportSources, opts ImportOptions) *ImportResult {
	m := EmptyModel()
	res := &ImportResult{Model: m}
	m.Firewall.Options = FirewallOptions{
		BlockPolicy: BlockPolicyDrop, StatePolicy: StatePolicyOptionFloating, Optimization: OptNormal,
		MaxStates: PfDefaultStates, Syncookies: SyncookiesNever, LogInterface: "none",
	}
	m.Firewall.OutboundNAT = OutboundNAT{Mode: NATModeManual, Rules: []NATRule{}}
	m.DNS = DNS{Mode: ResolverModeRecursive, Forwarders: []string{}, Overrides: []HostOverride{}, RewriteInvalidLeaseNames: true}

	res.Notes = append(res.Notes, importName(m, src)...)
	res.Notes = append(res.Notes, importInterfaces(m, src)...)
	res.Notes = append(res.Notes, importFlowExports(m, src)...)
	res.Notes = append(res.Notes, importGateway(m, src)...)

	rc := RcValues(src.Files[RcPath])
	running := func(flags string) bool { return flags != "NO" }

	// The areas.
	area := func(name string, a ImportArea, notes []ImportNote) {
		a.Area = name
		a.Suggested = a.Exact || !a.Running
		a.Managed = a.Suggested
		if v, ok := opts.Manage[name]; ok {
			a.Managed = v
		}
		if !a.Managed {
			// Nothing is lost; what was understood is kept for when the
			// area is handed over.
			m.System.Unmanaged = append(m.System.Unmanaged, name)
			notes = slices.DeleteFunc(notes, func(n ImportNote) bool { return n.Kind == NoteLost })
			for i := range notes {
				notes[i].Kind = NoteLeft
				notes[i].Message += ", for when OPF manages it"
			}
			notes = append(notes, ImportNote{File: areaFile(name), Kind: NoteLeft, Message: "left as it is: OPF doesn't write it, or start, stop or restart its daemon"})
		}
		res.Areas = append(res.Areas, a)
		res.Notes = append(res.Notes, notes...)
	}
	a, notes := importNTP(m, src)
	area(AreaNTP, a, notes)
	a, notes = importDHCP(m, src, running(rc["dhcpd_flags"]), rc["dhcpd_flags"])
	area(AreaDHCP, a, notes)
	a, notes = importUnbound(m, src, running(rc["unbound_flags"]))
	area(AreaDNS, a, notes)
	if Unmanaged(m, AreaDHCP) {
		for i := range m.DHCP {
			m.DHCP[i].Enabled = false
		}
	}
	if Unmanaged(m, AreaDNS) {
		m.DNS.Enabled = false
	}
	slices.Sort(m.System.Unmanaged)

	// pf.conf last: its rules name the interfaces and aliases.
	if pfconf, ok := src.Files["/etc/pf.conf"]; ok {
		res.Notes = append(res.Notes, importPfConf(m, pfconf, opts.Pf)...)
	} else {
		res.Notes = append(res.Notes, ImportNote{File: "/etc/pf.conf", Kind: NoteLost, Message: "there's no pf.conf: pf runs its default rules, and OPF's first commit writes its own"})
	}

	// Forwarding packets between interfaces: OPF turns it on with more
	// than one.
	if want, have := SysctlVars(m)["net.inet.ip.forwarding"], SysctlValues(src.Files[SysctlPath])["net.inet.ip.forwarding"]; want != orZero(have) {
		what := "on"
		if want == "0" {
			what = "off"
		}
		res.Notes = append(res.Notes, ImportNote{File: SysctlPath, Kind: NoteLost, Text: "net.inet.ip.forwarding=" + orZero(have),
			Message: fmt.Sprintf("OPF turns forwarding packets between interfaces %s, since the model has %d interfaces", what, enabledIfaces(m))})
	}
	if len(HostsLines(m)) > 0 {
		res.Notes = append(res.Notes, ImportNote{File: HostsPath, Kind: NoteLost, Message: "OPF adds the firewall's name, on its inside networks, for its own programs"})
	}
	sortNotes(res.Notes)
	return res
}

// PfDefaultStates is pf's limit on states when pf.conf sets none.
const PfDefaultStates = 100000

func orZero(s string) string {
	if s == "" {
		return "0"
	}
	return s
}

func enabledIfaces(m *Model) int {
	n := 0
	for _, i := range m.Interfaces {
		if i.Enabled {
			n++
		}
	}
	return n
}

func areaFile(area string) string {
	switch area {
	case AreaDHCP:
		return DHCPdConfPath
	case AreaDNS:
		return UnboundConfPath
	}
	return NTPdConfPath
}

// sortNotes orders notes by file, then line, keeping the order of those
// with neither.
func sortNotes(n []ImportNote) {
	sort.SliceStable(n, func(i, j int) bool {
		if n[i].File != n[j].File {
			return n[i].File < n[j].File
		}
		return n[i].Line < n[j].Line
	})
}

// importName reads /etc/myname: the host name, and the domain after it.
func importName(m *Model, src ImportSources) []ImportNote {
	const file = "/etc/myname"
	full := strings.TrimSpace(strings.SplitN(src.Files[file], "\n", 2)[0])
	host, domain, _ := strings.Cut(full, ".")
	var notes []ImportNote
	if dnsLabelRE.MatchString(host) {
		m.System.Hostname = host
	} else {
		m.System.Hostname = "firewall"
		notes = append(notes, ImportNote{File: file, Kind: NoteLost, Text: full, Message: "not a host name OPF can use; it's called firewall instead"})
	}
	v := &validator{m: m}
	v.domain("", domain)
	if domain != "" && len(v.errs) == 0 {
		m.System.Domain = domain
	} else {
		m.System.Domain = "home.arpa"
		notes = append(notes, ImportNote{File: file, Kind: NoteLost, Text: full, Message: "no domain OPF can use; it's home.arpa (RFC 8375's, for home networks) instead"})
	}
	if len(notes) == 0 {
		notes = append(notes, ImportNote{File: file, Kind: NoteModel, Text: full, Message: "the firewall's name and domain"})
	}
	return notes
}

// hostnameIf is what a hostname.if says, in the model's terms.
type hostnameIf struct {
	desc     string
	v4       IPv4Config
	v6       IPv6Mode
	mtu      *int
	vlan     *VLANConfig
	down     bool
	upOnly   bool // nothing but up: a port carrying VLANs
	notModel []string
}

var (
	ifDescRE  = regexp.MustCompile(`^description\s+(?:"([^"]*)"|(.+))$`)
	ifInetRE  = regexp.MustCompile(`^inet\s+(\d+\.\d+\.\d+\.\d+)(?:/(\d+)|\s+(\S+)(?:\s+(\S+))?)$`)
	ifVnetRE  = regexp.MustCompile(`^(?:vnetid\s+(\d+)\s+parent\s+([a-z]+[0-9]+)|parent\s+([a-z]+[0-9]+)\s+vnetid\s+(\d+)|vlan\s+(\d+)\s+vlandev\s+([a-z]+[0-9]+))$`)
	ifMTURE   = regexp.MustCompile(`^mtu\s+(\d+)$`)
	ifFileRE  = regexp.MustCompile(`^/etc/hostname\.([a-z]+[0-9]+)$`)
	ifWordsRE = regexp.MustCompile(`\s+`)
)

// parseHostnameIf reads a hostname.if into what the model has. Lines it
// doesn't have are listed in notModel.
func parseHostnameIf(content string) hostnameIf {
	var h hostnameIf
	h.v4.Mode, h.v6 = IPv4None, IPv6None
	upSeen, other := false, false
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if c := strings.IndexByte(line, '#'); c >= 0 && !strings.HasPrefix(line, "!") && !strings.Contains(line[:c], `"`) {
			line = strings.TrimSpace(line[:c])
		}
		if line == "" {
			continue
		}
		line = ifWordsRE.ReplaceAllString(line, " ")
		switch {
		case line == "up":
			upSeen = true
			continue
		case line == "down":
			h.down = true
		case line == "dhcp" || line == "inet autoconf":
			if h.v4.Mode != IPv4None {
				h.notModel = append(h.notModel, raw)
			}
			h.v4 = IPv4Config{Mode: IPv4DHCP}
		case line == "inet6 autoconf" || line == "rtsol":
			h.v6 = IPv6SLAAC
		case ifDescRE.MatchString(line):
			sub := ifDescRE.FindStringSubmatch(line)
			h.desc = sub[1] + sub[2]
		case ifMTURE.MatchString(line):
			n, _ := strconv.Atoi(ifMTURE.FindStringSubmatch(line)[1])
			h.mtu = &n
		case ifVnetRE.MatchString(line):
			sub := ifVnetRE.FindStringSubmatch(line)
			tag, parent := sub[1]+sub[4]+sub[5], sub[2]+sub[3]+sub[6]
			n, _ := strconv.Atoi(tag)
			h.vlan = &VLANConfig{Parent: parent, Tag: n}
		case ifInetRE.MatchString(line):
			sub := ifInetRE.FindStringSubmatch(line)
			prefix, ok := -1, true
			if sub[2] != "" {
				prefix, _ = strconv.Atoi(sub[2])
			} else {
				prefix, ok = maskPrefix(sub[3])
				if b := sub[4]; ok && b != "" && b != "NONE" {
					// A broadcast address other than the network's own.
					if p, err := netip.ParsePrefix(sub[1] + "/" + strconv.Itoa(prefix)); err != nil || b != broadcastOf(p) {
						ok = false
					}
				}
			}
			if !ok || prefix < 1 || prefix > 32 || h.v4.Mode != IPv4None {
				h.notModel = append(h.notModel, raw)
				continue
			}
			h.v4 = IPv4Config{Mode: IPv4Static, Address: sub[1], Prefix: &prefix}
		default:
			h.notModel = append(h.notModel, raw)
		}
		other = true
	}
	h.upOnly = upSeen && !other
	return h
}

// maskPrefix is a netmask's length: 255.255.255.0, or 0xffffff00.
func maskPrefix(mask string) (int, bool) {
	var bits uint32
	if hex, ok := strings.CutPrefix(mask, "0x"); ok {
		n, err := strconv.ParseUint(hex, 16, 32)
		if err != nil {
			return 0, false
		}
		bits = uint32(n)
	} else {
		a, err := netip.ParseAddr(mask)
		if err != nil || !a.Is4() {
			return 0, false
		}
		b := a.As4()
		bits = uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	}
	n := 0
	for n < 32 && bits&(1<<(31-n)) != 0 {
		n++
	}
	if bits<<n != 0 {
		return 0, false // not contiguous
	}
	return n, true
}

func broadcastOf(p netip.Prefix) string {
	a := p.Masked().Addr().As4()
	host := uint32(1)<<(32-p.Bits()) - 1
	v := (uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])) | host
	return fmt.Sprintf("%d.%d.%d.%d", v>>24, v>>16&0xff, v>>8&0xff, v&0xff)
}

// importInterfaces reads every hostname.if into the model's interfaces.
// One with a line the model doesn't have, a tunnel (its key would have
// to move into OPF's key files) and the like stay out of the model, so
// OPF leaves its file alone.
func importInterfaces(m *Model, src ImportSources) []ImportNote {
	var notes []ImportNote
	var paths []string
	for p := range src.Files {
		if ifFileRE.MatchString(p) {
			paths = append(paths, p)
		}
	}
	slices.Sort(paths)
	parsed := map[string]hostnameIf{}
	for _, p := range paths {
		parsed[ifFileRE.FindStringSubmatch(p)[1]] = parseHostnameIf(src.Files[p])
	}
	// VLANs' parents that carry nothing else are written by the
	// generator (BareParents), not modelled.
	parents := map[string]bool{}
	for _, h := range parsed {
		if h.vlan != nil {
			parents[h.vlan.Parent] = true
		}
	}
	used := map[string]bool{}
	wan := false
	for _, p := range paths {
		dev := ifFileRE.FindStringSubmatch(p)[1]
		h := parsed[dev]
		left := func(why string) {
			notes = append(notes, ImportNote{File: p, Kind: NoteLeft, Message: why})
		}
		kind := strings.TrimRight(dev, "0123456789")
		switch {
		case kind == "pflow":
			continue // a flow export (importFlowExports)
		case kind == "wg":
			left("a WireGuard tunnel: left as it is (OPF keeps a tunnel's key in a file of its own, so it can't take one over yet)")
			continue
		case !slices.Contains([]string{"vlan", "svlan"}, kind) && !isPortKind(kind):
			left(fmt.Sprintf("a %s interface, which OPF doesn't set up: left as it is", kind))
			continue
		case len(h.notModel) > 0:
			for _, l := range h.notModel {
				notes = append(notes, ImportNote{File: p, Kind: NoteLeft, Text: strings.TrimSpace(l), Message: "a setting OPF doesn't have"})
			}
			left("left as it is, with the rules that name it kept as written")
			continue
		case h.upOnly && parents[dev]:
			notes = append(notes, ImportNote{File: p, Kind: NoteModel, Text: "up", Message: "carries VLANs only"},
				ImportNote{File: p, Kind: NoteLost, Message: "OPF gives it a description: the VLANs it carries"})
			continue
		case (kind == "vlan" || kind == "svlan") != (h.vlan != nil):
			left("left as it is: a VLAN needs a tag and parent")
			continue
		}
		if h.vlan != nil {
			if ph, ok := parsed[h.vlan.Parent]; !ok || len(ph.notModel) > 0 {
				left(fmt.Sprintf("its parent %s isn't one OPF can take over, so it's left as it is", h.vlan.Parent))
				continue
			}
		}
		role := RoleOPT
		if slices.Contains(src.Egress, dev) && !wan {
			role, wan = RoleWAN, true
		}
		id := dev
		if role == RoleWAN {
			id = "wan"
		}
		for n := 2; used[id]; n++ {
			id = fmt.Sprintf("%s%d", dev, n)
		}
		used[id] = true
		name := h.desc
		if !plainNameRE.MatchString(name) {
			name = dev
			if role == RoleWAN {
				name = "WAN"
			}
		}
		i := Iface{ID: id, Name: name, Device: dev, Role: role, Enabled: !h.down, IPv4: h.v4, IPv6: h.v6, MTU: h.mtu}
		if h.vlan != nil {
			v := *h.vlan
			i.VLAN = &v
		}
		m.Interfaces = append(m.Interfaces, i)
		msg := "an interface"
		if role == RoleWAN {
			msg = "the WAN: it has the default route (it's in pf's egress group)"
		}
		notes = append(notes, ImportNote{File: p, Kind: NoteModel, Message: msg})
		if h.desc != name {
			notes = append(notes, ImportNote{File: p, Kind: NoteLost, Text: fmt.Sprintf("description %q", name), Message: "OPF gives every interface a description: its name"})
		}
	}
	// VLAN parents by the model's id.
	for i := range m.Interfaces {
		if v := m.Interfaces[i].VLAN; v != nil {
			if id := m.deviceID(v.Parent); id != "" {
				v.Parent = id
			}
		}
	}
	return notes
}

// isPortKind says whether an interface kind is a physical port: not one
// of the virtual kinds (netstartOrder's).
func isPortKind(kind string) bool {
	// umb and wwan are devices, but mobile broadband, not ports.
	return !slices.Contains(ClonedKinds, kind) && kind != "umb" && kind != "wwan"
}

// importGateway reads /etc/mygate: the default gateway, on the
// interface whose network has it.
func importGateway(m *Model, src ImportSources) []ImportNote {
	const file = "/etc/mygate"
	content, ok := src.Files[file]
	if !ok {
		return nil
	}
	var addr string
	for _, l := range strings.Split(content, "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			addr = l
			break
		}
	}
	a, err := netip.ParseAddr(addr)
	if err != nil || !a.Is4() {
		return []ImportNote{{File: file, Kind: NoteLeft, Text: addr, Message: "not an IPv4 address OPF can use: left as it is"}}
	}
	for _, i := range m.Interfaces {
		if i.IPv4.Mode != IPv4Static || i.IPv4.Prefix == nil {
			continue
		}
		p, err := netip.ParsePrefix(i.IPv4.Address + "/" + strconv.Itoa(*i.IPv4.Prefix))
		if err == nil && p.Masked().Contains(a) {
			m.Routing.Gateways = append(m.Routing.Gateways, Gateway{ID: "gw_" + i.ID, Name: "Default gateway", Iface: i.ID, Address: addr, Description: ""})
			m.Routing.DefaultGateway = "gw_" + i.ID
			return []ImportNote{{File: file, Kind: NoteModel, Text: addr, Message: "the default gateway, on " + i.Name}}
		}
	}
	return []ImportNote{{File: file, Kind: NoteLeft, Text: addr, Message: "on none of the interfaces OPF took over: left as it is"}}
}

// dhcpdStmt is a statement of dhcpd.conf: its words, and its block's
// statements when it has one.
type dhcpdStmt struct {
	Line  int
	Words []string
	Block []dhcpdStmt
	Text  string
}

// parseDHCPd reads dhcpd.conf's statements; ok is false when its braces
// don't match or a statement doesn't end.
func parseDHCPd(content string) ([]dhcpdStmt, bool) {
	var toks []struct {
		s    string
		line int
	}
	line := 1
	for i := 0; i < len(content); i++ {
		c := content[i]
		switch {
		case c == '\n':
			line++
		case c == ' ' || c == '\t' || c == '\r':
		case c == '#':
			for i < len(content) && content[i] != '\n' {
				i++
			}
			i--
		case c == '{' || c == '}' || c == ';':
			toks = append(toks, struct {
				s    string
				line int
			}{string(c), line})
		case c == '"':
			j := i + 1
			for j < len(content) && content[j] != '"' {
				j++
			}
			if j >= len(content) {
				return nil, false
			}
			toks = append(toks, struct {
				s    string
				line int
			}{content[i : j+1], line})
			i = j
		default:
			j := i
			for j < len(content) && !strings.ContainsRune(" \t\r\n{};#\"", rune(content[j])) {
				j++
			}
			toks = append(toks, struct {
				s    string
				line int
			}{content[i:j], line})
			i = j - 1
		}
	}
	pos := 0
	var block func(depth int) ([]dhcpdStmt, bool)
	block = func(depth int) ([]dhcpdStmt, bool) {
		var out []dhcpdStmt
		var cur dhcpdStmt
		for pos < len(toks) {
			t := toks[pos]
			pos++
			switch t.s {
			case ";":
				cur.Text = strings.Join(cur.Words, " ") + ";"
				out = append(out, cur)
				cur = dhcpdStmt{}
			case "{":
				inner, ok := block(depth + 1)
				if !ok {
					return nil, false
				}
				cur.Block = inner
				cur.Text = strings.Join(cur.Words, " ") + " { ... }"
				out = append(out, cur)
				cur = dhcpdStmt{}
			case "}":
				if depth == 0 || len(cur.Words) > 0 {
					return nil, false
				}
				return out, true
			default:
				if len(cur.Words) == 0 {
					cur.Line = t.line
				}
				cur.Words = append(cur.Words, t.s)
			}
		}
		return out, depth == 0 && len(cur.Words) == 0
	}
	return block(0)
}

func unquote(s string) string { return strings.TrimSuffix(strings.TrimPrefix(s, `"`), `"`) }

// importDHCP reads dhcpd.conf's subnets as scopes on the interfaces
// whose networks they are. It's exact when every statement is one the
// generator writes, with the values it would write.
func importDHCP(m *Model, src ImportSources, running bool, flags string) (ImportArea, []ImportNote) {
	const file = DHCPdConfPath
	a := ImportArea{Running: running, Exact: true}
	var notes []ImportNote
	lost := func(s dhcpdStmt, why string) {
		a.Exact = false
		notes = append(notes, ImportNote{File: file, Line: s.Line, Kind: NoteLost, Text: s.Text, Message: why})
	}
	content, ok := src.Files[file]
	if !ok {
		a.Exact = !running
		a.Summary = "no dhcpd.conf"
		if running {
			a.Summary = "dhcpd is enabled, but there's no dhcpd.conf"
		}
		return a, notes
	}
	stmts, ok := parseDHCPd(content)
	if !ok {
		a.Exact = false
		a.Summary = "dhcpd.conf couldn't be read"
		notes = append(notes, ImportNote{File: file, Kind: NoteLost, Message: "its braces or semicolons don't match up, so nothing in it was understood"})
		return a, notes
	}
	if strings.Contains(content, "#") {
		notes = append(notes, ImportNote{File: file, Kind: NoteLost, Message: "its comments aren't kept"})
	}
	var devices []string
	for _, s := range stmts {
		w := s.Words
		switch {
		case len(w) == 3 && w[0] == "option" && w[1] == "domain-name" && s.Block == nil:
			if unquote(w[2]) != m.System.Domain {
				lost(s, "OPF gives its DHCP clients the firewall's domain, "+m.System.Domain)
			}
		case len(w) == 4 && w[0] == "subnet" && w[2] == "netmask" && s.Block != nil:
			sc, dev, ok := importScope(m, s, lost, &notes)
			if ok {
				m.DHCP = append(m.DHCP, sc)
				devices = append(devices, dev)
			}
		default:
			lost(s, "a setting OPF doesn't have")
		}
	}
	// dhcpd answers on the devices rc.conf.local gives it, or on every
	// one with a subnet when it gives none; OPF gives it those with a
	// scope.
	if running && flags != "" {
		given := strings.Fields(flags)
		slices.Sort(given)
		slices.Sort(devices)
		if !slices.Equal(given, devices) {
			a.Exact = false
			notes = append(notes, ImportNote{File: RcPath, Kind: NoteLost, Text: "dhcpd_flags=" + flags,
				Message: "OPF has dhcpd answer on the interfaces with a scope: " + strings.Join(devices, " ")})
		}
	}
	for i := range m.DHCP {
		m.DHCP[i].Enabled = running
	}
	a.Summary = fmt.Sprintf("%d scopes", len(m.DHCP))
	if len(m.DHCP) == 1 {
		a.Summary = "1 scope"
	}
	if !running {
		a.Summary += "; dhcpd isn't enabled"
	}
	return a, notes
}

func importScope(m *Model, s dhcpdStmt, lost func(dhcpdStmt, string), notes *[]ImportNote) (DHCPScope, string, bool) {
	const file = DHCPdConfPath
	net, mask := s.Words[1], s.Words[3]
	prefix, ok := maskPrefix(mask)
	var iface *Iface
	if ok {
		for i := range m.Interfaces {
			f := &m.Interfaces[i]
			if f.IPv4.Mode != IPv4Static || f.IPv4.Prefix == nil || *f.IPv4.Prefix != prefix {
				continue
			}
			p, err := netip.ParsePrefix(f.IPv4.Address + "/" + strconv.Itoa(prefix))
			if err == nil && p.Masked().Addr().String() == net {
				iface = f
			}
		}
	}
	if iface == nil {
		lost(s, "a subnet of none of the interfaces OPF took over")
		return DHCPScope{}, "", false
	}
	sc := DHCPScope{Iface: iface.ID, DNS: DNSModeSelf, DNSServers: []string{}, Reservations: []Reservation{}, LeaseHours: 12}
	routers, dns, rng, lease := false, false, false, false
	for _, st := range s.Block {
		w := st.Words
		switch {
		case len(w) == 3 && w[0] == "option" && w[1] == "routers" && st.Block == nil:
			routers = true
			if w[2] != iface.IPv4.Address {
				lost(st, "OPF gives the firewall's address, "+iface.IPv4.Address+", as the router")
			}
		case len(w) >= 3 && w[0] == "option" && w[1] == "domain-name-servers" && st.Block == nil:
			dns = true
			var servers []string
			for _, x := range w[2:] {
				for _, y := range strings.Split(x, ",") {
					if y != "" {
						servers = append(servers, y)
					}
				}
			}
			if len(servers) == 1 && servers[0] == iface.IPv4.Address {
				sc.DNS = DNSModeSelf
			} else {
				sc.DNS, sc.DNSServers = DNSModeCustom, servers
				if strings.Contains(strings.Join(w[2:], " "), " ") && !strings.Contains(strings.Join(w[2:], " "), ", ") {
					lost(st, "the servers aren't separated the way OPF writes them")
				}
			}
		case len(w) == 3 && w[0] == "range" && st.Block == nil && !rng:
			rng = true
			sc.RangeStart, sc.RangeEnd = w[1], w[2]
		case len(w) == 2 && w[0] == "default-lease-time" && st.Block == nil:
			lease = true
			n, err := strconv.Atoi(w[1])
			if err != nil || n <= 0 || n%3600 != 0 {
				lost(st, "OPF's lease times are whole hours")
				if err == nil && n > 0 {
					sc.LeaseHours = max(1, n/3600)
				}
			} else {
				sc.LeaseHours = n / 3600
			}
		case len(w) == 2 && w[0] == "host" && st.Block != nil:
			r, ok := importReservation(st, lost)
			if ok {
				sc.Reservations = append(sc.Reservations, r)
			}
		default:
			lost(st, "a setting OPF doesn't have")
		}
	}
	if !routers {
		lost(s, "OPF gives the firewall's address as the router, which this subnet doesn't")
	}
	if !dns {
		lost(s, "OPF gives a DNS server, the firewall unless another is set, which this subnet doesn't")
	}
	if !rng {
		lost(s, "a subnet without a range: OPF's scopes have one")
		return DHCPScope{}, "", false
	}
	if !lease {
		*notes = append(*notes, ImportNote{File: file, Line: s.Line, Kind: NoteModel, Text: s.Text, Message: "no lease time: dhcpd's default, 12 hours, which OPF writes out"})
	}
	*notes = append(*notes, ImportNote{File: file, Line: s.Line, Kind: NoteModel, Text: s.Text, Message: "a scope on " + iface.Name})
	return sc, iface.Device, true
}

func importReservation(s dhcpdStmt, lost func(dhcpdStmt, string)) (Reservation, bool) {
	r := Reservation{ID: "imp-" + strings.ToLower(s.Words[1]), Hostname: s.Words[1]}
	if !dnsLabelRE.MatchString(r.Hostname) {
		lost(s, "a host name OPF can't use")
		return r, false
	}
	for _, st := range s.Block {
		w := st.Words
		switch {
		case len(w) == 3 && w[0] == "hardware" && w[1] == "ethernet":
			r.MAC = strings.ToLower(w[2])
		case len(w) == 2 && w[0] == "fixed-address":
			r.IP = w[1]
		default:
			lost(st, "a host setting OPF doesn't have")
		}
	}
	if r.MAC == "" || r.IP == "" {
		lost(s, "a host without both a hardware address and a fixed address")
		return r, false
	}
	return r, true
}

// importUnbound reads what of unbound.conf the model has: where it
// forwards, and whether it validates. The generator writes much else
// (statistics, its control socket, the domain's zone), so a running
// resolver is never written the same way, and is left alone unless the
// admin asks.
func importUnbound(m *Model, src ImportSources, running bool) (ImportArea, []ImportNote) {
	const file = UnboundConfPath
	a := ImportArea{Running: running}
	var notes []ImportNote
	content, ok := src.Files[file]
	if !ok {
		a.Exact = !running
		a.Summary = "no unbound.conf"
		return a, notes
	}
	m.DNS.Enabled = running
	section := ""
	forwardRoot := false
	for n, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if c := strings.IndexByte(line, '#'); c >= 0 && !strings.Contains(line[:c], `"`) {
			line = strings.TrimSpace(line[:c])
		}
		if line == "" {
			continue
		}
		key, val, _ := strings.Cut(line, ":")
		key, val = strings.TrimSpace(key), unquote(strings.TrimSpace(val))
		if val == "" && !strings.Contains(key, " ") {
			section = key
			continue
		}
		switch {
		case section == "server" && key == "auto-trust-anchor-file":
			m.DNS.DNSSEC = true
		case section == "forward-zone" && key == "name":
			forwardRoot = val == "."
		case section == "forward-zone" && forwardRoot && key == "forward-addr":
			addr, _, _ := strings.Cut(val, "@")
			m.DNS.Mode = ResolverModeForward
			m.DNS.Forwarders = append(m.DNS.Forwarders, addr)
		case section == "forward-zone" && forwardRoot && key == "forward-tls-upstream":
			m.DNS.ForwardTLS = val == "yes"
		default:
			continue
		}
		notes = append(notes, ImportNote{File: file, Line: n + 1, Kind: NoteModel, Text: line, Message: "a resolver setting"})
	}
	switch {
	case !running:
		a.Summary = "unbound isn't enabled"
		notes = append(notes, ImportNote{File: file, Kind: NoteLost, Message: "OPF writes its own: unbound isn't running, so nothing changes until you turn the resolver on"})
	case m.DNS.Mode == ResolverModeForward:
		a.Summary = fmt.Sprintf("forwards to %s", strings.Join(m.DNS.Forwarders, ", "))
	default:
		a.Summary = "resolves names itself"
	}
	if running {
		notes = append(notes, ImportNote{File: file, Kind: NoteLost, Message: "OPF writes its own: where it listens, who it answers, its statistics and control socket; everything else in this file goes"})
	}
	return a, notes
}
