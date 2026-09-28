package pf

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// FieldError is one problem with a model, at a path such as
// "firewall.rules[3].description".
type FieldError struct {
	Path    string `json:"path"`
	Message string `json:"message"`
}

func (e FieldError) Error() string { return e.Path + ": " + e.Message }

// Validate checks a model before anything is generated from it. Every
// value that ends up in a configuration file is checked against what
// that file's parser accepts (pf.conf(5), hostname.if(5),
// dhcpd.conf(5), unbound.conf(5)), so a value can't change the meaning
// of the file around it. References between objects must resolve.
//
// Raw pf rules and custom pf blocks are deliberately powerful and only
// checked for shape: one line per raw rule, no control characters.
func Validate(m *Model) []FieldError {
	v := &validator{m: m}
	v.system()
	v.interfaces()
	v.routing()
	v.firewall()
	v.dhcp()
	v.dns()
	v.wireguard()
	return v.errs
}

type validator struct {
	m    *Model
	errs []FieldError
}

func (v *validator) fail(path, format string, args ...any) {
	v.errs = append(v.errs, FieldError{Path: path, Message: fmt.Sprintf(format, args...)})
}

func at(path string, i int) string { return fmt.Sprintf("%s[%d]", path, i) }

var (
	// Interface ids become pf macros ($lan), so they follow macro rules.
	ifaceIDRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	// Other ids only link objects together inside the model.
	idRE     = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	deviceRE = regexp.MustCompile(`^[a-z]+[0-9]+$`) // em0, vlan20, wg0
	// Interface groups can't end in a digit (ifconfig(8)).
	groupRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*[A-Za-z_]$|^[A-Za-z_]$`)
	// pf table names (PF_TABLE_NAME_SIZE 32) and tags (PF_TAG_NAME_SIZE 64).
	tableRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,30}$`)
	tagRE   = regexp.MustCompile(`^[A-Za-z0-9_]{1,63}$`)
	// Names written into hostname.if lines (description, wgdescr), which
	// netstart hands to ifconfig and a shell.
	plainNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 _.-]{0,62}$`)
	dnsLabelRE  = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
	serviceRE   = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`) // /etc/services names
	flagsRE     = regexp.MustCompile(`^(any|[FSRPAUEW]*/[FSRPAUEW]+)$`)
	icmpTypeRE  = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)
	timezoneRE  = regexp.MustCompile(`^[A-Za-z0-9_+-]+(/[A-Za-z0-9_+-]+)*$`)
)

func (v *validator) oneOf(path, got string, allowed ...string) {
	if !slices.Contains(allowed, got) {
		v.fail(path, "must be one of %s, not %q", strings.Join(allowed, ", "), got)
	}
}

func (v *validator) intRange(path string, n, lo, hi int) {
	if n < lo || n > hi {
		v.fail(path, "must be between %d and %d", lo, hi)
	}
}

// text checks free text that ends up quoted in a config file, or in a
// comment in hostname.if, which netstart reads with the shell's read.
// pf's lexer can't carry a newline or a backslash through a quoted
// string, and expands $if, $nr and similar in labels.
func (v *validator) text(path, s string, max int, required bool) {
	switch {
	case s == "" && required:
		v.fail(path, "is required")
	case !utf8.ValidString(s):
		v.fail(path, "isn't valid UTF-8")
	case len(s) > max:
		v.fail(path, "is %d bytes; the most is %d", len(s), max)
	case strings.ContainsAny(s, `\$`):
		v.fail(path, `can't contain \ or $`)
	case strings.ContainsFunc(s, unicode.IsControl):
		v.fail(path, "can't contain control characters or line breaks")
	}
}

// note checks a description written as a comment above pf rules. pf's
// lexer continues a comment ending in a backslash onto the next line, so
// backslashes are out; so are line breaks, which would end the comment.
func (v *validator) note(path, s string) {
	switch {
	case !utf8.ValidString(s):
		v.fail(path, "isn't valid UTF-8")
	case len(s) > 200:
		v.fail(path, "is %d bytes; the most is 200", len(s))
	case strings.Contains(s, `\`):
		v.fail(path, `can't contain \`)
	case strings.ContainsFunc(s, unicode.IsControl):
		v.fail(path, "can't contain control characters or line breaks")
	}
}

func (v *validator) re(path, s string, re *regexp.Regexp, what string) bool {
	if !re.MatchString(s) {
		v.fail(path, "%q isn't a valid %s", s, what)
		return false
	}
	return true
}

func (v *validator) hostname(path, s string) {
	if !dnsLabelRE.MatchString(s) {
		v.fail(path, "%q isn't a valid host name (letters, digits and -)", s)
	}
}

func (v *validator) domain(path, s string) {
	if len(s) > 253 || s == "" {
		v.fail(path, "%q isn't a valid domain", s)
		return
	}
	for _, l := range strings.Split(s, ".") {
		if !dnsLabelRE.MatchString(l) {
			v.fail(path, "%q isn't a valid domain", s)
			return
		}
	}
}

// host is a host name, domain name or IP address.
func (v *validator) host(path, s string) {
	if _, err := netip.ParseAddr(s); err == nil {
		return
	}
	v.domain(path, s)
}

func (v *validator) addr(path, s string, v4 bool) netip.Addr {
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		v.fail(path, "%q isn't an IP address", s)
		return netip.Addr{}
	}
	if v4 && !a.Is4() {
		v.fail(path, "%q isn't an IPv4 address", s)
	}
	return a
}

func (v *validator) prefix(path, s string, v4 bool) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		v.fail(path, "%q isn't a network in CIDR form", s)
		return
	}
	if v4 && !p.Addr().Is4() {
		v.fail(path, "%q isn't an IPv4 network", s)
	}
}

func (v *validator) addrOrPrefix(path, s string) {
	if strings.Contains(s, "/") {
		v.prefix(path, s, false)
	} else {
		v.addr(path, s, false)
	}
}

func (v *validator) unique(path string, seen map[string]bool, key, what string) {
	if seen[key] {
		v.fail(path, "%s %q is used more than once", what, key)
	}
	seen[key] = true
}

func (v *validator) iface(id string) *Iface {
	for i := range v.m.Interfaces {
		if v.m.Interfaces[i].ID == id {
			return &v.m.Interfaces[i]
		}
	}
	return nil
}

func (v *validator) ifaceRef(path, id string) *Iface {
	i := v.iface(id)
	if i == nil {
		v.fail(path, "no interface %q", id)
	}
	return i
}

func (v *validator) alias(name string) *Alias {
	for i := range v.m.Firewall.Aliases {
		if v.m.Firewall.Aliases[i].Name == name {
			return &v.m.Firewall.Aliases[i]
		}
	}
	return nil
}

func (v *validator) gatewayRef(path, id string) {
	if !slices.ContainsFunc(v.m.Routing.Gateways, func(g Gateway) bool { return g.ID == id }) {
		v.fail(path, "no gateway %q", id)
	}
}

// ---------- sections ----------

func (v *validator) system() {
	s := v.m.System
	v.hostname("system.hostname", s.Hostname)
	v.domain("system.domain", s.Domain)
	if s.Timezone != "" && (len(s.Timezone) > 64 || !timezoneRE.MatchString(s.Timezone)) {
		v.fail("system.timezone", "%q isn't a time zone name", s.Timezone)
	}
	if len(s.NTPServers) == 0 {
		v.fail("system.ntpServers", "needs at least one server")
	}
	for i, n := range s.NTPServers {
		v.host(at("system.ntpServers", i), n)
	}
}

func (v *validator) interfaces() {
	ids, devices := map[string]bool{}, map[string]bool{}
	for i, f := range v.m.Interfaces {
		p := at("interfaces", i)
		if v.re(p+".id", f.ID, ifaceIDRE, "interface id (lowercase letters, digits and _)") && pfKeywords[f.ID] {
			v.fail(p+".id", "%q is a pf keyword and can't name a macro", f.ID)
		}
		v.unique(p+".id", ids, f.ID, "interface id")
		if v.re(p+".device", f.Device, deviceRE, "device name (like em0)") && len(f.Device) > 15 {
			v.fail(p+".device", "is longer than 15 characters")
		}
		v.unique(p+".device", devices, f.Device, "device")
		v.re(p+".name", f.Name, plainNameRE, "name (letters, digits, spaces, _ . -)")
		v.oneOf(p+".role", string(f.Role), string(RoleWAN), string(RoleLAN), string(RoleOPT), string(RoleVPN))
		v.oneOf(p+".ipv6", string(f.IPv6), string(IPv6SLAAC), string(IPv6None))
		switch f.IPv4.Mode {
		case IPv4Static:
			v.addr(p+".ipv4.address", f.IPv4.Address, true)
			if f.IPv4.Prefix == nil {
				v.fail(p+".ipv4.prefix", "is required for a fixed address")
			} else {
				v.intRange(p+".ipv4.prefix", *f.IPv4.Prefix, 1, 32)
			}
			if f.IPv4.Gateway != "" {
				v.addr(p+".ipv4.gateway", f.IPv4.Gateway, true)
			}
		case IPv4DHCP, IPv4None:
			if f.IPv4.Address != "" || f.IPv4.Prefix != nil || f.IPv4.Gateway != "" {
				v.fail(p+".ipv4", "an address is only allowed with mode static")
			}
		default:
			v.oneOf(p+".ipv4.mode", string(f.IPv4.Mode), string(IPv4DHCP), string(IPv4Static), string(IPv4None))
		}
		if f.MTU != nil {
			v.intRange(p+".mtu", *f.MTU, 576, 9216)
		}
		if f.VLAN != nil {
			v.re(p+".vlan.parent", f.VLAN.Parent, deviceRE, "device name")
			v.intRange(p+".vlan.tag", f.VLAN.Tag, 1, 4094)
			if !strings.HasPrefix(f.Device, "vlan") {
				v.fail(p+".device", "a VLAN's device must be a vlan interface, like vlan%d", f.VLAN.Tag)
			}
		}
	}
}

func (v *validator) routing() {
	r := v.m.Routing
	ids := map[string]bool{}
	for i, g := range r.Gateways {
		p := at("routing.gateways", i)
		v.re(p+".id", g.ID, idRE, "id")
		v.unique(p+".id", ids, g.ID, "gateway id")
		v.re(p+".name", g.Name, plainNameRE, "name")
		v.ifaceRef(p+".iface", g.Iface)
		if g.Address != "dhcp" {
			v.addr(p+".address", g.Address, false)
		}
		if g.Monitor != "" {
			v.addr(p+".monitor", g.Monitor, false)
		}
		v.text(p+".description", g.Description, 200, false)
	}
	if r.DefaultGateway != "" {
		v.gatewayRef("routing.defaultGateway", r.DefaultGateway)
	}
	routes := map[string]bool{}
	for i, rt := range r.Routes {
		p := at("routing.routes", i)
		v.re(p+".id", rt.ID, idRE, "id")
		v.unique(p+".id", routes, rt.ID, "route id")
		v.prefix(p+".network", rt.Network, false)
		v.gatewayRef(p+".gateway", rt.Gateway)
		for _, g := range r.Gateways {
			if g.ID == rt.Gateway && g.Address == "dhcp" {
				v.fail(p+".gateway", "a static route needs a gateway with a fixed address")
			}
		}
		// Written after a # on a !route line in hostname.if.
		v.text(p+".description", rt.Description, 200, false)
	}
}

func (v *validator) endpoint(path string, e Endpoint) {
	switch e.Type {
	case EndpointAny:
		if e.Not {
			v.fail(path+".not", "\"not any\" matches nothing")
		}
	case EndpointSelf, EndpointIface:
		if e.Type == EndpointIface {
			switch {
			case e.Iface != "" && e.Group != "":
				v.fail(path, "has both an interface and a group")
			case e.Iface != "":
				v.ifaceRef(path+".iface", e.Iface)
			case e.Group != "":
				if !(groupRE.MatchString(e.Group) || deviceRE.MatchString(e.Group)) || len(e.Group) > 15 {
					v.fail(path+".group", "%q isn't an interface group or interface name", e.Group)
				}
			default:
				v.fail(path, "needs an interface or a group")
			}
		}
		v.oneOf(path+".part", string(e.Part), string(PartAddress), string(PartNetwork), string(PartBroadcast), string(PartPeer))
	case EndpointHost:
		v.addr(path+".value", e.Value, false)
	case EndpointNetwork:
		v.prefix(path+".value", e.Value, false)
	case EndpointAlias:
		a := v.alias(e.Alias)
		switch {
		case a == nil:
			v.fail(path+".alias", "no alias %q", e.Alias)
		case a.Type == AliasPorts:
			v.fail(path+".alias", "%q is a port alias, not addresses", e.Alias)
		}
	default:
		v.fail(path+".type", "unknown endpoint type %q", e.Type)
	}
}

func (v *validator) port(path, s string) {
	if s == "" {
		return
	}
	if name, ok := strings.CutPrefix(s, "alias:"); ok {
		a := v.alias(name)
		if a == nil || a.Type != AliasPorts {
			v.fail(path, "no port alias %q", name)
		}
		return
	}
	if !validPortExpr(s) {
		v.fail(path, "%q isn't a port, range (8000:8080), list (80,443) or comparison (> 1023)", s)
	}
}

func validPort(s string) bool {
	if serviceRE.MatchString(s) {
		return true // resolved by pfctl from /etc/services
	}
	n, err := strconv.Atoi(s)
	return err == nil && n >= 1 && n <= 65535 && strconv.Itoa(n) == s
}

func validPortExpr(s string) bool {
	s = strings.TrimSpace(s)
	if strings.Contains(s, ",") {
		for _, p := range strings.Split(s, ",") {
			if !validPortExpr(p) || strings.ContainsAny(strings.TrimSpace(p), " <>=!") {
				return false
			}
		}
		return true
	}
	for _, sep := range []string{":", "-", "><", "<>"} {
		if a, b, ok := strings.Cut(s, sep); ok && sep != "-" || ok && isNumber(a) && isNumber(b) {
			a, b = strings.TrimSpace(a), strings.TrimSpace(b)
			return isNumber(a) && isNumber(b) && validPort(a) && validPort(b)
		}
	}
	for _, op := range []string{"!=", "<=", ">=", "<", ">", "="} {
		if rest, ok := strings.CutPrefix(s, op); ok {
			return validPort(strings.TrimSpace(rest))
		}
	}
	return validPort(s)
}

func (v *validator) ifaceList(path string, ids []string) {
	for i, id := range ids {
		v.ifaceRef(at(path, i), id)
	}
}

func (v *validator) rawLine(path, s string, required bool) {
	switch {
	case strings.TrimSpace(s) == "" && required:
		v.fail(path, "is required")
	case strings.ContainsAny(s, "\n\r"):
		v.fail(path, "must be a single line; use custom pf for several")
	case strings.ContainsFunc(s, func(r rune) bool { return unicode.IsControl(r) && r != '\t' }):
		v.fail(path, "can't contain control characters")
	case !utf8.ValidString(s) || len(s) > 4096:
		v.fail(path, "must be valid UTF-8 and at most 4096 bytes")
	}
}

func (v *validator) firewall() {
	fw := v.m.Firewall
	aliasNames := map[string]bool{}
	for i, a := range fw.Aliases {
		p := at("firewall.aliases", i)
		v.re(p+".id", a.ID, idRE, "id")
		v.re(p+".name", a.Name, tableRE, "alias name (letters, digits, _; up to 31)")
		v.unique(p+".name", aliasNames, a.Name, "alias")
		v.text(p+".description", a.Description, 200, false)
		for j, e := range a.Entries {
			ep := at(p+".entries", j)
			switch a.Type {
			case AliasHosts:
				v.addr(ep, e, false)
			case AliasNetworks, AliasTable:
				v.addrOrPrefix(ep, e)
			case AliasPorts:
				if !validPort(e) {
					v.fail(ep, "%q isn't a port", e)
				}
			case AliasURL:
				v.fail(ep, "a downloaded list has no fixed entries")
			}
		}
		switch a.Type {
		case AliasHosts, AliasNetworks, AliasPorts:
			if len(a.Entries) == 0 {
				v.fail(p+".entries", "needs at least one entry")
			}
		case AliasTable:
		case AliasURL:
			// Written into a pf.conf comment and fetched by the parent.
			u, err := url.Parse(a.URL)
			if err != nil || u.Scheme != "https" || u.Host == "" || strings.ContainsFunc(a.URL, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) {
				v.fail(p+".url", "must be an https:// URL")
			}
			if a.RefreshHours != nil {
				v.intRange(p+".refreshHours", *a.RefreshHours, 1, 8760)
			}
		default:
			v.fail(p+".type", "unknown alias type %q", a.Type)
		}
	}

	ids := map[string]bool{}
	for i, r := range fw.Rules {
		p := at("firewall.rules", i)
		v.re(p+".id", r.ID, labelIDRE, "rule id (it's in the rule's pf label)")
		v.unique(p+".id", ids, r.ID, "rule id")
		v.ifaceList(p+".interfaces", r.Interfaces)
		for j, g := range r.Groups {
			if !(groupRE.MatchString(g) || deviceRE.MatchString(g)) || len(g) > 15 {
				v.fail(at(p+".groups", j), "%q isn't an interface group or interface name", g)
			}
		}
		v.note(p+".description", r.Description)
		switch r.Kind {
		case "raw":
			v.rawLine(p+".text", r.Text, true)
		case "form":
			v.formRule(p, r)
		default:
			v.fail(p+".kind", "must be form or raw, not %q", r.Kind)
		}
	}

	fids := map[string]bool{}
	for i, f := range fw.Forwards {
		p := at("firewall.forwards", i)
		v.re(p+".id", f.ID, labelIDRE, "port forward id (it's in the rules' pf label)")
		v.unique(p+".id", fids, f.ID, "port forward id")
		v.ifaceRef(p+".iface", f.Iface)
		v.oneOf(p+".protocol", string(f.Protocol), string(ProtoTCP), string(ProtoUDP), string(ProtoTCPUDP))
		v.endpoint(p+".source", f.Source)
		for _, fp := range []struct{ path, val string }{{".externalPort", f.ExternalPort}, {".targetPort", f.TargetPort}} {
			if !validPortExpr(fp.val) || strings.ContainsAny(fp.val, ",<>=! ") {
				v.fail(p+fp.path, "%q isn't a port or range", fp.val)
			}
		}
		v.addr(p+".target", f.Target, false)
		v.note(p+".description", f.Description)
	}

	nat := fw.OutboundNAT
	v.oneOf("firewall.outboundNat.mode", string(nat.Mode), string(NATModeAuto), string(NATModeHybrid), string(NATModeManual))
	nids := map[string]bool{}
	for i, n := range nat.Rules {
		p := at("firewall.outboundNat.rules", i)
		v.re(p+".id", n.ID, labelIDRE, "NAT rule id (it's in the rule's pf label)")
		v.unique(p+".id", nids, n.ID, "NAT rule id")
		v.ifaceRef(p+".iface", n.Iface)
		v.endpoint(p+".source", n.Source)
		v.endpoint(p+".destination", n.Destination)
		switch n.Translation.Type {
		case TranslationIfaddr, TranslationNone:
		case TranslationAddress:
			v.addrOrPrefix(p+".translation.value", n.Translation.Value)
		default:
			v.fail(p+".translation.type", "unknown translation %q", n.Translation.Type)
		}
		if n.Pool != "" {
			v.oneOf(p+".pool", string(n.Pool), string(PoolRoundRobin), string(PoolSourceHash), string(PoolRandom))
		}
		v.note(p+".description", n.Description)
	}

	o := fw.Options
	v.oneOf("firewall.options.blockPolicy", string(o.BlockPolicy), string(BlockPolicyDrop), string(BlockPolicyReturn))
	v.oneOf("firewall.options.statePolicy", string(o.StatePolicy), string(StatePolicyOptionFloating), string(StatePolicyOptionIfBound))
	v.oneOf("firewall.options.optimization", string(o.Optimization), string(OptNormal), string(OptHighLatency), string(OptSatellite), string(OptAggressive), string(OptConservative))
	v.oneOf("firewall.options.syncookies", string(o.Syncookies), string(SyncookiesNever), string(SyncookiesAdaptive), string(SyncookiesAlways))
	v.intRange("firewall.options.maxStates", o.MaxStates, 1000, 10_000_000)
	if o.Scrub.MaxMss != nil {
		v.intRange("firewall.options.scrub.maxMss", *o.Scrub.MaxMss, 536, 65535)
	}

	// Custom pf is an escape hatch and may hold anything pf accepts, but
	// no control characters besides tabs and line breaks.
	for _, c := range []struct{ path, val string }{
		{"firewall.custom.options", fw.Custom.Options},
		{"firewall.custom.beforeFilter", fw.Custom.BeforeFilter},
		{"firewall.custom.afterFilter", fw.Custom.AfterFilter},
	} {
		if !utf8.ValidString(c.val) || len(c.val) > 64<<10 ||
			strings.ContainsFunc(c.val, func(r rune) bool { return unicode.IsControl(r) && r != '\t' && r != '\n' }) {
			v.fail(c.path, "must be valid UTF-8 text of at most 64 KB without control characters")
		}
	}
}

func (v *validator) formRule(p string, r Rule) {
	v.oneOf(p+".action", string(r.Action), string(ActionPass), string(ActionBlock), string(ActionReject), string(ActionMatch))
	v.oneOf(p+".direction", string(r.Direction), string(DirectionIn), string(DirectionOut), string(DirectionAny))
	v.oneOf(p+".family", string(r.Family), string(FamilyInet), string(FamilyInet6), string(FamilyAny))
	v.oneOf(p+".protocol", string(r.Protocol), string(ProtoAny), string(ProtoTCP), string(ProtoUDP), string(ProtoTCPUDP), string(ProtoICMP), string(ProtoICMP6), string(ProtoESP), string(ProtoGRE))
	v.oneOf(p+".log", string(r.Log), string(LogOff), string(LogOn), string(LogAll))
	v.endpoint(p+".source", r.Source)
	v.endpoint(p+".destination", r.Destination)
	ports := r.Protocol == ProtoTCP || r.Protocol == ProtoUDP || r.Protocol == ProtoTCPUDP
	for _, pp := range []struct{ path, val string }{{".sourcePort", r.SourcePort}, {".port", r.Port}} {
		if pp.val != "" && !ports {
			v.fail(p+pp.path, "ports need protocol TCP or UDP")
		}
		v.port(p+pp.path, pp.val)
	}
	if r.TCPFlags != "" {
		v.re(p+".tcpFlags", r.TCPFlags, flagsRE, "flags value (like S/SA)")
	}
	if r.ICMPType != "" {
		v.re(p+".icmpType", r.ICMPType, icmpTypeRE, "ICMP type")
	}
	for _, t := range []struct{ path, val string }{{".tag", r.Tag}, {".tagged", r.Tagged}} {
		if t.val != "" {
			v.re(p+t.path, t.val, tagRE, "tag (letters, digits, _)")
		}
	}
	if r.OSFingerprint != "" {
		v.text(p+".osFingerprint", r.OSFingerprint, 64, false)
	}
	if r.Gateway != "" {
		v.gatewayRef(p+".gateway", r.Gateway)
	}
	if r.ReplyTo != "" {
		v.gatewayRef(p+".replyTo", r.ReplyTo)
	}
	if r.RTable != nil {
		v.intRange(p+".rtable", *r.RTable, 0, 255)
	}
	if r.Prio != nil {
		v.intRange(p+".prio", *r.Prio, 0, 7)
	}
	if r.Probability != nil {
		v.intRange(p+".probability", *r.Probability, 0, 100)
	}
	if r.BlockReturn != "" {
		v.oneOf(p+".blockReturn", string(r.BlockReturn), string(BlockReturnDrop), string(BlockReturnReturn), string(BlockReturnRST), string(BlockReturnICMP), string(BlockReturnICMP6))
	}
	if r.ReturnRstTTL != nil {
		v.intRange(p+".returnRstTtl", *r.ReturnRstTTL, 1, 255)
	}
	if r.ReturnICMPCode != "" {
		v.re(p+".returnIcmpCode", r.ReturnICMPCode, icmpTypeRE, "ICMP code")
	}
	if s := r.State; s != nil {
		v.oneOf(p+".state.mode", string(s.Mode), string(StateModeKeep), string(StateModeModulate), string(StateModeSynproxy), string(StateModeNone))
		for _, n := range []struct {
			path string
			val  *int
		}{{".state.maxStates", s.MaxStates}, {".state.maxSrcConn", s.MaxSrcConn}} {
			if n.val != nil {
				v.intRange(p+n.path, *n.val, 1, 10_000_000)
			}
		}
		if s.MaxSrcConnRate != nil {
			v.intRange(p+".state.maxSrcConnRate.count", s.MaxSrcConnRate.Count, 1, 1_000_000)
			v.intRange(p+".state.maxSrcConnRate.seconds", s.MaxSrcConnRate.Seconds, 1, 86400)
		}
		if s.Overload != "" {
			if a := v.alias(s.Overload); a == nil || a.Type != AliasTable {
				v.fail(p+".state.overload", "no table alias %q", s.Overload)
			}
		}
		if s.Policy != "" {
			v.oneOf(p+".state.policy", string(s.Policy), string(StatePolicyIfBound), string(StatePolicyFloating))
		}
	}
}

func (v *validator) dhcp() {
	seen := map[string]bool{}
	for i, s := range v.m.DHCP {
		p := at("dhcp", i)
		v.unique(p+".iface", seen, s.Iface, "DHCP interface")
		f := v.ifaceRef(p+".iface", s.Iface)
		var net4 netip.Prefix
		if f != nil {
			if f.IPv4.Mode != IPv4Static || f.IPv4.Prefix == nil {
				v.fail(p+".iface", "DHCP needs an interface with a fixed IPv4 address")
			} else if a, err := netip.ParseAddr(f.IPv4.Address); err == nil {
				net4 = netip.PrefixFrom(a, *f.IPv4.Prefix).Masked()
			}
		}
		inNet := func(path, s string) netip.Addr {
			a := v.addr(path, s, true)
			if a.IsValid() && net4.IsValid() && !net4.Contains(a) {
				v.fail(path, "%s isn't in %s", s, net4)
			}
			return a
		}
		start, end := inNet(p+".rangeStart", s.RangeStart), inNet(p+".rangeEnd", s.RangeEnd)
		if start.IsValid() && end.IsValid() && end.Less(start) {
			v.fail(p+".rangeEnd", "comes before the first address")
		}
		v.intRange(p+".leaseHours", s.LeaseHours, 1, 8760)
		v.oneOf(p+".dns", string(s.DNS), string(DNSModeSelf), string(DNSModeCustom))
		for j, d := range s.DNSServers {
			v.addr(at(p+".dnsServers", j), d, true)
		}
		macs, ips, names := map[string]bool{}, map[string]bool{}, map[string]bool{}
		for j, r := range s.Reservations {
			rp := at(p+".reservations", j)
			v.re(rp+".id", r.ID, idRE, "id")
			v.hostname(rp+".hostname", r.Hostname)
			v.unique(rp+".hostname", names, strings.ToLower(r.Hostname), "host name")
			if hw, err := net.ParseMAC(r.MAC); err != nil || len(hw) != 6 {
				v.fail(rp+".mac", "%q isn't a MAC address like 00:11:22:33:44:55", r.MAC)
			}
			v.unique(rp+".mac", macs, strings.ToLower(r.MAC), "MAC address")
			inNet(rp+".ip", r.IP)
			v.unique(rp+".ip", ips, r.IP, "address")
		}
	}
}

func (v *validator) dns() {
	d := v.m.DNS
	v.oneOf("dns.mode", string(d.Mode), string(ResolverModeRecursive), string(ResolverModeForward))
	if d.Mode == ResolverModeForward && len(d.Forwarders) == 0 {
		v.fail("dns.forwarders", "forwarding needs at least one server")
	}
	for i, f := range d.Forwarders {
		v.addr(at("dns.forwarders", i), f, false)
	}
	ids := map[string]bool{}
	for i, o := range d.Overrides {
		p := at("dns.overrides", i)
		v.re(p+".id", o.ID, idRE, "id")
		v.unique(p+".id", ids, o.ID, "host name id")
		v.hostname(p+".host", o.Host)
		v.domain(p+".domain", o.Domain)
		v.addr(p+".ip", o.IP, false)
		v.text(p+".description", o.Description, 200, false)
	}
}

func (v *validator) wgKey(path, k string) {
	b, err := base64.StdEncoding.DecodeString(k)
	if err != nil || len(b) != 32 {
		v.fail(path, "isn't a WireGuard key (44 characters of base64)")
	}
}

func (v *validator) wireguard() {
	w := v.m.WireGuard
	if !w.Enabled && len(w.Peers) == 0 && w.Address == "" {
		return
	}
	v.intRange("wireguard.listenPort", w.ListenPort, 1, 65535)
	v.prefix("wireguard.address", w.Address, false)
	v.wgKey("wireguard.publicKey", w.PublicKey)
	ids, keys := map[string]bool{}, map[string]bool{}
	for i, pr := range w.Peers {
		p := at("wireguard.peers", i)
		v.re(p+".id", pr.ID, idRE, "id")
		v.unique(p+".id", ids, pr.ID, "peer id")
		v.re(p+".name", pr.Name, plainNameRE, "name (letters, digits, spaces, _ . -)")
		v.wgKey(p+".publicKey", pr.PublicKey)
		v.unique(p+".publicKey", keys, pr.PublicKey, "public key")
		v.prefix(p+".address", pr.Address, false)
		for j, n := range pr.Networks {
			v.prefix(at(p+".networks", j), n, false)
		}
		if pr.Endpoint != "" {
			host, port, err := net.SplitHostPort(pr.Endpoint)
			if err != nil || !validPort(port) || strings.Trim(port, "0123456789") != "" {
				v.fail(p+".endpoint", "%q isn't host:port", pr.Endpoint)
			} else {
				v.host(p+".endpoint", host)
			}
		}
		if pr.Keepalive != nil {
			v.intRange(p+".keepalive", *pr.Keepalive, 0, 65535)
		}
		v.oneOf(p+".clientRoutes", string(pr.ClientRoutes), string(ClientRoutesSplit), string(ClientRoutesFull), string(ClientRoutesSite))
	}
}
