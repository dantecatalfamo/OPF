package pf

import (
	"fmt"
	"regexp"
	"strings"
)

// rc.conf.local is shared: pkg_add tells admins to `rcctl enable` the
// daemons they install, which writes pkg_scripts and *_flags lines to
// it, and an existing system has its own. So OPF doesn't own the file.
// It sets only its own daemons' variables (RcVars), in a marked block
// at the end, and keeps every other line as it is.

// RcPath is where rc.conf.local lives.
const RcPath = "/etc/rc.conf.local"

const rcMarker = "# Set by OPF from its web interface; the lines above are kept as they are."

// RcNames are the variables OPF sets, one per daemon in
// config.RcServices.
var RcNames = []string{"dhcpd_flags", "unbound_flags"}

var rcAssignRE = regexp.MustCompile(`^\s*(` + strings.Join(RcNames, "|") + `)=(.*)$`)

// RcVars returns the values OPF gives its variables. dhcpd is given the
// devices it serves explicitly, so it never answers on an interface
// without a scope (the WAN). unbound's empty flags mean enabled with the
// rc.d script's defaults, as `rcctl enable` writes it; NO is disabled.
func RcVars(m *Model) map[string]string {
	var devices []string
	for _, s := range m.DHCP {
		if !s.Enabled {
			continue
		}
		for _, i := range m.Interfaces {
			if i.ID == s.Iface && i.Enabled && i.IPv4.Mode == IPv4Static && i.IPv4.Address != "" && i.IPv4.Prefix != nil {
				devices = append(devices, i.Device)
			}
		}
	}
	vars := map[string]string{"dhcpd_flags": "NO", "unbound_flags": "NO"}
	if len(devices) > 0 {
		vars["dhcpd_flags"] = strings.Join(devices, " ")
	}
	if m.DNS.Enabled {
		vars["unbound_flags"] = ""
	}
	return vars
}

// MergeRcConfLocal returns an existing rc.conf.local with OPF's
// variables set to what the model says. Every assignment to one of them,
// and OPF's marker, is taken out wherever it is, and OPF's block goes at
// the end, so it's what counts (rc(8) sources the file, and sh keeps
// the last assignment). Every other line is kept byte for byte, in
// order. An assignment to one of OPF's variables that continues onto
// another line can't be replaced safely, so it's an error.
func MergeRcConfLocal(existing string, m *Model) (string, error) {
	var kept []string
	if existing != "" {
		for n, line := range strings.Split(strings.TrimSuffix(existing, "\n"), "\n") {
			if line == rcMarker {
				continue
			}
			if rcAssignRE.MatchString(line) {
				if strings.HasSuffix(line, `\`) || strings.Count(line, `"`)%2 != 0 || strings.Count(line, `'`)%2 != 0 {
					return "", fmt.Errorf("line %d of %s sets %s over more than one line; put it on one line", n+1, RcPath, rcAssignRE.FindStringSubmatch(line)[1])
				}
				continue
			}
			kept = append(kept, line)
		}
	}
	for len(kept) > 0 && strings.TrimSpace(kept[len(kept)-1]) == "" {
		kept = kept[:len(kept)-1]
	}
	var b strings.Builder
	for _, line := range kept {
		b.WriteString(line + "\n")
	}
	if len(kept) > 0 {
		b.WriteString("\n")
	}
	b.WriteString(rcMarker + "\n")
	vars := RcVars(m)
	for _, name := range RcNames {
		// Plain double quotes: the values are device names (validated to
		// letters and digits) and NO, so nothing in them is special to sh.
		fmt.Fprintf(&b, "%s=\"%s\"\n", name, vars[name])
	}
	return b.String(), nil
}

// GenerateRcConfLocal is rc.conf.local on a system that has none: just
// OPF's block. The appliance merges into the live file instead.
func GenerateRcConfLocal(m *Model) string {
	out, _ := MergeRcConfLocal("", m) // nothing to refuse in an empty file
	return out
}

// shellWord reads the value of an assignment the way sh does for the
// forms rc.conf.local uses: up to the closing quote of a quoted value,
// or up to whitespace (a comment, say) for a bare one.
func shellWord(v string) string {
	if v != "" && (v[0] == '"' || v[0] == '\'') {
		if end := strings.IndexByte(v[1:], v[0]); end >= 0 {
			return v[1 : 1+end]
		}
		return v[1:]
	}
	if i := strings.IndexAny(v, " \t"); i >= 0 {
		return v[:i]
	}
	return v
}

// RcValues reads the values an rc.conf.local gives OPF's variables: the
// last assignment of each, unquoted. One that isn't set is NO, which is
// rc.conf's default for all of them.
func RcValues(content string) map[string]string {
	vals := map[string]string{}
	for _, name := range RcNames {
		vals[name] = "NO"
	}
	for _, line := range strings.Split(content, "\n") {
		if sub := rcAssignRE.FindStringSubmatch(line); sub != nil {
			vals[sub[1]] = shellWord(sub[2])
		}
	}
	return vals
}
