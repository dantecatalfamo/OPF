package pf

import (
	"regexp"
	"strings"
)

// sysctl.conf is shared like rc.conf.local: an existing system may have
// its own lines, and OPF sets only its own variables (SysctlNames), in a
// marked block at the end. /etc/rc applies the file at boot, line by
// line, so the last assignment counts.

// SysctlPath is where sysctl.conf lives.
const SysctlPath = "/etc/sysctl.conf"

const sysctlMarker = "# Set by OPF from its web interface; the lines above are kept as they are."

// SysctlNames are the variables OPF sets.
var SysctlNames = []string{"net.inet.ip.forwarding"}

var sysctlAssignRE = regexp.MustCompile(`^\s*(` + strings.ReplaceAll(strings.Join(SysctlNames, "|"), ".", `\.`) + `)\s*=`)

// SysctlVars returns the values OPF gives its variables. A stock OpenBSD
// doesn't forward packets between interfaces; a firewall with more than
// one (a VPN tunnel counts) has to, or nothing reaches past it.
func SysctlVars(m *Model) map[string]string {
	n := 0
	for _, i := range m.Interfaces {
		if i.Enabled {
			n++
		}
	}
	vars := map[string]string{"net.inet.ip.forwarding": "0"}
	if n > 1 {
		vars["net.inet.ip.forwarding"] = "1"
	}
	return vars
}

// MergeSysctlConf returns an existing sysctl.conf with OPF's variables
// set to what the model says: every assignment to one of them, and
// OPF's marker, is taken out wherever it is, and OPF's block goes at the
// end. Every other line is kept byte for byte, in order.
func MergeSysctlConf(existing string, m *Model) string {
	var kept []string
	if existing != "" {
		for _, line := range strings.Split(strings.TrimSuffix(existing, "\n"), "\n") {
			if line == sysctlMarker || sysctlAssignRE.MatchString(line) {
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
	b.WriteString(sysctlMarker + "\n")
	vars := SysctlVars(m)
	for _, name := range SysctlNames {
		b.WriteString(name + "=" + vars[name] + "\n")
	}
	return b.String()
}

// SysctlValues reads the values a sysctl.conf gives OPF's variables: the
// last assignment of each. One that isn't set is "", the kernel's
// default.
func SysctlValues(content string) map[string]string {
	vals := map[string]string{}
	for _, name := range SysctlNames {
		vals[name] = ""
	}
	for _, line := range strings.Split(content, "\n") {
		if sub := sysctlAssignRE.FindStringSubmatch(line); sub != nil {
			v, _, _ := strings.Cut(line[len(sub[0]):], "#")
			vals[sub[1]] = strings.TrimSpace(v)
		}
	}
	return vals
}

// GenerateSysctlConf is sysctl.conf on a system that has none: just
// OPF's block. The appliance merges into the live file instead.
func GenerateSysctlConf(m *Model) string { return MergeSysctlConf("", m) }
