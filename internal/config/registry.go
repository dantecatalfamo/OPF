package config

import (
	"fmt"
	"io/fs"
	"regexp"
	"slices"
	"strings"
)

// File describes a configuration file OPF manages. The file on disk is
// the only state; this just says how to validate and activate it.
type File struct {
	Name string // stable identifier used in URLs
	Path string // absolute path on the live system
	Desc string

	// Check validates a file without activating it. "{}" is replaced
	// with the path of the file to check. Nil means no checker exists.
	Check []string

	// Apply activates a file. "{}" is replaced with the path to load,
	// which for Confirm files is the staged copy rather than Path.
	Apply []string

	// Service, if set, is reloaded or restarted with rcctl after the
	// file changes, but only when it is already running.
	Service       string
	ServiceAction string // "reload" or "restart"

	// Confirm files are loaded from their staged copy without being
	// written to Path. Unless the commit is confirmed before the
	// timeout, the live file is loaded again. Because Path is untouched
	// until confirmation, a reboot also reverts the change.
	Confirm bool

	// Mode is used when creating a file that doesn't exist yet.
	Mode fs.FileMode

	// Match makes this entry a pattern for a family of files: Name and
	// Path each contain one "*", and a file matches when the text in
	// its place matches this regular expression in full. "{*}" in Check
	// and Apply is replaced with that text. Lookup returns the concrete
	// file, e.g. hostname.em0 for hostname.*.
	Match string
}

func (f File) isPattern() bool { return f.Match != "" }

// instance returns the concrete file a pattern entry names for part, or
// false if part doesn't match.
func (f File) instance(part string) (File, bool) {
	if !regexp.MustCompile(`^(?:` + f.Match + `)$`).MatchString(part) {
		return File{}, false
	}
	g := f
	g.Name = strings.Replace(f.Name, "*", part, 1)
	g.Path = strings.Replace(f.Path, "*", part, 1)
	g.Match = ""
	g.Check = substPart(f.Check, part)
	g.Apply = substPart(f.Apply, part)
	return g, true
}

// match reports whether name is an instance of pattern entry f, and
// returns the instance.
func (f File) match(name string) (File, bool) {
	prefix, suffix, _ := strings.Cut(f.Name, "*")
	if len(name) <= len(prefix)+len(suffix) || !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, suffix) {
		return File{}, false
	}
	return f.instance(name[len(prefix) : len(name)-len(suffix)])
}

func substPart(argv []string, part string) []string {
	if argv == nil {
		return nil
	}
	out := make([]string, len(argv))
	for i, a := range argv {
		out[i] = strings.ReplaceAll(a, "{*}", part)
	}
	return out
}

// ModelPath is where the appliance model lives. It's a managed file like
// any other, so it's staged, committed, snapshotted and reverted
// together with the files generated from it.
const ModelPath = "/var/opf/config.json"

// DefaultFiles are the files managed on a stock OpenBSD system, in the
// order they are applied during a commit.
func DefaultFiles() []File {
	return []File{
		{
			Name: "config.json", Path: ModelPath,
			Desc: "OPF's configuration model",
			Mode: 0600,
		},
		{
			// hostname(1) takes the name as an argument, so the file is
			// read by a shell; its contents are validated by the model.
			Name: "myname", Path: "/etc/myname",
			Desc:  "Host name",
			Apply: []string{"sh", "-c", `hostname "$(cat "$1")"`, "sh", "{}"},
			Mode:  0644,
		},
		{
			// Read at boot and by a full netstart; not applied on commit.
			Name: "mygate", Path: "/etc/mygate",
			Desc: "Default gateway (applied at boot)",
			Mode: 0644,
		},
		{
			// hostname.if(5), one per interface. Applied first, since
			// pf rules refer to the interfaces. netstart reads /etc
			// directly, so these can't be loaded from a staged copy for
			// confirmation (see TODO).
			Name: "hostname.*", Path: "/etc/hostname.*", Match: `[a-z]+[0-9]+`,
			Desc:  "Network interface",
			Apply: []string{"sh", "/etc/netstart", "{*}"},
			Mode:  0640, // may hold keys, e.g. wgkey
		},
		{
			Name: "rc.conf.local", Path: "/etc/rc.conf.local",
			Desc:  "Enabled daemons and their flags",
			Check: []string{"sh", "-n", "{}"},
			Mode:  0644,
		},
		{
			Name: "pf.conf", Path: "/etc/pf.conf",
			Desc:    "Packet filter rules",
			Check:   []string{"pfctl", "-n", "-f", "{}"},
			Apply:   []string{"pfctl", "-f", "{}"},
			Confirm: true,
			Mode:    0600,
		},
		{
			Name: "dhcpd.conf", Path: "/etc/dhcpd.conf",
			Desc:    "DHCP server",
			Check:   []string{"dhcpd", "-n", "-c", "{}"},
			Service: "dhcpd", ServiceAction: "restart",
			Mode: 0644,
		},
		{
			Name: "unbound.conf", Path: "/var/unbound/etc/unbound.conf",
			Desc:    "Recursive DNS resolver",
			Check:   []string{"unbound-checkconf", "{}"},
			Service: "unbound", ServiceAction: "reload",
			Mode: 0644,
		},
		{
			Name: "ntpd.conf", Path: "/etc/ntpd.conf",
			Desc:    "Time synchronisation",
			Check:   []string{"ntpd", "-n", "-f", "{}"},
			Service: "ntpd", ServiceAction: "restart",
			Mode: 0644,
		},
		{
			Name: "httpd.conf", Path: "/etc/httpd.conf",
			Desc:    "Web server",
			Check:   []string{"httpd", "-n", "-f", "{}"},
			Service: "httpd", ServiceAction: "reload",
			Mode: 0644,
		},
		{
			Name: "sshd_config", Path: "/etc/ssh/sshd_config",
			Desc:    "SSH server",
			Check:   []string{"sshd", "-t", "-f", "{}"},
			Service: "sshd", ServiceAction: "reload",
			Mode: 0644,
		},
	}
}

func validateFiles(files []File) error {
	seen := map[string]bool{}
	for _, f := range files {
		if f.Name == "" || f.Path == "" {
			return fmt.Errorf("config: file needs a name and path: %+v", f)
		}
		if seen[f.Name] {
			return fmt.Errorf("config: duplicate file name %q", f.Name)
		}
		seen[f.Name] = true
		if f.isPattern() {
			if strings.Count(f.Name, "*") != 1 || strings.Count(f.Path, "*") != 1 {
				return fmt.Errorf("config: pattern %s needs one * in its name and path", f.Name)
			}
			if _, err := regexp.Compile(f.Match); err != nil {
				return fmt.Errorf("config: pattern %s: %w", f.Name, err)
			}
			if f.Confirm {
				return fmt.Errorf("config: pattern %s can't be confirmable", f.Name)
			}
		} else if strings.Contains(f.Name, "*") {
			return fmt.Errorf("config: %s has a * but no Match", f.Name)
		}
		if f.Confirm && !slices.Contains(f.Apply, "{}") {
			return fmt.Errorf("config: %s needs an Apply command that takes {} to be confirmable", f.Name)
		}
		if f.Service != "" && f.ServiceAction != "reload" && f.ServiceAction != "restart" {
			return fmt.Errorf("config: %s has invalid service action %q", f.Name, f.ServiceAction)
		}
	}
	return nil
}

func subst(argv []string, path string) []string {
	out := make([]string, len(argv))
	for i, a := range argv {
		if a == "{}" {
			a = path
		}
		out[i] = a
	}
	return out
}
