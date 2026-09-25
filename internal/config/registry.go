package config

import (
	"fmt"
	"io/fs"
	"slices"
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
}

// DefaultFiles are the files managed on a stock OpenBSD system, in the
// order they are applied during a commit.
func DefaultFiles() []File {
	return []File{
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
