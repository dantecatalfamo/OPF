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
	// with the path of the file to check, "{staged}" with the directory
	// staged files are in (each at its own path under it) and "{root}"
	// with the prefix of live paths ("" in production), for a checker
	// that reads other files the commit may be adding. Nil means no
	// checker exists.
	Check []string

	// Apply activates a file. "{}" is replaced with the path to load,
	// which for Confirm files is the staged copy rather than Path.
	Apply []string

	// Remove undoes what a file set up, after a commit removes it (or a
	// revert removes one the commit created): "{}" is a copy of what the
	// file held, and "{*}" works as for Apply. Nil means
	// removing the file is enough (it's only read at boot, say).
	Remove []string

	// ApplyWhenRemoved runs Apply even when reverting a commit removes
	// the file (it didn't exist before), with "{}" naming the missing
	// path; for files whose absence means something, like
	// rc.conf.local's defaults.
	ApplyWhenRemoved bool

	// Service, if set, is reloaded or restarted with rcctl after the
	// file changes, but only when it is already running. A commit (or a
	// revert) does this once per service, after its last changed file is
	// in place.
	Service       string
	ServiceAction string // "reload" or "restart"

	// ReloadWith, for a Service file, is a cheaper way to make the
	// service take this file alone ("{}" is its path), such as reloading
	// one zone. It's used instead of ServiceAction when every file of the
	// service that changed has one; otherwise the service is reloaded or
	// restarted as usual, which takes them all.
	ReloadWith []string

	// RestartIf says whether a change, from before to after, is one the
	// service can't take with a reload, so it's restarted instead:
	// unbound reopens its log file when it reloads, but never goes back
	// to syslog from one.
	RestartIf func(before, after []byte) bool

	// Manages lists services this file's Apply brings in line itself,
	// starting, stopping or restarting them. When the file is part of a
	// commit or a revert, those services aren't also told about their
	// own files: rc.conf.local stops a daemon it disables, which can't
	// be restarted first with the configuration that disables it (an
	// empty dhcpd.conf).
	Manages []string

	// Confirm files are loaded from their staged copy without being
	// written to Path. Unless the commit is confirmed before the
	// timeout, the live file is loaded again. Because Path is untouched
	// until confirmation, a reboot also reverts the change.
	Confirm bool

	// ConfirmInstalled files make a commit wait for confirmation too,
	// for changes that can cut off access as much as pf.conf's, but
	// they're installed and applied straight away like any other file:
	// what applies them can only read Path (netstart reads
	// /etc/hostname.*). Unless the commit is confirmed in time, the old
	// file is put back and applied again. A reboot meanwhile starts with
	// the new file, and Recover reverts it when OPF starts.
	ConfirmInstalled bool

	// Mode is used when creating a file that doesn't exist yet.
	Mode fs.FileMode

	// Order, for a pattern entry, sorts its instances for applying:
	// lower first, by name within the same. Nil sorts by name.
	Order func(name string) int

	// Match makes this entry a pattern for a family of files: Name and
	// Path each contain one "*", and a file matches when the text in
	// its place matches this regular expression in full. "{*}" in Check
	// and Apply is replaced with that text. Lookup returns the concrete
	// file, e.g. hostname.em0 for hostname.*.
	Match string
}

func (f File) isPattern() bool { return f.Match != "" }

// NeedsConfirm reports whether committing f waits for confirmation.
func (f File) NeedsConfirm() bool { return f.Confirm || f.ConfirmInstalled }

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
	g.Remove = substPart(f.Remove, part)
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
// unboundOwnLog is in unbound.conf while unbound logs to a file of its
// own rather than syslog.
const unboundOwnLog = "\tuse-syslog: no\n"

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
			// hostname.if(5), one per interface. Applied first, since
			// pf rules refer to the interfaces. netstart reads /etc
			// directly, so these can't be loaded from a staged copy;
			// they're installed, and put back unless confirmed.
			Name: "hostname.*", Path: "/etc/hostname.*", Match: `[a-z]+[0-9]+`,
			Desc:             "Network interface",
			Apply:            []string{"sh", "-c", HostnameApply, "sh", "{*}"},
			ConfirmInstalled: true,
			Order:            netstartOrder,
			// Virtual interfaces (vlan, wg) are destroyed; a physical
			// port can't be, so it's taken down instead.
			Remove: []string{"sh", "-c", `ifconfig "$1" destroy 2>/dev/null || ifconfig "$1" down`, "sh", "{*}"},
			Mode:   0640, // may hold keys, e.g. wgkey
		},
		{
			// The default gateway, one address. netstart only ever adds
			// it (route add does nothing when there's a default route
			// already), so it's set here: after the interfaces, since it
			// may only be reachable through an address they just got.
			// A wrong one can cut off access from other networks, so it
			// waits for confirmation. Removing it deletes the default
			// route through that gateway, and no other: dhcpleased's
			// routes have the same priority. The model only writes it
			// when no interface uses DHCP, which is when netstart reads
			// it at boot.
			Name: "mygate", Path: "/etc/mygate",
			Desc:             "Default gateway",
			Apply:            []string{"sh", "-c", `gw=$(head -n 1 "$1") && { route -qn change -inet default "$gw" || route -qn add -inet default "$gw"; }`, "sh", "{}"},
			Remove:           []string{"sh", "-c", `gw=$(head -n 1 "$1") && route -qn delete -inet default "$gw" || :`, "sh", "{}"},
			ConfirmInstalled: true,
			Mode:             0644,
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
			// Before unbound.conf, so the zone it names is in place when
			// unbound reloads. unbound-checkconf doesn't read zone files;
			// the generator writes it from checked names.
			Name: "opf-own.rpz", Path: "/var/unbound/db/opf-own.rpz",
			Desc:    "DNS names you block or allow",
			Service: "unbound", ServiceAction: "reload",
			// Alone, just this zone: reloading unbound whole loads every
			// blocklist again (14 s with half a million names), and drops
			// the names DHCP leases have.
			ReloadWith: []string{"unbound-control", "-c", "/var/unbound/etc/unbound.conf", "auth_zone_reload", "opf-own."},
			Mode:       0644,
		},
		{
			Name: "unbound.conf", Path: "/var/unbound/etc/unbound.conf",
			Desc:    "Recursive DNS resolver",
			Check:   []string{"sh", "-c", UnboundCheck, "sh", "{}", "{staged}", "{root}"},
			Service: "unbound", ServiceAction: "reload",
			// Logging to its own file or to syslog (DNS activity).
			RestartIf: func(before, after []byte) bool {
				return strings.Contains(string(before), unboundOwnLog) != strings.Contains(string(after), unboundOwnLog)
			},
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
		{
			// Shared like rc.conf.local; OPF sets only its lines
			// (pf.SysctlNames), which this sets on the running system.
			// /etc/rc applies the file at boot. Gone (a revert of the
			// commit that made it), forwarding is off, OpenBSD's
			// default.
			// The firewall's own name, for its own programs; read at
			// every lookup, so nothing to apply.
			Name: "hosts", Path: "/etc/hosts",
			Desc: "The firewall's own name, for its own programs",
			Mode: 0644,
		},
		{
			Name: "sysctl.conf", Path: "/etc/sysctl.conf",
			Desc:             "Kernel settings: forwarding packets between interfaces",
			Apply:            []string{"sh", "-c", `v=$(sed -n 's/^[[:space:]]*net\.inet\.ip\.forwarding[[:space:]]*=[[:space:]]*\([0-9]*\).*/\1/p' "$1" 2>/dev/null | tail -n 1); sysctl net.inet.ip.forwarding="${v:-0}" >/dev/null`, "sh", "{}"},
			ApplyWhenRemoved: true,
			Mode:             0644,
		},
		{
			// After every service's configuration, so a service it
			// enables starts with its new configuration file.
			Name: "rc.conf.local", Path: "/etc/rc.conf.local",
			Desc:             "Enabled daemons and their flags",
			Check:            []string{"sh", "-n", "{}"},
			Apply:            []string{"sh", "-c", RcReconcile, "sh", "{}"},
			ApplyWhenRemoved: true,
			Manages:          RcServices,
			Mode:             0644,
		},
	}
}

// UnboundCheck runs unbound-checkconf on $1. unbound-checkconf opens the
// zone files a configuration names, and one this commit adds (your
// first blocked name's opf-own.rpz) isn't there yet, only staged under
// $2; so a copy that names the staged one is checked instead. $3 is
// the prefix of live paths.
var UnboundCheck = `conf=$1 staged=$2 root=$3
tmp=$(mktemp) || exit 1
trap 'rm -f "$tmp"' EXIT
while IFS= read -r line; do
	case $line in
	*zonefile:*)
		p=${line#*zonefile:}; p=${p#*\"}; p=${p%\"*}
		if [ ! -e "$root$p" ] && [ -e "$staged$p" ]; then
			line="	zonefile: \"$staged$p\""
		fi;;
	esac
	printf '%s\n' "$line"
done < "$conf" > "$tmp"
if cmp -s "$conf" "$tmp"; then
	exec unbound-checkconf "$conf"
fi
unbound-checkconf "$tmp"`

// netstartOrder is when netstart brings an interface up at boot, so a
// commit applies them the same way: physical ports first, then the
// interfaces built on them (aggregates, then VLANs, then carp and PPPoE),
// then tunnels, bridges and the rest. Not by name: a VLAN on vmx0 would
// come before its parent.
func netstartOrder(name string) int {
	switch strings.TrimRight(strings.TrimPrefix(name, "hostname."), "0123456789") {
	case "aggr", "trunk":
		return 1
	case "svlan", "vlan":
		return 2
	case "carp":
		return 3
	case "pppoe":
		return 4
	case "tun", "tap", "gif", "etherip", "gre", "egre", "nvgre", "eoip", "vxlan", "pflow", "wg", "bridge", "veb", "vport", "tpmr", "vether":
		return 5
	}
	return 0 // a physical port
}

// HostnameApply applies /etc/hostname.$1 with netstart. An interface
// that leaves DHCP or SLAAC for a fixed address keeps its AUTOCONF flag
// through netstart, and dhcpleased (or slaacd) keeps its lease; when
// the flag does go, it deletes the address and default route it set,
// even one now also set by hand. So autoconf the file doesn't ask for
// is turned off first, and the daemon given time to let go, before
// netstart sets what the file says.
var HostnameApply = `if=$1 f=/etc/hostname.$1
for af in inet inet6; do
	flag=AUTOCONF4; [ $af = inet6 ] && flag=AUTOCONF6
	if ifconfig "$if" 2>/dev/null | head -n 1 | grep -q "$flag" && ! grep -qx "$af autoconf" "$f" 2>/dev/null; then
		ifconfig "$if" $af -autoconf
		sleep 2
	fi
done
exec sh /etc/netstart "$if"`

// RcServices are the daemons whose rc.conf.local lines OPF writes
// (pf.GenerateRcConfLocal), and so the ones RcReconcile manages.
var RcServices = []string{"dhcpd", "unbound"}

// RcReconcile brings RcServices in line with an rc.conf.local, $1: a
// service it disables is stopped, one it enables is restarted if it's
// running (so new flags take effect) or started if not. It reads only
// those services' lines rather than sourcing the file, whose other
// lines aren't OPF's. The file may be gone after a revert, which leaves
// them all disabled, as they are by default. Any failure fails the
// commit, which is then reverted.
var RcReconcile = `set -e
if [ -f "$1" ]; then eval "$(grep -E '^[[:space:]]*(` + strings.Join(RcServices, "|") + `)_flags=' "$1" || true)"; fi
for s in ` + strings.Join(RcServices, " ") + `; do
	eval "f=\${${s}_flags-NO}"
	if [ "$f" = NO ]; then
		if rcctl check "$s" >/dev/null 2>&1; then rcctl stop "$s"; fi
	elif rcctl check "$s" >/dev/null 2>&1; then
		rcctl restart "$s"
	else
		rcctl start "$s"
	fi
done`

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
		if f.Confirm && f.ConfirmInstalled {
			return fmt.Errorf("config: %s can't be both Confirm and ConfirmInstalled", f.Name)
		}
		if f.Confirm && !slices.Contains(f.Apply, "{}") {
			return fmt.Errorf("config: %s needs an Apply command that takes {} to be confirmable", f.Name)
		}
		if f.Service != "" && f.ServiceAction != "reload" && f.ServiceAction != "restart" {
			return fmt.Errorf("config: %s has invalid service action %q", f.Name, f.ServiceAction)
		}
		if f.ReloadWith != nil && f.Service == "" {
			return fmt.Errorf("config: %s has ReloadWith but no Service", f.Name)
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
