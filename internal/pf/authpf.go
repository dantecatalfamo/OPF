package pf

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// Sign-in access (authpf(8)): network access that opens while someone
// is signed in over SSH and closes when they sign out. Each user is a
// system account whose shell is authpf; signing in loads the rules for
// them, with $user_ip their address, into the anchor
// "authpf/<user>(<pid>)" and puts the address in <authpf_users>;
// signing out takes both out again and ends every connection from
// that address.
//
// OPF writes /etc/authpf (the settings, the rules for everyone and for
// each user with rules of their own, who may sign in, who's banned and
// why, the message shown, each user's SSH keys), an sshd_config block
// for the authpf group (keys only, no tunnels, sessions that stop
// answering ended within a minute), and pf.conf's anchor, table and the
// SSH pass on the networks users sign in from. The accounts themselves
// are the appliance's (authpfaccounts.go).

// Authpf is sign-in access; nil, or not Enabled, there's none.
type Authpf struct {
	Enabled bool `json:"enabled"`
	// SignIn are the interfaces users sign in on: SSH to the firewall's
	// address there is let in.
	SignIn []string `json:"signIn"`
	// Message is shown once a user is signed in (authpf.message).
	Message string       `json:"message,omitempty"`
	Users   []AuthpfUser `json:"users"`
}

// AuthpfUser is one person who can sign in.
type AuthpfUser struct {
	ID string `json:"id"`
	// Name is their login, a system account OPF makes and removes.
	Name        string `json:"name"`
	Description string `json:"description"`
	// Keys are their SSH public keys, one per entry ("ssh-ed25519 AAAA…
	// comment"). Signing in takes a key; there's no password.
	Keys []string `json:"keys"`
	// Banned, when set, is the message they see instead of access
	// (authpf's banned/<name>).
	Banned string `json:"banned,omitempty"`
}

// RuleAuthpf marks a rule as one for signed-in users: it's loaded when
// one signs in, from authpf's rules, not from pf.conf. Users are the
// AuthpfUser ids it's for; none is everyone.
type RuleAuthpf struct {
	Users []string `json:"users,omitempty"`
}

const (
	// AuthpfDir is authpf's directory.
	AuthpfDir = "/etc/authpf"
	// AuthpfConfPath must exist for authpf to run at all.
	AuthpfConfPath    = AuthpfDir + "/authpf.conf"
	AuthpfRulesPath   = AuthpfDir + "/authpf.rules"
	AuthpfAllowPath   = AuthpfDir + "/authpf.allow"
	AuthpfMessagePath = AuthpfDir + "/authpf.message"
	// AuthpfUsersTable is the table of signed-in addresses (authpf's
	// default name).
	AuthpfUsersTable = "authpf_users"
	// AuthpfAnchor is the anchor authpf loads each session's rules into.
	AuthpfAnchor = "authpf"
	// AuthpfGroup is the group OPF's sign-in accounts are in; sshd's
	// block for them matches it.
	AuthpfGroup = "authpf"
	// AuthpfShell is their login shell.
	AuthpfShell = "/usr/sbin/authpf"
	// AuthpfAccountMark starts the comment (GECOS) of every account OPF
	// made for sign-in access; OPF never touches an account without it.
	AuthpfAccountMark = "OPF sign-in"
	// AuthpfSSHPort is the port users sign in on.
	AuthpfSSHPort = 22
)

// AuthpfUserRulesPath is a user's own rules: everyone's and theirs.
func AuthpfUserRulesPath(name string) string { return AuthpfDir + "/users/" + name + "/authpf.rules" }

// AuthpfBannedPath is a banned user's message.
func AuthpfBannedPath(name string) string { return AuthpfDir + "/banned/" + name }

// AuthpfKeysPath is a user's SSH public keys (sshd's AuthorizedKeysFile
// for the group), root's, so no user can change them.
func AuthpfKeysPath(name string) string { return AuthpfDir + "/keys/" + name }

// AuthpfOn is whether sign-in access is set up.
func AuthpfOn(m *Model) bool { return m.Firewall.Authpf != nil && m.Firewall.Authpf.Enabled }

// IsAuthpf is whether a rule is for signed-in users.
func (r *Rule) IsAuthpf() bool { return r.Authpf != nil }

// AuthpfNameRE is what a sign-in login may be: as OPF's other accounts.
var AuthpfNameRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}$`)

// authpfReserved are logins no sign-in account may take: the base
// system's and anything shaped like a daemon's.
var authpfReserved = []string{"root", "daemon", "operator", "bin", "build", "sshd", "nobody", "www", "named", "proxy", "authpf", "admin", "opf"}

// authpfRulesFor is the rules a user's session loads: everyone's, then
// the user's own. A nil user is everyone's alone.
func authpfRulesFor(m *Model, u *AuthpfUser) []Rule {
	var out []Rule
	for _, r := range m.Firewall.Rules {
		if !r.Enabled || !r.IsAuthpf() {
			continue
		}
		if len(r.Authpf.Users) == 0 || (u != nil && slices.Contains(r.Authpf.Users, u.ID)) {
			out = append(out, r)
		}
	}
	return out
}

// hasOwnRules is whether a user has rules of their own, and so a rules
// file of their own (authpf reads only the first file it finds).
func hasOwnRules(m *Model, u *AuthpfUser) bool {
	for _, r := range m.Firewall.Rules {
		if r.IsAuthpf() && slices.Contains(r.Authpf.Users, u.ID) {
			return true
		}
	}
	return false
}

// GenerateAuthpfRules is a session's rules file. pf loads it into the
// session's own anchor, where pf.conf's macros aren't defined, so it
// defines the interfaces' itself; tables are pf.conf's (an anchor that
// names a table it doesn't define uses the main ruleset's).
func GenerateAuthpfRules(m *Model, u *AuthpfUser) string {
	var b strings.Builder
	b.WriteString(header + "\n")
	if u != nil {
		fmt.Fprintf(&b, "# Loaded for %s while signed in: everyone's rules, then theirs.\n", u.Name)
	} else {
		b.WriteString("# Loaded for each signed-in user, with $user_ip their address.\n")
	}
	for _, i := range m.Interfaces {
		fmt.Fprintf(&b, "%s = \"%s\"\n", i.ID, i.Device)
	}
	for _, r := range authpfRulesFor(m, u) {
		if r.Description != "" {
			b.WriteString("# " + r.Description + "\n")
		}
		b.WriteString(GenerateRule(&r, m) + "\n")
	}
	return b.String()
}

// authpfFiles are the files sign-in access needs; none when it's off.
func authpfFiles(m *Model) []GeneratedFile {
	if !AuthpfOn(m) {
		return nil
	}
	a := m.Firewall.Authpf
	files := []GeneratedFile{
		// Empty is every default: the anchor "authpf", the table
		// "authpf_users". authpf reads name=value lines only.
		{Path: AuthpfConfPath, Content: ""},
		{Path: AuthpfRulesPath, Content: GenerateAuthpfRules(m, nil)},
	}
	// Only OPF's users may use authpf, whatever other account has it as
	// its shell.
	var allow strings.Builder
	for _, u := range a.Users {
		allow.WriteString(u.Name + "\n")
	}
	files = append(files, GeneratedFile{Path: AuthpfAllowPath, Content: allow.String()})
	if strings.TrimSpace(a.Message) != "" {
		files = append(files, GeneratedFile{Path: AuthpfMessagePath, Content: strings.TrimRight(a.Message, "\n") + "\n"})
	}
	for i := range a.Users {
		u := &a.Users[i]
		if hasOwnRules(m, u) {
			files = append(files, GeneratedFile{Path: AuthpfUserRulesPath(u.Name), Content: GenerateAuthpfRules(m, u)})
		}
		if u.Banned != "" {
			files = append(files, GeneratedFile{Path: AuthpfBannedPath(u.Name), Content: strings.TrimRight(u.Banned, "\n") + "\n"})
		}
		var keys strings.Builder
		for _, k := range u.Keys {
			keys.WriteString(strings.TrimSpace(k) + "\n")
		}
		files = append(files, GeneratedFile{Path: AuthpfKeysPath(u.Name), Content: keys.String()})
	}
	return files
}

// authpfPf is pf.conf's part: the table of signed-in addresses, SSH in
// on the networks users sign in from, and the anchor each session's
// rules are loaded into. Before the port forwards and every user rule,
// so a session's rules are reached; after the defaults and the WAN's
// protections, which a session doesn't get past.
func authpfPf(m *Model) (table string, lines []string) {
	if !AuthpfOn(m) {
		return "", nil
	}
	table = fmt.Sprintf("table <%s> persist", AuthpfUsersTable)
	for _, id := range m.Firewall.Authpf.SignIn {
		if i := ifaceByID(m, id); i != nil {
			lines = append(lines, fmt.Sprintf("pass in quick on $%s proto tcp to %s port %d%s", i.ID, endpoint(ifaceAddr(i.ID), m), AuthpfSSHPort, label(LabelAuthpf, i.ID)))
		}
	}
	lines = append(lines, fmt.Sprintf("anchor \"%s/*\"", AuthpfAnchor))
	return table, lines
}

func ifaceByID(m *Model, id string) *Iface {
	for i := range m.Interfaces {
		if m.Interfaces[i].ID == id {
			return &m.Interfaces[i]
		}
	}
	return nil
}

// ---------- sshd_config ----------

// sshd_config is the admin's; OPF adds one block at its end, between
// these lines, for the sign-in accounts. It ends with "Match all", so
// whatever is added after it is everyone's again, as it would be
// without it.
// SshdPath is sshd's configuration.
const SshdPath = "/etc/ssh/sshd_config"

const (
	sshdBegin = "# Begin OPF: sign-in access (authpf). OPF rewrites what's between these lines."
	sshdEnd   = "# End OPF"
)

// SshdLines are OPF's block; none when sign-in access is off.
func SshdLines(m *Model) []string {
	if !AuthpfOn(m) {
		return nil
	}
	return []string{
		sshdBegin,
		"Match Group " + AuthpfGroup,
		"\tAuthorizedKeysFile " + AuthpfDir + "/keys/%u",
		"\tAuthenticationMethods publickey",
		"\tAllowTcpForwarding no",
		"\tAllowStreamLocalForwarding no",
		"\tAllowAgentForwarding no",
		"\tPermitTunnel no",
		"\tX11Forwarding no",
		"\tPermitUserRC no",
		// A session that stops answering, or is hijacked, ends within
		// a minute (authpf(8)).
		"\tClientAliveInterval 15",
		"\tClientAliveCountMax 3",
		"Match all",
		sshdEnd,
	}
}

// MergeSshdConfig returns sshd_config with OPF's block as the model has
// it: the old block is taken out wherever it is, the new one goes at the
// end.
func MergeSshdConfig(existing string, m *Model) string {
	block := SshdLines(m)
	if len(block) == 0 && !strings.Contains(existing, sshdBegin) {
		return existing // nothing of OPF's to add or take out
	}
	var kept []string
	in := false
	for _, line := range strings.Split(strings.TrimSuffix(existing, "\n"), "\n") {
		switch {
		case strings.TrimSpace(line) == sshdBegin:
			in = true
		case in && strings.TrimSpace(line) == sshdEnd:
			in = false
		case !in:
			kept = append(kept, line)
		}
	}
	for len(kept) > 0 && strings.TrimSpace(kept[len(kept)-1]) == "" {
		kept = kept[:len(kept)-1]
	}
	if len(block) > 0 {
		kept = append(kept, "")
		kept = append(kept, block...)
	}
	if len(kept) == 0 {
		return ""
	}
	return strings.Join(kept, "\n") + "\n"
}

// SshdValues are OPF's lines in sshd_config, for telling whether
// someone changed them.
func SshdValues(content string) []string {
	var out []string
	in := false
	for _, line := range strings.Split(content, "\n") {
		t := strings.TrimSpace(line)
		switch {
		case t == sshdBegin:
			in = true
		case t == sshdEnd:
			in = false
		case in:
			out = append(out, strings.Join(strings.Fields(t), " "))
		}
	}
	return out
}

// ---------- SSH public keys ----------

var sshKeyTypes = []string{
	"ssh-ed25519", "sk-ssh-ed25519@openssh.com",
	"ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "sk-ecdsa-sha2-nistp256@openssh.com",
	"ssh-rsa",
}

// checkSSHKey says what's wrong with an authorized key line, if
// anything: a key type, its base64 blob (which must say the same type),
// and an optional comment. No options (command=, from=...): access is
// pf's to give, and an option could turn a key into something else.
func checkSSHKey(line string) string {
	f := strings.Fields(line)
	if len(f) < 2 {
		return "a key is its type and its key, such as \"ssh-ed25519 AAAA…\""
	}
	if !slices.Contains(sshKeyTypes, f[0]) {
		return fmt.Sprintf("%q isn't a key type SSH takes (ssh-ed25519, ecdsa-sha2-…, ssh-rsa); options before the key aren't allowed", printable(f[0], 40))
	}
	blob, err := base64.StdEncoding.DecodeString(f[1])
	if err != nil || len(blob) < 4 {
		return "the key isn't base64"
	}
	n := binary.BigEndian.Uint32(blob)
	if int(n) > len(blob)-4 || string(blob[4:4+n]) != f[0] {
		return "the key isn't a " + f[0] + " key"
	}
	for _, r := range line {
		if r < 0x20 || r == 0x7f {
			return "the key has a control character"
		}
	}
	return ""
}

func printable(s string, n int) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= n {
			b.WriteString("…")
			break
		}
		if r < 0x20 || r == 0x7f {
			r = '?'
		}
		b.WriteRune(r)
	}
	return b.String()
}
