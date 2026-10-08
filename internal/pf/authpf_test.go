package pf

import (
	"fmt"
	"strings"
	"testing"
)

const testKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINQ9WEF+N8iMv6e+NjdG7K1KLPDKQtTuFwr+0w8Y435m test@example"

// withAuthpf is the sample with sign-in access on the IoT network: two
// users, one banned, a rule for everyone and one for alice alone.
func withAuthpf(t *testing.T) *Model {
	t.Helper()
	m, _ := loadSampleModel(t)
	m.Firewall.Authpf = &Authpf{
		Enabled: true,
		SignIn:  []string{"iot"},
		Message: "You're signed in.\nPlay nice.",
		Users: []AuthpfUser{
			{ID: "u1", Name: "alice", Description: "Contractor", Keys: []string{testKey}},
			{ID: "u2", Name: "bob", Keys: []string{testKey}, Banned: "Ask the office."},
		},
	}
	m.Firewall.Rules = append(m.Firewall.Rules,
		Rule{ID: "ra1", Kind: "form", Enabled: true, Action: ActionPass, Direction: DirectionIn, Quick: true, Family: FamilyInet, Protocol: ProtoAny,
			Interfaces: []string{"iot"}, Source: Endpoint{Type: EndpointAuthpfUser}, Destination: Endpoint{Type: EndpointAny}, Log: LogOff, Description: "Signed-in users out", Authpf: &RuleAuthpf{}},
		Rule{ID: "ra2", Kind: "form", Enabled: true, Action: ActionPass, Direction: DirectionIn, Quick: true, Family: FamilyInet, Protocol: ProtoTCP, Port: "445",
			Interfaces: []string{"iot"}, Source: Endpoint{Type: EndpointAuthpfUser}, Destination: Endpoint{Type: EndpointHost, Value: "192.168.1.20"}, Log: LogOff, Description: "Alice to the file server", Authpf: &RuleAuthpf{Users: []string{"u1"}}},
	)
	return m
}

func files(m *Model) map[string]string {
	out := map[string]string{}
	for _, f := range GenerateFiles(m) {
		out[f.Path] = f.Content
	}
	return out
}

func TestAuthpfFiles(t *testing.T) {
	m := withAuthpf(t)
	if errs := Validate(m); len(errs) != 0 {
		t.Fatalf("invalid: %v", errs)
	}
	f := files(m)
	if c, ok := f[AuthpfConfPath]; !ok || c != "anchor=authpf\ntable=authpf_users\n" {
		t.Errorf("authpf.conf %q %v", c, ok)
	}
	everyone := f[AuthpfRulesPath]
	for _, want := range []string{`iot = "vlan20"`, "pass in quick on $iot inet from $user_ip to any", `label "opf:rule:ra1"`} {
		if !strings.Contains(everyone, want) {
			t.Errorf("authpf.rules lacks %q:\n%s", want, everyone)
		}
	}
	if strings.Contains(everyone, "445") {
		t.Errorf("alice's rule is everyone's:\n%s", everyone)
	}
	// Alice has a file of her own, with everyone's rules too; bob doesn't.
	alice := f[AuthpfUserRulesPath("alice")]
	if !strings.Contains(alice, "opf:rule:ra1") || !strings.Contains(alice, "port 445") {
		t.Errorf("alice's rules:\n%s", alice)
	}
	if _, ok := f[AuthpfUserRulesPath("bob")]; ok {
		t.Error("bob has rules of his own")
	}
	if f[AuthpfAllowPath] != "alice\nbob\n" || f[AuthpfBannedPath("bob")] != "Ask the office.\n" || f[AuthpfMessagePath] != "You're signed in.\nPlay nice.\n" {
		t.Errorf("allow %q banned %q message %q", f[AuthpfAllowPath], f[AuthpfBannedPath("bob")], f[AuthpfMessagePath])
	}
	if f[AuthpfKeysPath("alice")] != testKey+"\n" {
		t.Errorf("alice's keys %q", f[AuthpfKeysPath("alice")])
	}

	// pf.conf: the table, SSH in on the IoT network and the anchor, after
	// the defaults and before the port forwards and every user rule;
	// never the rules for signed-in users.
	conf := f["/etc/pf.conf"]
	table := strings.Index(conf, "table <authpf_users> persist")
	ssh := strings.Index(conf, `pass in quick on $iot proto tcp to ($iot) port 22 label "opf:authpf:iot"`)
	anchor := strings.Index(conf, `anchor "authpf/*"`)
	defaults := strings.Index(conf, "# Defaults")
	forwards := strings.Index(conf, "# Port forwards")
	if table < 0 || ssh < 0 || anchor < 0 || !(defaults < ssh && ssh < anchor && anchor < forwards) {
		t.Errorf("table %d ssh %d anchor %d defaults %d forwards %d:\n%s", table, ssh, anchor, defaults, forwards, conf)
	}
	if strings.Contains(conf, "$user_ip") || strings.Contains(conf, "opf:rule:ra1") {
		t.Errorf("a rule for signed-in users is in pf.conf")
	}
	if kind, id, ok := ParseLabel("opf:authpf:iot"); !ok || kind != LabelAuthpf || id != "iot" {
		t.Errorf("label %q %q %v", kind, id, ok)
	}

	// Off: none of it.
	m.Firewall.Authpf.Enabled = false
	m.Firewall.Rules = m.Firewall.Rules[:len(m.Firewall.Rules)-2]
	f = files(m)
	for p := range f {
		if strings.HasPrefix(p, AuthpfDir) {
			t.Errorf("%s with sign-in access off", p)
		}
	}
	if strings.Contains(f["/etc/pf.conf"], "authpf") {
		t.Error("pf.conf mentions authpf with it off")
	}
}

func TestMergeSshdConfig(t *testing.T) {
	stock := "AuthorizedKeysFile\t.ssh/authorized_keys\nSubsystem\tsftp\t/usr/libexec/sftp-server\n\n"
	m := withAuthpf(t)
	merged := MergeSshdConfig(stock, m)
	if !strings.HasPrefix(merged, "AuthorizedKeysFile\t.ssh/authorized_keys\nSubsystem\tsftp\t/usr/libexec/sftp-server\n\n"+sshdBegin+"\nMatch Group authpf\n") {
		t.Errorf("merged:\n%s", merged)
	}
	for _, want := range []string{"\tAuthenticationMethods publickey\n", "\tAuthorizedKeysFile /etc/authpf/keys/%u\n", "\tAllowTcpForwarding no\n", "\tClientAliveInterval 15\n", "Match all\n" + sshdEnd + "\n"} {
		if !strings.Contains(merged, want) {
			t.Errorf("merged lacks %q", want)
		}
	}
	// Again: the same. The admin's lines after OPF's block stay theirs.
	if again := MergeSshdConfig(merged, m); again != merged {
		t.Errorf("not idempotent:\n%s", again)
	}
	theirs := merged + "PermitRootLogin no\n"
	if got := MergeSshdConfig(theirs, m); !strings.Contains(got, "PermitRootLogin no\n\n"+sshdBegin) {
		t.Errorf("the admin's line after the block:\n%s", got)
	}
	// Off: the block goes, the rest stays; a file without one is left as
	// it is, blank lines and all.
	m.Firewall.Authpf.Enabled = false
	if got := MergeSshdConfig(merged, m); got != strings.TrimRight(stock, "\n")+"\n" {
		t.Errorf("block taken out:\n%q", got)
	}
	if got := MergeSshdConfig(stock, m); got != stock {
		t.Errorf("untouched file changed: %q", got)
	}
	if v := SshdValues(merged); len(v) == 0 || v[0] != "Match Group authpf" {
		t.Errorf("values %v", v)
	}
}

func TestValidateAuthpf(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(m *Model)
		path string
	}{
		{"no networks to sign in from", func(m *Model) { m.Firewall.Authpf.SignIn = nil }, "firewall.authpf.signIn"},
		{"an unknown network", func(m *Model) { m.Firewall.Authpf.SignIn = []string{"nope"} }, "firewall.authpf.signIn[0]"},
		{"a system login", func(m *Model) { m.Firewall.Authpf.Users[0].Name = "root" }, "firewall.authpf.users[0].name"},
		{"an uppercase login", func(m *Model) { m.Firewall.Authpf.Users[0].Name = "Alice" }, "firewall.authpf.users[0].name"},
		{"a login twice", func(m *Model) { m.Firewall.Authpf.Users[1].Name = "alice" }, "firewall.authpf.users[1].name"},
		{"no key", func(m *Model) { m.Firewall.Authpf.Users[0].Keys = nil }, "firewall.authpf.users[0].keys"},
		{"a key with options", func(m *Model) { m.Firewall.Authpf.Users[0].Keys = []string{`command="/bin/sh" ` + testKey} }, "firewall.authpf.users[0].keys[0]"},
		{"a key of the wrong type", func(m *Model) {
			m.Firewall.Authpf.Users[0].Keys = []string{strings.Replace(testKey, "ssh-ed25519", "ssh-rsa", 1)}
		}, "firewall.authpf.users[0].keys[0]"},
		{"a key that isn't base64", func(m *Model) { m.Firewall.Authpf.Users[0].Keys = []string{"ssh-ed25519 not*base64"} }, "firewall.authpf.users[0].keys[0]"},
		{"a key with a newline", func(m *Model) { m.Firewall.Authpf.Users[0].Keys = []string{testKey + "\nssh-ed25519 AAAA"} }, "firewall.authpf.users[0].keys[0]"},
		{"a control character in a message", func(m *Model) { m.Firewall.Authpf.Message = "hi\x1b[2J" }, "firewall.authpf.message"},
		{"the signed-in user in a plain rule", func(m *Model) {
			m.Firewall.Rules[len(m.Firewall.Rules)-1].Authpf = nil
		}, fmt.Sprintf("firewall.rules[%d]", len(withAuthpf(t).Firewall.Rules)-1) + ".source.type"},
		{"a rule for an unknown user", func(m *Model) {
			m.Firewall.Rules[len(m.Firewall.Rules)-1].Authpf.Users = []string{"u9"}
		}, fmt.Sprintf("firewall.rules[%d]", len(withAuthpf(t).Firewall.Rules)-1) + ".authpf.users[0]"},
		{"a rule not about the user", func(m *Model) {
			m.Firewall.Rules[len(m.Firewall.Rules)-1].Source = Endpoint{Type: EndpointAny}
		}, fmt.Sprintf("firewall.rules[%d]", len(withAuthpf(t).Firewall.Rules)-1) + ".source"},
		{"an alias called authpf_users", func(m *Model) { m.Firewall.Aliases[0].Name = AuthpfUsersTable }, "firewall.aliases[0].name"},
	} {
		m := withAuthpf(t)
		tc.edit(m)
		if !slicesContainsPath(Validate(m), tc.path) {
			t.Errorf("%s: no error at %s: %v", tc.name, tc.path, Validate(m))
		}
	}
	// Every signed-in user, in a plain rule: only with sign-in access on.
	m := withAuthpf(t)
	m.Firewall.Rules[0].Source = Endpoint{Type: EndpointAuthpfUsers}
	if errs := Validate(m); len(errs) != 0 {
		t.Errorf("<authpf_users> in a rule: %v", errs)
	}
	if got := GenerateRule(&m.Firewall.Rules[0], m); !strings.Contains(got, "from <authpf_users>") {
		t.Errorf("rendered %q", got)
	}
	m.Firewall.Authpf.Enabled = false
	m.Firewall.Rules = m.Firewall.Rules[:len(m.Firewall.Rules)-2]
	if !slicesContainsPath(Validate(m), "firewall.rules[0].source.type") {
		t.Error("<authpf_users> with sign-in access off")
	}
}
