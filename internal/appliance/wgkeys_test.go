package appliance

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dantecatalfamo/OPF/internal/pf"
	"github.com/dantecatalfamo/OPF/internal/sysinfo"
)

func TestTunnelKeys(t *testing.T) {
	e := newEnv(t, time.Minute)
	pub, err := e.m.NewTunnelKey()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(e.root, pf.WGKeyPath(pub))
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("key file %v %v", st, err)
	}
	// The kept key is the one the public key is for.
	data, _ := os.ReadFile(path)
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	k, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil || base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()) != pub {
		t.Fatalf("the private key doesn't make the public key: %v", err)
	}

	// A device's pair is made and kept nowhere.
	dk, err := e.m.NewDeviceKey()
	if err != nil || dk.PrivateKey == "" || dk.PublicKey == "" {
		t.Fatal(dk, err)
	}
	if _, err := os.Stat(filepath.Join(e.root, pf.WGKeyPath(dk.PublicKey))); err == nil {
		t.Error("a device's key was kept")
	}

	// A tunnel with a key OPF didn't make can't be staged; with its own,
	// it can, and hostname.wg0 reads the key from its file.
	m := e.live().Model
	wg := m.Interfaces[3].WireGuard
	wg.PublicKey = dk.PublicKey
	if _, err := e.m.Stage(StageRequest{Base: e.live().Version, Model: m}); code(err) != CodeInvalid || !strings.Contains(err.Error(), "private key") {
		t.Errorf("staged an unknown key: %v", err)
	}
	wg.PublicKey = pub
	st2, err := e.m.Stage(StageRequest{Base: e.live().Version, Model: m})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range st2.Changes {
		if strings.HasSuffix(c.Path, "hostname.wg0") {
			found = strings.Contains(c.Diff, `!ifconfig $if wgkey "$(cat `+pf.WGKeyPath(pub)+`)"`)
			if strings.Contains(c.Diff, strings.TrimSpace(string(data))) {
				t.Error("the private key is in the diff")
			}
		}
	}
	if !found {
		t.Errorf("hostname.wg0 doesn't read the key: %+v", st2.Changes)
	}

	// Once the tunnel's gone for good, so is its key.
	e.m.Discard()
	m = e.live().Model
	m.Interfaces[3].WireGuard.PublicKey = pub
	if err := stageCommit(t, e, m); err != nil {
		t.Fatal(err)
	}
	m = e.live().Model
	m.Interfaces = append(m.Interfaces[:3], m.Interfaces[4:]...)
	m.Firewall.Rules = slicesFilter(m.Firewall.Rules, func(r pf.Rule) bool {
		return !strings.Contains(strings.Join(r.Interfaces, ","), "wg") || strings.Contains(strings.Join(r.Interfaces, ","), "wg1")
	})
	if err := stageCommit(t, e, m); err != nil {
		t.Logf("removing the tunnel didn't stage (%v); checking pruning by hand", err)
		return
	}
	e.m.pruneDownloads()
	if _, err := os.Stat(path); err == nil {
		t.Error("the removed tunnel's key is still there")
	}
}

func slicesFilter[T any](s []T, keep func(T) bool) []T {
	var out []T
	for _, x := range s {
		if keep(x) {
			out = append(out, x)
		}
	}
	return out
}

func TestPresharedKeys(t *testing.T) {
	e := newEnv(t, time.Minute)
	m := e.live().Model
	tun := &m.Interfaces[3]
	peer := tun.WireGuard.Peers[0]
	if _, err := e.m.SetPresharedKey(PresharedKeyRequest{Key: "short"}); code(err) != CodeInvalid {
		t.Errorf("a bad key: %v", err)
	}
	made, err := e.m.SetPresharedKey(PresharedKeyRequest{})
	if b, _ := base64.StdEncoding.DecodeString(made.Key); err != nil || len(b) != 32 {
		t.Fatalf("%+v %v", made, err)
	}
	path := filepath.Join(e.root, pf.WGPSKPath(made.ID))
	if st, err := os.Stat(path); err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("%v %v", st, err)
	}
	// One given is kept as it is, in a file of its own: the first stays,
	// for a revert to find.
	given := base64.StdEncoding.EncodeToString(make([]byte, 32))
	kept, err := e.m.SetPresharedKey(PresharedKeyRequest{Key: given})
	if err != nil || kept.Key != given || kept.ID == made.ID {
		t.Fatalf("%+v %v", kept, err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Error("a new key replaced the old one's file")
	}

	// A device naming one stages when the key's here, and hostname.wgN
	// reads it from its file; the key's never in the diff.
	tun.WireGuard.Peers[0].PresharedKey = kept.ID
	st, err := e.m.Stage(StageRequest{Base: e.live().Version, Model: m})
	if err != nil {
		t.Fatal(err)
	}
	ok := false
	for _, c := range st.Changes {
		if strings.HasSuffix(c.Path, "hostname."+tun.Device) {
			ok = strings.Contains(c.Diff, `!ifconfig $if wgpeer `+peer.PublicKey+` wgpsk "$(cat `+pf.WGPSKPath(kept.ID)+`)"`) && !strings.Contains(c.Diff, given)
		}
	}
	if !ok {
		t.Errorf("hostname.%s: %+v", tun.Device, st.Changes)
	}
	e.m.Discard()
	// One that isn't here, and an id that could name another path.
	for _, id := range []string{"00000000000000aa", "../../etc/passwd"} {
		tun.WireGuard.Peers[0].PresharedKey = id
		if _, err := e.m.Stage(StageRequest{Base: e.live().Version, Model: m}); code(err) != CodeInvalid {
			t.Errorf("staged preshared key %q: %v", id, err)
		}
	}
}

func TestLastSeen(t *testing.T) {
	e := newEnv(t, time.Minute)
	peer := e.live().Model.Interfaces[3].WireGuard.Peers[0]
	at := time.Now().Add(-90 * time.Minute).Truncate(time.Second)
	e.m.eventLog().sawDevice(peer.ID, at, "198.51.100.7")
	// Remembered across a restart.
	if err := e.m.saveEvents(); err != nil {
		t.Fatal(err)
	}
	m2, _ := New(e.m.store)
	m2.loadEvents()
	s, ok := m2.eventLog().device(peer.ID)
	if !ok || !s.At.Equal(at) || s.From != "198.51.100.7" {
		t.Fatalf("after loading: %+v %v", s, ok)
	}
	// An older handshake doesn't replace it; a newer one does.
	m2.eventLog().sawDevice(peer.ID, at.Add(-time.Hour), "203.0.113.1")
	if s, _ := m2.eventLog().device(peer.ID); !s.At.Equal(at) {
		t.Errorf("an older handshake replaced it: %+v", s)
	}
	// The interface reloaded and forgot: the status still says when.
	ifs := []InterfaceState{{Interface: sysinfo.Interface{Name: "wg0", WireGuard: &sysinfo.WireGuard{Peers: []sysinfo.WGPeer{{PublicKey: peer.PublicKey}}}}}}
	m2.addLastSeen(ifs)
	p := ifs[0].WireGuard.Peers[0]
	if p.LastSeen == nil || !p.LastSeen.Equal(at) || p.LastFrom != "198.51.100.7" {
		t.Errorf("status %+v", p)
	}
}

// A provider's private key is kept like one OPF made, and a way out
// using it stages; something that isn't a key is refused.
func TestImportTunnelKey(t *testing.T) {
	e := newEnv(t, time.Minute)
	k, _ := ecdh.X25519().GenerateKey(rand.Reader)
	want := base64.StdEncoding.EncodeToString(k.PublicKey().Bytes())
	pub, err := e.m.ImportTunnelKey(" " + base64.StdEncoding.EncodeToString(k.Bytes()) + "\n")
	if err != nil || pub != want {
		t.Fatalf("import = %q, %v; want %q", pub, err, want)
	}
	st, err := os.Stat(filepath.Join(e.root, pf.WGKeyPath(pub)))
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("key file %v %v", st, err)
	}
	for _, bad := range []string{"", "not a key", base64.StdEncoding.EncodeToString(make([]byte, 31))} {
		if _, err := e.m.ImportTunnelKey(bad); code(err) != CodeInvalid {
			t.Errorf("%q: %v", bad, err)
		}
	}

	live := e.live()
	m := live.Model
	prefix := 32
	m.Interfaces = append(m.Interfaces, pf.Iface{ID: "vpnout", Name: "Provider", Device: "wg2", Role: pf.RoleVPN, Enabled: true,
		IPv4: pf.IPv4Config{Mode: pf.IPv4Static, Address: "10.64.1.2", Prefix: &prefix}, IPv6: pf.IPv6None,
		WireGuard: &pf.WireGuard{PublicKey: pub, Peers: []pf.Peer{}, Exit: &pf.Exit{
			PublicKey: want, Endpoint: "vpn.example.net:51820", From: []string{"iot"},
		}}})
	if _, err := e.m.Stage(StageRequest{Base: live.Version, Model: m}); err != nil {
		t.Fatalf("stage: %v %+v", err, AsError(err).Details)
	}
}
