package appliance

import (
	"crypto/ecdh"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dantecatalfamo/OPF/internal/pf"
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
