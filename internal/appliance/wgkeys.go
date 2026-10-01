package appliance

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/dantecatalfamo/OPF/internal/pf"
)

// WireGuard keys. A tunnel's private key is made here and kept in a
// file only root can read (pf.WGKeyPath), which hostname.wgN reads when
// the interface comes up: it's never in the model, a generated file, a
// diff, history, or the web process. The model has only the public key.
// A device's key pair is made by the browser, so its private key never
// reaches the firewall; for a browser that can't, NewDeviceKey makes
// one and keeps nothing.

// DeviceKey is a key pair for a device, given once.
type DeviceKey struct {
	PrivateKey string `json:"privateKey"`
	PublicKey  string `json:"publicKey"`
}

func newKeyPair() (priv, pub string, err error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(k.Bytes()), base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()), nil
}

// NewTunnelKey makes a tunnel's key pair, keeps the private key, and
// returns the public one for the model.
func (m *Manager) NewTunnelKey() (string, error) {
	priv, pub, err := newKeyPair()
	if err != nil {
		return "", apiError(err)
	}
	path := m.store.SystemPath(pf.WGKeyPath(pub))
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return "", apiError(err)
	}
	if err := writeAtomic(path, []byte(priv+"\n"), 0600); err != nil {
		return "", apiError(err)
	}
	return pub, nil
}

// NewDeviceKey makes a key pair for a device and keeps nothing.
func (m *Manager) NewDeviceKey() (*DeviceKey, error) {
	priv, pub, err := newKeyPair()
	if err != nil {
		return nil, apiError(err)
	}
	return &DeviceKey{PrivateKey: priv, PublicKey: pub}, nil
}

// PresharedKeyRequest is a preshared key to keep: Key, base64 of 32
// bytes, or empty for OPF to make one.
type PresharedKeyRequest struct {
	Key string `json:"key,omitempty"`
}

// PresharedKey is a kept preshared key: its id, for the device in the
// model, and the key, to show once (the device needs it too).
type PresharedKey struct {
	ID  string `json:"id"`
	Key string `json:"key"`
}

// SetPresharedKey keeps a preshared key, made here unless one's given,
// in a file of its own: a new key never replaces an old one, which a
// revert would want back. Unused ones go once a commit is final.
func (m *Manager) SetPresharedKey(req PresharedKeyRequest) (*PresharedKey, error) {
	key := req.Key
	if key == "" {
		var b [32]byte
		if _, err := rand.Read(b[:]); err != nil {
			return nil, apiError(err)
		}
		key = base64.StdEncoding.EncodeToString(b[:])
	} else if b, err := base64.StdEncoding.DecodeString(key); err != nil || len(b) != 32 {
		return nil, &Error{Code: CodeInvalid, Message: "a preshared key is 32 bytes in base64, like WireGuard's own (wg genpsk)", Details: []Detail{{Path: "key", Message: "isn't a preshared key"}}}
	}
	var idb [8]byte
	if _, err := rand.Read(idb[:]); err != nil {
		return nil, apiError(err)
	}
	id := hex.EncodeToString(idb[:])
	path := m.store.SystemPath(pf.WGPSKPath(id))
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, apiError(err)
	}
	if err := writeAtomic(path, []byte(key+"\n"), 0600); err != nil {
		return nil, apiError(err)
	}
	return &PresharedKey{ID: id, Key: key}, nil
}

// checkTunnelKeys refuses a tunnel whose private key isn't here: one
// added or given a new key since what's live, with a public key OPF
// didn't make.
func (m *Manager) checkTunnelKeys(model, live *pf.Model) []Detail {
	known := map[string]bool{}
	if live != nil {
		for _, t := range live.Tunnels() {
			known[t.WireGuard.PublicKey] = true
		}
	}
	var out []Detail
	for i := range model.Interfaces {
		t := &model.Interfaces[i]
		if t.WireGuard == nil || known[t.WireGuard.PublicKey] {
			continue
		}
		if _, err := os.Stat(m.store.SystemPath(pf.WGKeyPath(t.WireGuard.PublicKey))); err != nil {
			out = append(out, Detail{Path: fmt.Sprintf("interfaces[%d].wireguard.publicKey", i), Message: "the firewall has no private key for this public key; make the tunnel's key on the firewall"})
		}
	}
	// And a device said to share a preshared key whose key isn't here.
	for i := range model.Interfaces {
		t := &model.Interfaces[i]
		if t.WireGuard == nil {
			continue
		}
		for j, p := range t.WireGuard.Peers {
			if p.PresharedKey == "" {
				continue
			}
			if _, err := os.Stat(m.store.SystemPath(pf.WGPSKPath(p.PresharedKey))); err != nil {
				out = append(out, Detail{Path: fmt.Sprintf("interfaces[%d].wireguard.peers[%d].presharedKey", i, j), Message: "the firewall has no preshared key for this device; set one"})
			}
		}
	}
	return out
}

// wgKeyFiles are the key files the models' tunnels use.
func wgKeyFiles(models ...*pf.Model) map[string]bool {
	keep := map[string]bool{}
	for _, md := range models {
		for _, t := range md.Tunnels() {
			keep[filepath.Base(pf.WGKeyPath(t.WireGuard.PublicKey))] = true
			for _, p := range t.WireGuard.Peers {
				if p.PresharedKey != "" {
					keep[filepath.Base(pf.WGPSKPath(p.PresharedKey))] = true
				}
			}
		}
	}
	return keep
}
