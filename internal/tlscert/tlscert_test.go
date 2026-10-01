package tlscert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnsure(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tls")
	now := time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)
	cert, key, made, err := Ensure(dir, []string{"gw.office.arpa", "gw", "192.168.1.1"}, now)
	if err != nil || !made {
		t.Fatal(made, err)
	}
	c, err := tls.X509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(c.Certificate[0])
	if err := leaf.VerifyHostname("gw.office.arpa"); err != nil {
		t.Error(err)
	}
	if err := leaf.VerifyHostname("192.168.1.1"); err != nil {
		t.Error(err)
	}
	if st, _ := os.Stat(filepath.Join(dir, KeyFile)); st.Mode().Perm() != 0600 {
		t.Errorf("key is %v", st.Mode())
	}
	if len(Fingerprint(cert)) != 32*3-1 {
		t.Errorf("fingerprint %q", Fingerprint(cert))
	}

	// Kept on the next start.
	cert2, _, made, _ := Ensure(dir, nil, now.Add(24*time.Hour))
	if made || string(cert2) != string(cert) {
		t.Error("made again")
	}
	// Made again a month before it ends.
	cert3, _, made, _ := Ensure(dir, []string{"gw"}, now.Add(validity-renew+time.Hour))
	if !made || string(cert3) == string(cert) {
		t.Error("not renewed")
	}

	// Someone's own certificate is never replaced, even expired.
	own := t.TempDir()
	ownCert, ownKey := foreign(t, now.Add(-time.Hour))
	os.WriteFile(filepath.Join(own, CertFile), ownCert, 0644)
	os.WriteFile(filepath.Join(own, KeyFile), ownKey, 0600)
	if got, _, made, err := Ensure(own, nil, now); err != nil || made || string(got) != string(ownCert) {
		t.Errorf("replaced someone's certificate: %v %v", made, err)
	}
	_, ownKey = foreign(t, now)

	// A key that doesn't match its certificate is an error, not
	// silently replaced.
	bad := t.TempDir()
	os.WriteFile(filepath.Join(bad, CertFile), cert, 0644)
	os.WriteFile(filepath.Join(bad, KeyFile), ownKey, 0600)
	if _, _, _, err := Ensure(bad, nil, now); err == nil {
		t.Error("mismatched key accepted")
	}
}

// foreign is a certificate someone else made, ending at notAfter.
func foreign(t *testing.T, notAfter time.Time) ([]byte, []byte) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fw.example.com", Organization: []string{"Example Corp"}},
		NotBefore: notAfter.Add(-time.Hour), NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, _ := x509.MarshalPKCS8PrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder})
}
