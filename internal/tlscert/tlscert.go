// Package tlscert keeps the web interface's certificate: a self-signed
// one OPF makes on first start, until someone puts their own in its
// place.
package tlscert

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	CertFile = "cert.pem"
	KeyFile  = "key.pem"
	// validity is the longest Apple's platforms accept for a server
	// certificate; the certificate is made again a month before it ends.
	validity = 825 * 24 * time.Hour
	renew    = 30 * 24 * time.Hour
)

// Ensure returns the certificate and key in dir, first making a
// self-signed pair for hosts (names and addresses) if there's none, or
// OPF's own is close to expiring. A certificate someone put there
// themselves is never replaced.
func Ensure(dir string, hosts []string, now time.Time) (certPEM, keyPEM []byte, made bool, err error) {
	certPath, keyPath := filepath.Join(dir, CertFile), filepath.Join(dir, KeyFile)
	certPEM, err1 := os.ReadFile(certPath)
	keyPEM, err2 := os.ReadFile(keyPath)
	if err1 == nil && err2 == nil {
		c, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return nil, nil, false, fmt.Errorf("%s and %s don't make a certificate: %w", certPath, keyPath, err)
		}
		leaf, err := x509.ParseCertificate(c.Certificate[0])
		if err != nil {
			return nil, nil, false, err
		}
		if !ours(leaf) || leaf.NotAfter.Sub(now) > renew {
			return certPEM, keyPEM, false, nil
		}
	} else if !errors.Is(err1, os.ErrNotExist) && err1 != nil {
		return nil, nil, false, err1
	} else if !errors.Is(err2, os.ErrNotExist) && err2 != nil {
		return nil, nil, false, err2
	}
	certPEM, keyPEM, err = generate(hosts, now)
	if err != nil {
		return nil, nil, false, err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, nil, false, err
	}
	// The key first, so a crash between leaves no certificate without it.
	if err := writeFile(keyPath, keyPEM, 0600); err != nil {
		return nil, nil, false, err
	}
	if err := writeFile(certPath, certPEM, 0644); err != nil {
		return nil, nil, false, err
	}
	return certPEM, keyPEM, true, nil
}

// ours is a certificate Ensure made: self-signed, with OPF's
// organisation.
func ours(c *x509.Certificate) bool {
	return len(c.Subject.Organization) == 1 && c.Subject.Organization[0] == "OPF self-signed" && bytes.Equal(c.RawIssuer, c.RawSubject)
}

func generate(hosts []string, now time.Time) ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, nil, err
	}
	cn := "OPF"
	if len(hosts) > 0 {
		cn = hosts[0]
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"OPF self-signed"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else if h != "" {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	kder, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}), nil
}

func writeFile(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".new"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil { // whatever the umask
		return err
	}
	return os.Rename(tmp, path)
}

// Fingerprint is the SHA-256 of a certificate's DER, as browsers show
// it: AB:CD:...
func Fingerprint(certPEM []byte) string {
	b, _ := pem.Decode(certPEM)
	if b == nil {
		return ""
	}
	sum := sha256.Sum256(b.Bytes)
	var parts []string
	for _, x := range sum {
		parts = append(parts, fmt.Sprintf("%02X", x))
	}
	return strings.Join(parts, ":")
}
