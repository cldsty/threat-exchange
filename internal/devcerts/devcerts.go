// Package devcerts generates a private certificate authority, a server
// certificate and a client certificate for local development and tests.
// It removes the dependency on openssl (which is often missing on Windows).
//
// The generated material is NOT meant for production, where certificates
// must come from the organization's PKI.
package devcerts

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// Options configures generation.
type Options struct {
	// Dir is the output directory.
	Dir string
	// Hosts are DNS names and IP addresses for the server certificate.
	Hosts []string
	// ClientID becomes the Common Name of the client certificate.
	ClientID string
	// Validity of the leaf certificates.
	Validity time.Duration
	// IfMissing skips generation when the CA certificate already exists.
	IfMissing bool
	// Owner, when >= 0, changes the owner (uid and gid) of the server
	// private key, e.g. to the non-root user of the service container.
	Owner int
}

// File names written to Options.Dir.
const (
	CACert     = "ca.crt"
	ServerCert = "server.crt"
	ServerKey  = "server.key"
	ClientCert = "client.crt"
	ClientKey  = "client.key"
)

// Generate writes ca.crt, server.crt/key and client.crt/key. It returns
// false when generation was skipped because of IfMissing.
func Generate(o Options) (bool, error) {
	if o.Validity <= 0 {
		o.Validity = 90 * 24 * time.Hour
	}
	if o.ClientID == "" {
		o.ClientID = "dev-client"
	}
	if len(o.Hosts) == 0 {
		o.Hosts = []string{"localhost", "127.0.0.1", "::1"}
	}
	if o.IfMissing {
		if _, err := os.Stat(filepath.Join(o.Dir, CACert)); err == nil {
			return false, nil
		}
	}
	if err := os.MkdirAll(o.Dir, 0o755); err != nil {
		return false, fmt.Errorf("create output dir: %w", err)
	}

	now := time.Now()
	caKey, err := newKey()
	if err != nil {
		return false, err
	}
	caTmpl := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "threat-exchange dev CA", Organization: []string{"threat-exchange (development)"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(o.Validity + 24*time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	caDER, caCert, err := sign(caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return false, err
	}

	serverTmpl := &x509.Certificate{
		Subject:     pkix.Name{CommonName: o.Hosts[0]},
		NotBefore:   now.Add(-time.Hour),
		NotAfter:    now.Add(o.Validity),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range o.Hosts {
		if ip := net.ParseIP(h); ip != nil {
			serverTmpl.IPAddresses = append(serverTmpl.IPAddresses, ip)
		} else {
			serverTmpl.DNSNames = append(serverTmpl.DNSNames, h)
		}
	}
	clientTmpl := &x509.Certificate{
		Subject:     pkix.Name{CommonName: o.ClientID},
		NotBefore:   now.Add(-time.Hour),
		NotAfter:    now.Add(o.Validity),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	if err := writePEM(filepath.Join(o.Dir, CACert), "CERTIFICATE", caDER, 0o644); err != nil {
		return false, err
	}
	for _, leaf := range []struct {
		tmpl      *x509.Certificate
		cert, key string
		// service marks the key read by the service process.
		service bool
	}{
		{serverTmpl, ServerCert, ServerKey, true},
		// The client key is used by developers' tools (curl) on the host,
		// so it is left readable; it only grants access to a dev setup.
		{clientTmpl, ClientCert, ClientKey, false},
	} {
		key, err := newKey()
		if err != nil {
			return false, err
		}
		der, _, err := sign(leaf.tmpl, caCert, &key.PublicKey, caKey)
		if err != nil {
			return false, err
		}
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return false, fmt.Errorf("marshal key: %w", err)
		}
		if err := writePEM(filepath.Join(o.Dir, leaf.cert), "CERTIFICATE", der, 0o644); err != nil {
			return false, err
		}
		keyPath := filepath.Join(o.Dir, leaf.key)
		mode := os.FileMode(0o644)
		if leaf.service {
			mode = 0o600
		}
		if err := writePEM(keyPath, "PRIVATE KEY", keyDER, mode); err != nil {
			return false, err
		}
		if leaf.service && o.Owner >= 0 {
			if err := os.Chown(keyPath, o.Owner, o.Owner); err != nil {
				return false, fmt.Errorf("chown %s: %w", keyPath, err)
			}
		}
	}
	return true, nil
}

func newKey() (*ecdsa.PrivateKey, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	return k, nil
}

func sign(tmpl, parent *x509.Certificate, pub *ecdsa.PublicKey, signer *ecdsa.PrivateKey) ([]byte, *x509.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, nil, fmt.Errorf("generate serial: %w", err)
	}
	tmpl.SerialNumber = serial
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		return nil, nil, fmt.Errorf("create certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("parse certificate: %w", err)
	}
	return der, cert, nil
}

func writePEM(path, typ string, der []byte, mode os.FileMode) error {
	data := pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
	if data == nil {
		return errors.New("encode PEM")
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
