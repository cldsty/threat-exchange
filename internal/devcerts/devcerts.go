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
	// IfMissing skips generation when a complete and unexpired set of
	// certificates already exists.
	IfMissing bool
	// Owner, when >= 0, changes the owner (uid and gid) of the server
	// private key, e.g. to the non-root user of the service container.
	Owner int
	// DBDir, when set, is the output directory of a certificate for
	// PostgreSQL. It is separate because PostgreSQL refuses a key that other
	// users can read, which a bind mount on Docker Desktop cannot guarantee.
	DBDir string
	// DBHosts are the DNS names and IP addresses of the PostgreSQL server.
	DBHosts []string
	// DBOwner, when >= 0, changes the owner of the PostgreSQL private key.
	DBOwner int
}

// File names written to Options.Dir and Options.DBDir.
const (
	CACert     = "ca.crt"
	ServerCert = "server.crt"
	ServerKey  = "server.key"
	ClientCert = "client.crt"
	ClientKey  = "client.key"
	DBCert     = "db.crt"
	DBKey      = "db.key"
)

// leaf describes a certificate signed by the CA.
type leaf struct {
	tmpl      *x509.Certificate
	dir       string
	cert, key string
	// private keys are readable only by their owner; a negative owner keeps
	// the current one.
	private bool
	owner   int
}

// Generate writes ca.crt, server.crt/key, client.crt/key and, with DBDir,
// db.crt/key. It returns false when generation was skipped because of
// IfMissing.
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
	if o.IfMissing && complete(o) {
		return false, nil
	}
	for _, dir := range []string{o.Dir, o.DBDir} {
		if dir == "" {
			continue
		}
		// Certificates in the directory are read by other users and containers.
		if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // see above
			return false, fmt.Errorf("create output dir: %w", err)
		}
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
	if err := writePEM(filepath.Join(o.Dir, CACert), "CERTIFICATE", caDER, 0o644); err != nil {
		return false, err
	}

	leaves := []leaf{
		{tmpl: serverTemplate(o.Hosts, now, o.Validity), dir: o.Dir, cert: ServerCert, key: ServerKey, private: true, owner: o.Owner},
		// The client key is used by developers' tools (curl) on the host, so it
		// is left readable; it only grants access to a dev setup.
		{tmpl: clientTemplate(o.ClientID, now, o.Validity), dir: o.Dir, cert: ClientCert, key: ClientKey, owner: -1},
	}
	if o.DBDir != "" {
		leaves = append(leaves, leaf{
			tmpl: serverTemplate(o.DBHosts, now, o.Validity), dir: o.DBDir, cert: DBCert, key: DBKey, private: true, owner: o.DBOwner,
		})
	}
	for _, l := range leaves {
		if err := writeLeaf(l, caCert, caKey); err != nil {
			return false, err
		}
	}
	return true, nil
}

// complete reports whether all expected certificates exist and are not expired.
func complete(o Options) bool {
	if _, err := os.Stat(filepath.Join(o.Dir, CACert)); err != nil {
		return false
	}
	pairs := [][2]string{
		{filepath.Join(o.Dir, ServerCert), filepath.Join(o.Dir, ServerKey)},
		{filepath.Join(o.Dir, ClientCert), filepath.Join(o.Dir, ClientKey)},
	}
	if o.DBDir != "" {
		pairs = append(pairs, [2]string{filepath.Join(o.DBDir, DBCert), filepath.Join(o.DBDir, DBKey)})
	}
	for _, p := range pairs {
		cert, err := tls.LoadX509KeyPair(p[0], p[1])
		if err != nil || !time.Now().Before(cert.Leaf.NotAfter) {
			return false
		}
	}
	return true
}

func serverTemplate(hosts []string, now time.Time, validity time.Duration) *x509.Certificate {
	tmpl := &x509.Certificate{
		Subject:     pkix.Name{CommonName: hosts[0]},
		NotBefore:   now.Add(-time.Hour),
		NotAfter:    now.Add(validity),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	return tmpl
}

func clientTemplate(id string, now time.Time, validity time.Duration) *x509.Certificate {
	return &x509.Certificate{
		Subject:     pkix.Name{CommonName: id},
		NotBefore:   now.Add(-time.Hour),
		NotAfter:    now.Add(validity),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
}

func writeLeaf(l leaf, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) error {
	key, err := newKey()
	if err != nil {
		return err
	}
	der, _, err := sign(l.tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal key: %w", err)
	}
	if err := writePEM(filepath.Join(l.dir, l.cert), "CERTIFICATE", der, 0o644); err != nil {
		return err
	}
	keyPath := filepath.Join(l.dir, l.key)
	mode := os.FileMode(0o644)
	if l.private {
		mode = 0o600
	}
	// WriteFile keeps the mode of an existing file, and a previous key may
	// belong to another user: start from a clean slate.
	if err := os.Remove(keyPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("replace %s: %w", keyPath, err)
	}
	if err := writePEM(keyPath, "PRIVATE KEY", keyDER, mode); err != nil {
		return err
	}
	if l.owner >= 0 {
		if err := os.Chown(keyPath, l.owner, l.owner); err != nil {
			return fmt.Errorf("chown %s: %w", keyPath, err)
		}
	}
	return nil
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
