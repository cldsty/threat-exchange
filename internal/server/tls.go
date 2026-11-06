package server

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"sync"

	"threat-exchange/internal/config"
)

// certReloader serves the current server certificate and can reload it from
// disk without a restart (on SIGHUP), which allows certificate rotation
// without downtime.
type certReloader struct {
	certFile, keyFile string
	mu                sync.RWMutex
	cert              *tls.Certificate
}

func newCertReloader(certFile, keyFile string) (*certReloader, error) {
	r := &certReloader{certFile: certFile, keyFile: keyFile}
	if err := r.Reload(); err != nil {
		return nil, err
	}
	return r, nil
}

// Reload reads the key pair from disk. On error the previous certificate
// stays in use.
func (r *certReloader) Reload() error {
	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return fmt.Errorf("load TLS key pair: %w", err)
	}
	r.mu.Lock()
	r.cert = &cert
	r.mu.Unlock()
	return nil
}

func (r *certReloader) getCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cert, nil
}

// buildTLSConfig creates a hardened TLS configuration. Go's defaults already
// exclude weak cipher suites and enable modern key exchange (including the
// hybrid post-quantum X25519MLKEM768); we additionally enforce the minimum
// protocol version and, optionally, client certificate verification (mTLS).
func buildTLSConfig(c config.TLS, reloader *certReloader) (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: reloader.getCertificate,
	}
	if c.MinVersion == "1.3" {
		cfg.MinVersion = tls.VersionTLS13
	}
	if c.ClientCAFile != "" {
		pem, err := os.ReadFile(c.ClientCAFile) //nolint:gosec // path comes from trusted configuration
		if err != nil {
			return nil, fmt.Errorf("read client CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("client CA file contains no valid certificates")
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return cfg, nil
}
