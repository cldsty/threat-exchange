package devcerts_test

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"threat-exchange/internal/devcerts"
)

func TestGenerateProducesVerifiableChain(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	created, err := devcerts.Generate(devcerts.Options{
		Dir: dir, Hosts: []string{"localhost", "127.0.0.1"}, ClientID: "partner-a", Owner: -1,
	})
	require.NoError(t, err)
	require.True(t, created)

	caPEM, err := os.ReadFile(filepath.Join(dir, devcerts.CACert))
	require.NoError(t, err)
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(caPEM))

	server, err := tls.LoadX509KeyPair(filepath.Join(dir, devcerts.ServerCert), filepath.Join(dir, devcerts.ServerKey))
	require.NoError(t, err)
	_, err = server.Leaf.Verify(x509.VerifyOptions{
		DNSName: "localhost", Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	assert.NoError(t, err, "server cert valid for localhost")
	assert.NoError(t, server.Leaf.VerifyHostname("127.0.0.1"))

	client, err := tls.LoadX509KeyPair(filepath.Join(dir, devcerts.ClientCert), filepath.Join(dir, devcerts.ClientKey))
	require.NoError(t, err)
	_, err = client.Leaf.Verify(x509.VerifyOptions{
		Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	assert.NoError(t, err, "client cert valid for client auth")
	assert.Equal(t, "partner-a", client.Leaf.Subject.CommonName)
	assert.WithinDuration(t, time.Now().Add(90*24*time.Hour), client.Leaf.NotAfter, 2*time.Hour)

	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Join(dir, devcerts.ServerKey))
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "server key is private")
	}
}

func TestGenerateIfMissing(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	created, err := devcerts.Generate(devcerts.Options{Dir: dir, Owner: -1})
	require.NoError(t, err)
	require.True(t, created)
	before, err := os.ReadFile(filepath.Join(dir, devcerts.CACert))
	require.NoError(t, err)

	created, err = devcerts.Generate(devcerts.Options{Dir: dir, IfMissing: true, Owner: -1})
	require.NoError(t, err)
	assert.False(t, created)
	after, err := os.ReadFile(filepath.Join(dir, devcerts.CACert))
	require.NoError(t, err)
	assert.Equal(t, before, after, "existing certificates are kept")
}
