//go:build integration && !windows

package server_test

import (
	"crypto/tls"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"threat-exchange/internal/devcerts"
)

func TestCertificateReloadOnSIGHUP(t *testing.T) {
	// Not parallel: sends a signal to the test process.
	srv := start(t, nil)
	serial := func() string {
		conn, err := tls.Dial("tcp", strings.TrimPrefix(srv.apiURL, "https://"), &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // only reading the presented certificate
		})
		require.NoError(t, err)
		defer func() { _ = conn.Close() }()
		return conn.ConnectionState().PeerCertificates[0].SerialNumber.String()
	}
	before := serial()

	// Rotate the key pair on disk and ask the server to reload it.
	_, err := devcerts.Generate(devcerts.Options{Dir: srv.certs, Owner: -1})
	require.NoError(t, err)
	p, err := os.FindProcess(os.Getpid())
	require.NoError(t, err)
	require.NoError(t, p.Signal(syscall.SIGHUP))

	assert.Eventually(t, func() bool { return serial() != before }, 5*time.Second, 50*time.Millisecond,
		"new certificate is served without restart")
}
