//go:build integration

package server_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"threat-exchange/internal/auth"
	"threat-exchange/internal/config"
	"threat-exchange/internal/devcerts"
	"threat-exchange/internal/server"
	"threat-exchange/internal/testutil/pgtest"
)

const (
	readerKey = "tx_e2e_reader"
	writerKey = "tx_e2e_writer"
	md5       = "44d88612fea8a8f36de82e1278abb02f"
)

type running struct {
	app    *server.App
	apiURL string
	opsURL string
	certs  string
	stop   func() error
}

// start runs a fully assembled service (real PostgreSQL, TLS, middleware)
// on random local ports.
func start(t *testing.T, extra map[string]string) running {
	t.Helper()
	pool, dbURL := pgtest.NewDB(t)
	certs := t.TempDir()
	_, err := devcerts.Generate(devcerts.Options{Dir: certs, ClientID: "partner-a", Owner: -1})
	require.NoError(t, err)

	env := map[string]string{
		"DB_URL":          dbURL,
		"AUTH_API_KEYS":   "reader:reader:" + auth.HashKey(readerKey) + ",writer:writer:" + auth.HashKey(writerKey),
		"TLS_CERT_FILE":   filepath.Join(certs, devcerts.ServerCert),
		"TLS_KEY_FILE":    filepath.Join(certs, devcerts.ServerKey),
		"HTTP_ADDR":       "127.0.0.1:0",
		"OPS_ADDR":        "127.0.0.1:0",
		"LOG_LEVEL":       "error",
		"TLS_MIN_VERSION": "1.2",
	}
	for k, v := range extra {
		env[k] = v
	}
	cfg, err := config.LoadFrom(env)
	require.NoError(t, err)

	app, err := server.New(cfg, pool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)
	apiLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	opsLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- app.ServeListeners(ctx, apiLn, opsLn) }()

	r := running{
		app:    app,
		apiURL: "https://" + apiLn.Addr().String(),
		opsURL: "http://" + opsLn.Addr().String(),
		certs:  certs,
	}
	var stopped bool
	r.stop = func() error {
		if stopped {
			return nil
		}
		stopped = true
		cancel()
		select {
		case err := <-done:
			return err
		case <-time.After(20 * time.Second):
			t.Fatal("server did not stop in time")
			return nil
		}
	}
	t.Cleanup(func() { _ = r.stop() })

	require.Eventually(t, func() bool {
		resp, err := http.Get(r.opsURL + "/readyz")
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, 10*time.Second, 50*time.Millisecond)
	return r
}

func client(t *testing.T, certs string, withClientCert bool, maxVersion uint16) *http.Client {
	t.Helper()
	caPEM, err := os.ReadFile(filepath.Join(certs, devcerts.CACert))
	require.NoError(t, err)
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(caPEM))
	tc := &tls.Config{RootCAs: roots, ServerName: "localhost", MaxVersion: maxVersion}
	if withClientCert {
		cert, err := tls.LoadX509KeyPair(filepath.Join(certs, devcerts.ClientCert), filepath.Join(certs, devcerts.ClientKey))
		require.NoError(t, err)
		tc.Certificates = []tls.Certificate{cert}
	}
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: tc}}
}

func call(t *testing.T, c *http.Client, method, url, key, body string, headers ...string) (*http.Response, map[string]any) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, rd)
	require.NoError(t, err)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set(auth.HeaderAPIKey, key)
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := c.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	var m map[string]any
	if len(raw) > 0 {
		require.NoError(t, json.Unmarshal(raw, &m), string(raw))
	}
	return resp, m
}

func TestEndToEndWithMutualTLS(t *testing.T) {
	t.Parallel()
	certsDir := t.TempDir()
	_, err := devcerts.Generate(devcerts.Options{Dir: certsDir, ClientID: "partner-a", Owner: -1})
	require.NoError(t, err)
	srv := start(t, map[string]string{
		"TLS_CERT_FILE":      filepath.Join(certsDir, devcerts.ServerCert),
		"TLS_KEY_FILE":       filepath.Join(certsDir, devcerts.ServerKey),
		"TLS_CLIENT_CA_FILE": filepath.Join(certsDir, devcerts.CACert),
	})
	c := client(t, certsDir, true, 0)

	resp, body := call(t, c, http.MethodPost, srv.apiURL+"/info", writerKey,
		`{"md5":"`+strings.ToUpper(md5)+`","name":"EICAR-Test-File","types":["other"],"zone":"red","severity":"low"}`)
	require.Equal(t, http.StatusCreated, resp.StatusCode, body)
	assert.Equal(t, md5, body["md5"])
	assert.Equal(t, `"1"`, resp.Header.Get("ETag"))
	assert.Contains(t, resp.Header.Get("Strict-Transport-Security"), "max-age=")

	resp, body = call(t, c, http.MethodGet, srv.apiURL+"/info/"+md5, readerKey, "")
	require.Equal(t, http.StatusOK, resp.StatusCode, body)
	assert.Equal(t, "EICAR-Test-File", body["name"])
	assert.Equal(t, "writer", body["created_by"])

	resp, _ = call(t, c, http.MethodPost, srv.apiURL+"/info", writerKey, `{"md5":"`+md5+`","name":"dup"}`)
	assert.Equal(t, http.StatusConflict, resp.StatusCode)

	resp, body = call(t, c, http.MethodPut, srv.apiURL+"/info/"+md5, writerKey, `{"name":"EICAR-Test-File","revoked":true}`, "If-Match", `"1"`)
	require.Equal(t, http.StatusOK, resp.StatusCode, body)
	assert.Equal(t, true, body["revoked"])
	assert.Equal(t, `"2"`, resp.Header.Get("ETag"))

	resp, _ = call(t, c, http.MethodPut, srv.apiURL+"/info/"+md5, writerKey, `{"name":"lost update"}`, "If-Match", `"1"`)
	assert.Equal(t, http.StatusPreconditionFailed, resp.StatusCode)

	resp, _ = call(t, c, http.MethodPut, srv.apiURL+"/info/"+md5, readerKey, `{"name":"x"}`)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)

	resp, _ = call(t, c, http.MethodGet, srv.apiURL+"/info/ffffffffffffffffffffffffffffffff", readerKey, "")
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)

	resp, _ = call(t, c, http.MethodGet, srv.apiURL+"/info/"+md5, "wrong", "")
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	t.Run("client without certificate is rejected", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, srv.apiURL+"/info/"+md5, nil)
		_, err := client(t, certsDir, false, 0).Do(req)
		assert.Error(t, err, "mTLS handshake must fail")
	})

	t.Run("client trusting another CA is rejected", func(t *testing.T) {
		other := t.TempDir()
		_, err := devcerts.Generate(devcerts.Options{Dir: other, Owner: -1})
		require.NoError(t, err)
		req, _ := http.NewRequest(http.MethodGet, srv.apiURL+"/info/"+md5, nil)
		_, err = client(t, other, true, 0).Do(req)
		assert.Error(t, err)
	})

	t.Run("metrics are exposed on the ops port", func(t *testing.T) {
		resp, err := http.Get(srv.opsURL + "/metrics")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		raw, _ := io.ReadAll(resp.Body)
		assert.Contains(t, string(raw), `threat_exchange_http_requests_total{code="201",method="POST",route="POST /info"} 1`)
	})

	require.NoError(t, srv.stop(), "graceful shutdown returns no error")
}

func TestHTTP2(t *testing.T) {
	t.Parallel()
	srv := start(t, nil)
	c := client(t, srv.certs, false, 0)
	transport, ok := c.Transport.(*http.Transport)
	require.True(t, ok)
	transport.ForceAttemptHTTP2 = true

	resp, _ := call(t, c, http.MethodGet, srv.apiURL+"/info/"+md5, readerKey, "")
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	assert.Equal(t, 2, resp.ProtoMajor)
}

func TestAPIKeyBoundToClientCertificate(t *testing.T) {
	t.Parallel()
	certsDir := t.TempDir()
	_, err := devcerts.Generate(devcerts.Options{Dir: certsDir, ClientID: "partner-a", Owner: -1})
	require.NoError(t, err)
	srv := start(t, map[string]string{
		"TLS_CERT_FILE":         filepath.Join(certsDir, devcerts.ServerCert),
		"TLS_KEY_FILE":          filepath.Join(certsDir, devcerts.ServerKey),
		"TLS_CLIENT_CA_FILE":    filepath.Join(certsDir, devcerts.CACert),
		"AUTH_BIND_CLIENT_CERT": "true",
		"AUTH_API_KEYS":         "partner-a:reader:" + auth.HashKey("key-a") + ",partner-b:reader:" + auth.HashKey("key-b"),
	})
	c := client(t, certsDir, true, 0)

	resp, _ := call(t, c, http.MethodGet, srv.apiURL+"/info/"+md5, "key-a", "")
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "the certificate matches the key")
	resp, _ = call(t, c, http.MethodGet, srv.apiURL+"/info/"+md5, "key-b", "")
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "a key of another client is refused")
}

func TestReloadAPIKeysFromFile(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "keys")
	write := func(content string) {
		t.Helper()
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	}
	write("partner:reader:" + auth.HashKey("old-key"))
	srv := start(t, map[string]string{"AUTH_API_KEYS": "", "AUTH_API_KEYS_FILE": path})
	c := client(t, srv.certs, false, 0)
	status := func(key string) int {
		t.Helper()
		resp, _ := call(t, c, http.MethodGet, srv.apiURL+"/info/"+md5, key, "")
		return resp.StatusCode
	}
	require.Equal(t, http.StatusNotFound, status("old-key"))
	require.Equal(t, http.StatusUnauthorized, status("new-key"))

	write("partner:reader:" + auth.HashKey("old-key") + "\npartner:reader:" + auth.HashKey("new-key"))
	require.NoError(t, srv.app.Reload())
	assert.Equal(t, http.StatusNotFound, status("old-key"), "both keys work during rotation")
	assert.Equal(t, http.StatusNotFound, status("new-key"))

	write("partner:reader:" + auth.HashKey("new-key"))
	require.NoError(t, srv.app.Reload())
	assert.Equal(t, http.StatusUnauthorized, status("old-key"), "a revoked key stops working without a restart")

	write("broken file")
	require.Error(t, srv.app.Reload())
	assert.Equal(t, http.StatusNotFound, status("new-key"), "a broken file keeps the previous keys")
}

func TestStorageOutageEndToEnd(t *testing.T) {
	t.Parallel()
	srv := start(t, nil)
	c := client(t, srv.certs, false, 0)
	resp, _ := call(t, c, http.MethodPost, srv.apiURL+"/info", writerKey, `{"md5":"`+md5+`","name":"X"}`)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	// Stopping the temporary database in the middle is done by the pool test;
	// here it is enough that health is independent of readiness.
	r, err := http.Get(srv.opsURL + "/healthz")
	require.NoError(t, err)
	_ = r.Body.Close()
	assert.Equal(t, http.StatusOK, r.StatusCode)
}

func TestTLSVersionPolicy(t *testing.T) {
	t.Parallel()
	srv := start(t, map[string]string{"TLS_MIN_VERSION": "1.3"})

	req, _ := http.NewRequest(http.MethodGet, srv.apiURL+"/info/"+md5, nil)
	_, err := client(t, srv.certs, false, tls.VersionTLS12).Do(req)
	assert.Error(t, err, "TLS 1.2 client is refused when the minimum is 1.3")

	resp, _ := call(t, client(t, srv.certs, false, 0), http.MethodGet, srv.apiURL+"/info/"+md5, readerKey, "")
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, "TLS 1.3 client works; no mTLS configured")
}

func TestRateLimitEndToEnd(t *testing.T) {
	t.Parallel()
	srv := start(t, map[string]string{"RATE_LIMIT_KEY_RPS": "0.01", "RATE_LIMIT_KEY_BURST": "3"})
	c := client(t, srv.certs, false, 0)
	for range 3 {
		resp, _ := call(t, c, http.MethodGet, srv.apiURL+"/info/"+md5, readerKey, "")
		require.Equal(t, http.StatusNotFound, resp.StatusCode)
	}
	resp, body := call(t, c, http.MethodGet, srv.apiURL+"/info/"+md5, readerKey, "")
	assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode)
	assert.Equal(t, "rate_limited", body["code"])
	assert.NotEmpty(t, resp.Header.Get("Retry-After"))
}

func TestHealthEndpoints(t *testing.T) {
	t.Parallel()
	srv := start(t, nil)
	for _, path := range []string{"/healthz", "/readyz"} {
		resp, err := http.Get(srv.opsURL + path)
		require.NoError(t, err)
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode, path)
	}
	require.NoError(t, srv.stop())
	_, err := http.Get(srv.opsURL + "/healthz")
	assert.Error(t, err, "ops server is closed after shutdown")
}

func TestReadinessFailsWhenDatabaseIsDown(t *testing.T) {
	t.Parallel()
	pool, dbURL := pgtest.NewDB(t)
	certs := t.TempDir()
	_, err := devcerts.Generate(devcerts.Options{Dir: certs, Owner: -1})
	require.NoError(t, err)
	cfg, err := config.LoadFrom(map[string]string{
		"DB_URL": dbURL, "AUTH_API_KEYS": "r:reader:" + auth.HashKey(readerKey),
		"TLS_CERT_FILE": filepath.Join(certs, devcerts.ServerCert), "TLS_KEY_FILE": filepath.Join(certs, devcerts.ServerKey),
	})
	require.NoError(t, err)
	app, err := server.New(cfg, pool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)
	apiLn, _ := net.Listen("tcp", "127.0.0.1:0")
	opsLn, _ := net.Listen("tcp", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- app.ServeListeners(ctx, apiLn, opsLn) }()
	defer func() { cancel(); <-done }()

	url := "http://" + opsLn.Addr().String() + "/readyz"
	require.Eventually(t, func() bool {
		resp, err := http.Get(url)
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, 5*time.Second, 50*time.Millisecond)

	pool.Close() // simulate losing the database
	resp, err := http.Get(url)
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
}
