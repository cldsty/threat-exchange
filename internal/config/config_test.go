package config_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"threat-exchange/internal/config"
)

func base() map[string]string {
	return map[string]string{
		"DB_URL":        "postgres://u:p@db:5432/threats",
		"AUTH_API_KEYS": "a:reader:" + "0000000000000000000000000000000000000000000000000000000000000000",
		"TLS_CERT_FILE": "/certs/server.crt",
		"TLS_KEY_FILE":  "/certs/server.key",
	}
}

func TestDefaults(t *testing.T) {
	t.Parallel()
	cfg, err := config.LoadFrom(base())
	require.NoError(t, err)

	assert.Equal(t, ":8443", cfg.HTTP.Addr)
	assert.Equal(t, ":8081", cfg.Ops.Addr)
	assert.True(t, cfg.TLS.Enabled, "TLS is on by default")
	assert.Equal(t, "1.2", cfg.TLS.MinVersion)
	assert.Equal(t, 5*time.Second, cfg.HTTP.ReadHeaderTimeout)
	assert.EqualValues(t, 64<<10, cfg.HTTP.MaxBodyBytes)
	assert.True(t, cfg.RateLimit.Enabled)
	assert.False(t, cfg.MigrateOnStart)
	assert.Equal(t, "json", cfg.Log.Format)
}

func TestOverrides(t *testing.T) {
	t.Parallel()
	env := base()
	env["HTTP_ADDR"] = ":9443"
	env["HTTP_TRUSTED_PROXIES"] = "10.0.0.0/8, 192.168.1.10/32"
	env["TLS_MIN_VERSION"] = "1.3"
	env["RATE_LIMIT_KEY_RPS"] = "2.5"
	env["LOG_LEVEL"] = "debug"
	cfg, err := config.LoadFrom(env)
	require.NoError(t, err)
	assert.Equal(t, ":9443", cfg.HTTP.Addr)
	assert.Equal(t, "1.3", cfg.TLS.MinVersion)
	assert.InDelta(t, 2.5, cfg.RateLimit.KeyRate, 1e-9)
	prefixes, err := cfg.HTTP.TrustedProxyPrefixes()
	require.NoError(t, err)
	assert.Len(t, prefixes, 2)
}

func TestSecretsFromFiles(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	keys := filepath.Join(dir, "keys")
	require.NoError(t, os.WriteFile(keys, []byte("a:writer:"+
		"1111111111111111111111111111111111111111111111111111111111111111\n"), 0o600))
	dbURL := filepath.Join(dir, "db")
	require.NoError(t, os.WriteFile(dbURL, []byte("postgres://from-file\n"), 0o600))

	env := base()
	delete(env, "AUTH_API_KEYS")
	delete(env, "DB_URL")
	env["AUTH_API_KEYS_FILE"] = keys
	env["DB_URL_FILE"] = dbURL
	cfg, err := config.LoadFrom(env)
	require.NoError(t, err)
	assert.Contains(t, cfg.Auth.APIKeys, "a:writer:")
	assert.Equal(t, "postgres://from-file", cfg.DB.URL)
}

func TestInvalid(t *testing.T) {
	t.Parallel()
	tests := map[string]func(map[string]string){
		"missing DB":            func(e map[string]string) { delete(e, "DB_URL") },
		"missing keys":          func(e map[string]string) { delete(e, "AUTH_API_KEYS") },
		"TLS without cert":      func(e map[string]string) { delete(e, "TLS_CERT_FILE") },
		"bad TLS version":       func(e map[string]string) { e["TLS_MIN_VERSION"] = "1.0" },
		"mTLS without TLS":      func(e map[string]string) { e["TLS_ENABLED"] = "false"; e["TLS_CLIENT_CA_FILE"] = "/ca" },
		"bad log level":         func(e map[string]string) { e["LOG_LEVEL"] = "loud" },
		"bad log format":        func(e map[string]string) { e["LOG_FORMAT"] = "xml" },
		"bad CIDR":              func(e map[string]string) { e["HTTP_TRUSTED_PROXIES"] = "10.0.0.0/33" },
		"bad duration":          func(e map[string]string) { e["HTTP_READ_TIMEOUT"] = "soon" },
		"handler >= write":      func(e map[string]string) { e["HTTP_HANDLER_TIMEOUT"] = "30s" },
		"zero rate":             func(e map[string]string) { e["RATE_LIMIT_IP_RPS"] = "0" },
		"both value and file":   func(e map[string]string) { e["DB_URL_FILE"] = "/x" },
		"missing secret file":   func(e map[string]string) { delete(e, "DB_URL"); e["DB_URL_FILE"] = "/does/not/exist" },
		"inconsistent db pool":  func(e map[string]string) { e["DB_MIN_CONNS"] = "20" },
		"non-positive max body": func(e map[string]string) { e["HTTP_MAX_BODY_BYTES"] = "0" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			env := base()
			mutate(env)
			_, err := config.LoadFrom(env)
			assert.Error(t, err)
		})
	}
}

func TestTLSCanBeDisabledExplicitly(t *testing.T) {
	t.Parallel()
	env := base()
	delete(env, "TLS_CERT_FILE")
	delete(env, "TLS_KEY_FILE")
	env["TLS_ENABLED"] = "false"
	_, err := config.LoadFrom(env)
	assert.NoError(t, err)
}

func TestLoadForMigrateNeedsOnlyDatabase(t *testing.T) {
	t.Setenv("DB_URL", "postgres://u:p@db/threats")
	t.Setenv("AUTH_API_KEYS", "")
	t.Setenv("TLS_CERT_FILE", "")
	cfg, err := config.LoadForMigrate()
	require.NoError(t, err)
	assert.Equal(t, "postgres://u:p@db/threats", cfg.DB.URL)

	t.Setenv("DB_URL", "")
	_, err = config.LoadForMigrate()
	assert.Error(t, err)
}
