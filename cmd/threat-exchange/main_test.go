package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"threat-exchange/internal/auth"
)

func TestKeygen(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	require.NoError(t, run([]string{"keygen", "-id", "partner-a", "-role", "writer"}, &out, &out))

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	require.Len(t, lines, 2)
	key := strings.TrimSpace(lines[0][strings.LastIndex(lines[0], ":")+1:])
	_, after, found := strings.Cut(lines[1], "partner-a")
	require.True(t, found, lines[1])
	entry := "partner-a" + strings.TrimSpace(after)

	ks, err := auth.ParseKeyStore(entry)
	require.NoError(t, err, "printed entry is a valid AUTH_API_KEYS value")
	assert.Equal(t, 1, ks.Len())
	assert.Equal(t, auth.HashKey(key), entry[strings.LastIndex(entry, ":")+1:])
}

func TestKeygenValidation(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	assert.Error(t, run([]string{"keygen"}, &out, &out), "id is required")
	assert.Error(t, run([]string{"keygen", "-id", "a", "-role", "admin"}, &out, &out), "unknown role")
	assert.Error(t, run([]string{"keygen", "-id", "bad id"}, &out, &out), "invalid id")
}

func TestDevcerts(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "certs")
	var out bytes.Buffer
	require.NoError(t, run([]string{"devcerts", "-dir", dir}, &out, &out))
	for _, f := range []string{"ca.crt", "server.crt", "server.key", "client.crt", "client.key"} {
		_, err := os.Stat(filepath.Join(dir, f))
		assert.NoError(t, err, f)
	}
	out.Reset()
	require.NoError(t, run([]string{"devcerts", "-dir", dir, "-if-missing"}, &out, &out))
	assert.Contains(t, out.String(), "skipping")
}

func TestVersionAndUnknownCommand(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	require.NoError(t, run([]string{"version"}, &out, &out))
	assert.Equal(t, "dev\n", out.String())
	assert.Error(t, run([]string{"frobnicate"}, &out, &out))
}
