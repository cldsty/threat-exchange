package auth_test

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"threat-exchange/internal/auth"
)

func TestGenerateKey(t *testing.T) {
	t.Parallel()
	k1, d1, err := auth.GenerateKey()
	require.NoError(t, err)
	k2, _, err := auth.GenerateKey()
	require.NoError(t, err)

	assert.True(t, strings.HasPrefix(k1, "tx_"))
	assert.GreaterOrEqual(t, len(k1), 40, "at least 256 bits of entropy")
	assert.NotEqual(t, k1, k2)
	assert.Equal(t, auth.HashKey(k1), d1)
	assert.Len(t, d1, 64)
}

func TestKeyStoreAuthenticate(t *testing.T) {
	t.Parallel()
	ks, err := auth.ParseKeyStore(
		"# comment\nreader-1:reader:" + auth.HashKey("secret-r") +
			",writer-1:writer:" + strings.ToUpper(auth.HashKey("secret-w")))
	require.NoError(t, err)
	assert.Equal(t, 2, ks.Len())

	tests := []struct {
		name    string
		key     string
		want    auth.Principal
		wantErr error
	}{
		{"reader", "secret-r", auth.Principal{ID: "reader-1", Role: auth.RoleReader}, nil},
		{"writer (digest case-insensitive)", "secret-w", auth.Principal{ID: "writer-1", Role: auth.RoleWriter}, nil},
		{"missing", "", auth.Principal{}, auth.ErrMissingCredentials},
		{"wrong", "secret-x", auth.Principal{}, auth.ErrInvalidCredentials},
		{"digest is not a key", auth.HashKey("secret-r"), auth.Principal{}, auth.ErrInvalidCredentials},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequest("GET", "/", nil)
			if tt.key != "" {
				r.Header.Set(auth.HeaderAPIKey, tt.key)
			}
			got, err := ks.Authenticate(r)
			assert.ErrorIs(t, err, tt.wantErr)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParseKeyStoreErrors(t *testing.T) {
	t.Parallel()
	h := auth.HashKey("k")
	tests := map[string]string{
		"empty":            "",
		"only comments":    "# nothing",
		"bad format":       "id:reader",
		"bad role":         "id:admin:" + h,
		"bad id":           "bad id:reader:" + h,
		"short digest":     "id:reader:abc",
		"non-hex digest":   "id:reader:" + strings.Repeat("z", 64),
		"duplicate id":     "a:reader:" + h + ",a:writer:" + auth.HashKey("other"),
		"duplicate digest": "a:reader:" + h + ",b:writer:" + h,
	}
	for name, spec := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := auth.ParseKeyStore(spec)
			assert.Error(t, err)
		})
	}
}

func TestRoles(t *testing.T) {
	t.Parallel()
	assert.True(t, auth.RoleWriter.CanWrite())
	assert.False(t, auth.RoleReader.CanWrite())
	assert.False(t, auth.Role("admin").Valid())
}

func TestPrincipalContext(t *testing.T) {
	t.Parallel()
	_, ok := auth.PrincipalFrom(context.Background())
	assert.False(t, ok)
	p := auth.Principal{ID: "x", Role: auth.RoleReader}
	got, ok := auth.PrincipalFrom(auth.WithPrincipal(context.Background(), p))
	assert.True(t, ok)
	assert.Equal(t, p, got)
}
