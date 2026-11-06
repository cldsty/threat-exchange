// Package auth implements client authentication with API keys and role-based
// authorization.
//
// The server never stores plaintext keys: only their SHA-256 digests are
// configured. A presented key is hashed and looked up by digest, so the
// lookup does not compare secrets byte by byte and leaks nothing useful
// through timing. API keys are high-entropy random values (256 bits), which
// makes an unsalted fast hash appropriate here, unlike for user passwords.
//
// Authentication is hidden behind the Authenticator interface, so another
// scheme (e.g. JWT issued by an OAuth 2.0 server) can be added without
// changing the HTTP layer.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync/atomic"
)

// HeaderAPIKey is the request header that carries the API key.
const HeaderAPIKey = "X-API-Key" //nolint:gosec // a header name, not a credential

// keyPrefix makes keys recognizable by secret scanners and humans.
const keyPrefix = "tx_"

// Role is a set of permissions assigned to an API key.
type Role string

// Roles.
const (
	// RoleReader may only read threats.
	RoleReader Role = "reader"
	// RoleWriter may read, create and replace threats.
	RoleWriter Role = "writer"
)

// Valid reports whether r is a known role.
func (r Role) Valid() bool { return r == RoleReader || r == RoleWriter }

// CanWrite reports whether the role permits modifying operations.
func (r Role) CanWrite() bool { return r == RoleWriter }

// Principal is an authenticated client.
type Principal struct {
	// ID is a non-secret identifier of the key (e.g. partner name). It is
	// written to logs and stored as created_by/updated_by.
	ID   string
	Role Role
}

// Errors returned by authenticators.
var (
	ErrMissingCredentials = errors.New("missing credentials")
	ErrInvalidCredentials = errors.New("invalid credentials")
)

// Authenticator identifies the client of an HTTP request.
type Authenticator interface {
	Authenticate(r *http.Request) (Principal, error)
}

// KeyStore is an Authenticator backed by a fixed set of hashed API keys.
type KeyStore struct {
	byHash map[string]Principal
}

var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// ParseKeyStore parses key definitions. Each definition has the form
// "id:role:sha256hex"; definitions are separated by commas or newlines.
// Empty lines and lines starting with '#' are ignored. An id may appear several
// times with the same role, so a client can rotate its key without downtime:
// the old and the new key work at the same time under one identity.
func ParseKeyStore(spec string) (*KeyStore, error) {
	ks := &KeyStore{byHash: map[string]Principal{}}
	roles := map[string]Role{}
	fields := strings.FieldsFunc(spec, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' })
	for i, raw := range fields {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) != 3 {
			return nil, fmt.Errorf("key definition #%d: expected id:role:sha256hex", i+1)
		}
		id, role, digest := parts[0], Role(parts[1]), strings.ToLower(parts[2])
		if !idPattern.MatchString(id) {
			return nil, fmt.Errorf("key definition #%d: invalid id %q", i+1, id)
		}
		if !role.Valid() {
			return nil, fmt.Errorf("key %q: unknown role %q", id, role)
		}
		if b, err := hex.DecodeString(digest); err != nil || len(b) != sha256.Size {
			return nil, fmt.Errorf("key %q: digest must be 64 hex characters (SHA-256)", id)
		}
		if known, dup := roles[id]; dup && known != role {
			return nil, fmt.Errorf("key %q: all keys of one id must have the same role", id)
		}
		if _, dup := ks.byHash[digest]; dup {
			return nil, fmt.Errorf("key %q: duplicate digest", id)
		}
		roles[id] = role
		ks.byHash[digest] = Principal{ID: id, Role: role}
	}
	if len(ks.byHash) == 0 {
		return nil, errors.New("no API keys configured")
	}
	return ks, nil
}

// Len returns the number of configured keys.
func (ks *KeyStore) Len() int { return len(ks.byHash) }

// Authenticate implements Authenticator.
func (ks *KeyStore) Authenticate(r *http.Request) (Principal, error) {
	key := r.Header.Get(HeaderAPIKey)
	if key == "" {
		return Principal{}, ErrMissingCredentials
	}
	p, ok := ks.byHash[HashKey(key)]
	if !ok {
		return Principal{}, ErrInvalidCredentials
	}
	return p, nil
}

// HashKey returns the hex-encoded SHA-256 digest of an API key.
func HashKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

// GenerateKey returns a new random API key and its digest.
func GenerateKey() (key, digest string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("generate key: %w", err)
	}
	key = keyPrefix + base64.RawURLEncoding.EncodeToString(b)
	return key, HashKey(key), nil
}

// Reloadable is an Authenticator whose key set can be replaced at run time, so
// keys can be added and revoked without a restart.
type Reloadable struct {
	current atomic.Pointer[KeyStore]
}

// NewReloadable creates a Reloadable serving ks.
func NewReloadable(ks *KeyStore) *Reloadable {
	r := &Reloadable{}
	r.current.Store(ks)
	return r
}

// Store replaces the key set for all subsequent requests.
func (r *Reloadable) Store(ks *KeyStore) { r.current.Store(ks) }

// Len returns the number of configured keys.
func (r *Reloadable) Len() int { return r.current.Load().Len() }

// Authenticate implements Authenticator.
func (r *Reloadable) Authenticate(req *http.Request) (Principal, error) {
	return r.current.Load().Authenticate(req)
}

// CertBound requires the Common Name of the verified TLS client certificate to
// equal the principal ID, so a leaked API key is useless without the private
// key of its owner. Use it together with mutual TLS.
type CertBound struct {
	Next Authenticator
}

// Authenticate implements Authenticator.
func (c CertBound) Authenticate(r *http.Request) (Principal, error) {
	p, err := c.Next.Authenticate(r)
	if err != nil {
		return Principal{}, err
	}
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || r.TLS.PeerCertificates[0].Subject.CommonName != p.ID {
		return Principal{}, ErrInvalidCredentials
	}
	return p, nil
}

type principalKey struct{}

// WithPrincipal returns a context carrying p.
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// PrincipalFrom extracts the principal stored by WithPrincipal.
func PrincipalFrom(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok
}
