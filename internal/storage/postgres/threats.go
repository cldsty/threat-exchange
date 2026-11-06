package postgres

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"threat-exchange/internal/domain/threat"
	"threat-exchange/internal/service"
)

// ThreatRepository stores threats in PostgreSQL. All queries are static and
// parameterized; user input never becomes part of the SQL text.
type ThreatRepository struct {
	pool *pgxpool.Pool
}

var _ service.Repository = (*ThreatRepository)(nil)

// NewThreatRepository creates a repository on top of pool.
func NewThreatRepository(pool *pgxpool.Pool) *ThreatRepository {
	return &ThreatRepository{pool: pool}
}

// sha256UniqueConstraint is the name of the unique constraint on threats.sha256.
const sha256UniqueConstraint = "threats_sha256_key"

const threatColumns = `md5, sha1, sha256, name, description, types, zone, severity, file_size,
	first_seen_at, last_seen_at, tlp, confidence, revoked, created_at, updated_at, created_by, updated_by, version`

const (
	getThreatSQL = `SELECT ` + threatColumns + ` FROM threats WHERE md5 = $1`

	createThreatSQL = `INSERT INTO threats (md5, sha1, sha256, name, description, types, zone, severity,
	file_size, first_seen_at, last_seen_at, tlp, confidence, revoked, created_by, updated_by)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $15)
ON CONFLICT (md5) DO NOTHING
RETURNING ` + threatColumns

	replaceThreatSQL = `UPDATE threats SET
	sha1 = $2, sha256 = $3, name = $4, description = $5, types = $6, zone = $7, severity = $8,
	file_size = $9, first_seen_at = $10, last_seen_at = $11, tlp = $12, confidence = $13, revoked = $14,
	updated_by = $15, updated_at = now(), version = version + 1
WHERE md5 = $1 AND CASE WHEN $16::bigint[] IS NULL THEN updated_by = $15 ELSE version = ANY($16) END
RETURNING ` + threatColumns

	existsThreatSQL = `SELECT EXISTS (SELECT 1 FROM threats WHERE md5 = $1)`
)

// Get implements service.Repository.
func (r *ThreatRepository) Get(ctx context.Context, md5 string) (threat.Threat, error) {
	t, err := scanThreat(r.pool.QueryRow(ctx, getThreatSQL, md5))
	if errors.Is(err, pgx.ErrNoRows) {
		return threat.Threat{}, threat.ErrNotFound
	}
	if err != nil {
		return threat.Threat{}, wrapError("select threat", err)
	}
	return t, nil
}

// Create implements service.Repository.
func (r *ThreatRepository) Create(ctx context.Context, md5 string, a threat.Attributes, actor string) (threat.Threat, error) {
	t, err := scanThreat(r.pool.QueryRow(ctx, createThreatSQL,
		md5, a.SHA1, a.SHA256, a.Name, a.Description, typesToStrings(a.Types), string(a.Zone),
		string(a.Severity), a.FileSize, a.FirstSeenAt, a.LastSeenAt, string(a.TLP), a.Confidence, a.Revoked, actor))
	if errors.Is(err, pgx.ErrNoRows) {
		// ON CONFLICT DO NOTHING returned no row: the MD5 is already taken.
		return threat.Threat{}, threat.ErrAlreadyExists
	}
	if err != nil {
		return threat.Threat{}, writeError("insert threat", err)
	}
	return t, nil
}

// Replace implements service.Repository.
func (r *ThreatRepository) Replace(ctx context.Context, md5 string, a threat.Attributes, actor string, expectedVersions []int64) (threat.Threat, error) {
	t, err := scanThreat(r.pool.QueryRow(ctx, replaceThreatSQL,
		md5, a.SHA1, a.SHA256, a.Name, a.Description, typesToStrings(a.Types), string(a.Zone),
		string(a.Severity), a.FileSize, a.FirstSeenAt, a.LastSeenAt, string(a.TLP), a.Confidence, a.Revoked, actor, expectedVersions))
	if err == nil {
		return t, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return threat.Threat{}, writeError("update threat", err)
	}
	// No row updated: the record does not exist or the precondition failed.
	var exists bool
	if err := r.pool.QueryRow(ctx, existsThreatSQL, md5).Scan(&exists); err != nil {
		return threat.Threat{}, wrapError("check threat existence", err)
	}
	switch {
	case !exists:
		return threat.Threat{}, threat.ErrNotFound
	case len(expectedVersions) == 0:
		return threat.Threat{}, threat.ErrPreconditionRequired
	default:
		return threat.Threat{}, threat.ErrVersionMismatch
	}
}

// wrapError adds context to err and marks temporary failures with
// threat.ErrUnavailable.
func wrapError(op string, err error) error {
	if isTemporary(err) {
		return fmt.Errorf("%s: %w: %w", op, threat.ErrUnavailable, err)
	}
	return fmt.Errorf("%s: %w", op, err)
}

// writeError is wrapError for writes: it also converts a violation of the
// SHA-256 uniqueness to the domain error.
func writeError(op string, err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.ConstraintName == sha256UniqueConstraint {
		return threat.ErrHashConflict
	}
	return wrapError(op, err)
}

// isTemporary reports whether err means the database cannot serve the request
// right now, as opposed to rejecting it. A cancelled request is not temporary:
// the client has gone away.
func isTemporary(err error) bool {
	var (
		connErr *pgconn.ConnectError
		netErr  net.Error
		pgErr   *pgconn.PgError
	)
	switch {
	case errors.As(err, &connErr), errors.As(err, &netErr), errors.Is(err, context.DeadlineExceeded):
		return true
	case errors.As(err, &pgErr):
		// Classes 08 (connection), 53 (insufficient resources) and 57 (operator
		// intervention, including statement_timeout and server shutdown).
		return strings.HasPrefix(pgErr.Code, "08") || strings.HasPrefix(pgErr.Code, "53") || strings.HasPrefix(pgErr.Code, "57")
	}
	return false
}

func scanThreat(row pgx.Row) (threat.Threat, error) {
	var (
		t        threat.Threat
		types    []string
		zone     string
		severity string
		tlp      string
	)
	err := row.Scan(&t.MD5, &t.SHA1, &t.SHA256, &t.Name, &t.Description, &types, &zone, &severity,
		&t.FileSize, &t.FirstSeenAt, &t.LastSeenAt, &tlp, &t.Confidence, &t.Revoked, &t.CreatedAt, &t.UpdatedAt,
		&t.CreatedBy, &t.UpdatedBy, &t.Version)
	if err != nil {
		return threat.Threat{}, err
	}
	t.Zone = threat.Zone(zone)
	t.Severity = threat.Severity(severity)
	t.TLP = threat.TLP(tlp)
	t.Types = make([]threat.Type, len(types))
	for i, s := range types {
		t.Types[i] = threat.Type(s)
	}
	t.CreatedAt = t.CreatedAt.UTC()
	t.UpdatedAt = t.UpdatedAt.UTC()
	t.FirstSeenAt = utcPtr(t.FirstSeenAt)
	t.LastSeenAt = utcPtr(t.LastSeenAt)
	return t, nil
}

func typesToStrings(types []threat.Type) []string {
	out := make([]string, len(types))
	for i, t := range types {
		out[i] = string(t)
	}
	return out
}

func utcPtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}
