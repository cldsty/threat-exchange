//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"threat-exchange/internal/domain/threat"
	"threat-exchange/internal/storage/postgres"
	"threat-exchange/internal/testutil/pgtest"
)

const md5 = "d41d8cd98f00b204e9800998ecf8427e"

func ptr[T any](v T) *T { return &v }

func fullAttrs() threat.Attributes {
	first := time.Date(2026, 1, 15, 10, 30, 0, 123456000, time.UTC)
	last := first.Add(48 * time.Hour)
	return threat.Attributes{
		SHA1:        ptr(strings.Repeat("a", 40)),
		SHA256:      ptr(strings.Repeat("b", 64)),
		Name:        "Trojan.Win32.Generic",
		Description: ptr("Описание: загружает модули"),
		Types:       []threat.Type{threat.TypeTrojan, threat.TypeDownloader},
		Zone:        threat.ZoneRed,
		Severity:    threat.SeverityHigh,
		FileSize:    ptr[int64](73802),
		FirstSeenAt: &first,
		LastSeenAt:  &last,
		TLP:         threat.TLPAmberStrict,
		Confidence:  ptr[int32](85),
		Revoked:     false,
	}
}

func TestRepositoryRoundTrip(t *testing.T) {
	t.Parallel()
	pool, _ := pgtest.NewDB(t)
	repo := postgres.NewThreatRepository(pool)
	ctx := context.Background()

	_, err := repo.Get(ctx, md5)
	assert.ErrorIs(t, err, threat.ErrNotFound)

	created, err := repo.Create(ctx, md5, fullAttrs(), "partner-a")
	require.NoError(t, err)
	assert.Equal(t, md5, created.MD5)
	assert.Equal(t, fullAttrs(), created.Attributes, "all fields survive the round trip")
	assert.EqualValues(t, 1, created.Version)
	assert.Equal(t, "partner-a", created.CreatedBy)
	assert.Equal(t, time.UTC, created.CreatedAt.Location())
	assert.WithinDuration(t, time.Now(), created.CreatedAt, time.Minute)
	assert.Equal(t, created.CreatedAt, created.UpdatedAt)

	got, err := repo.Get(ctx, md5)
	require.NoError(t, err)
	assert.Equal(t, created, got)

	_, err = repo.Create(ctx, md5, fullAttrs(), "partner-b")
	assert.ErrorIs(t, err, threat.ErrAlreadyExists)
}

func TestRepositoryOptionalFieldsAreNull(t *testing.T) {
	t.Parallel()
	pool, _ := pgtest.NewDB(t)
	repo := postgres.NewThreatRepository(pool)
	minimal := threat.Attributes{Name: "X"}.Normalize()

	got, err := repo.Create(context.Background(), md5, minimal, "a")
	require.NoError(t, err)
	assert.Nil(t, got.SHA1)
	assert.Nil(t, got.Description)
	assert.Nil(t, got.FileSize)
	assert.Nil(t, got.FirstSeenAt)
	assert.Nil(t, got.Confidence)
	assert.Equal(t, threat.TLPAmber, got.TLP)
	assert.Equal(t, []threat.Type{}, got.Types)
}

func TestRepositoryReplace(t *testing.T) {
	t.Parallel()
	pool, _ := pgtest.NewDB(t)
	repo := postgres.NewThreatRepository(pool)
	ctx := context.Background()
	created, err := repo.Create(ctx, md5, fullAttrs(), "creator")
	require.NoError(t, err)

	time.Sleep(10 * time.Millisecond)
	replaced, err := repo.Replace(ctx, md5, threat.Attributes{Name: "New", Revoked: true}.Normalize(), "editor", []int64{1})
	require.NoError(t, err)
	assert.Equal(t, "New", replaced.Name)
	assert.True(t, replaced.Revoked)
	assert.Nil(t, replaced.SHA1, "replacement clears omitted fields")
	assert.EqualValues(t, 2, replaced.Version)
	assert.Equal(t, "creator", replaced.CreatedBy)
	assert.Equal(t, "editor", replaced.UpdatedBy)
	assert.Equal(t, created.CreatedAt, replaced.CreatedAt, "created_at never changes")
	assert.True(t, replaced.UpdatedAt.After(created.UpdatedAt))

	_, err = repo.Replace(ctx, md5, threat.Attributes{Name: "Stale"}.Normalize(), "editor", []int64{1})
	assert.ErrorIs(t, err, threat.ErrVersionMismatch)

	_, err = repo.Replace(ctx, "ffffffffffffffffffffffffffffffff", threat.Attributes{Name: "X"}.Normalize(), "editor", nil)
	assert.ErrorIs(t, err, threat.ErrNotFound)

	got, err := repo.Replace(ctx, md5, threat.Attributes{Name: "List"}.Normalize(), "editor", []int64{1, 2})
	require.NoError(t, err, "any version of the list matches")
	assert.EqualValues(t, 3, got.Version)
}

func TestRepositoryBlindReplaceOfForeignRecord(t *testing.T) {
	t.Parallel()
	pool, _ := pgtest.NewDB(t)
	repo := postgres.NewThreatRepository(pool)
	ctx := context.Background()
	_, err := repo.Create(ctx, md5, threat.Attributes{Name: "A"}.Normalize(), "partner-a")
	require.NoError(t, err)

	_, err = repo.Replace(ctx, md5, threat.Attributes{Name: "B"}.Normalize(), "partner-b", nil)
	assert.ErrorIs(t, err, threat.ErrPreconditionRequired)

	got, err := repo.Replace(ctx, md5, threat.Attributes{Name: "A2"}.Normalize(), "partner-a", nil)
	require.NoError(t, err, "the last author may replace their own data")
	assert.EqualValues(t, 2, got.Version)
}

func TestHistoryKeepsEveryVersion(t *testing.T) {
	t.Parallel()
	pool, _ := pgtest.NewDB(t)
	repo := postgres.NewThreatRepository(pool)
	ctx := context.Background()
	_, err := repo.Create(ctx, md5, threat.Attributes{Name: "From A", Zone: threat.ZoneRed, Severity: threat.SeverityHigh}.Normalize(), "partner-a")
	require.NoError(t, err)
	_, err = repo.Replace(ctx, md5, threat.Attributes{Name: "From B", Zone: threat.ZoneGreen}.Normalize(), "partner-b", []int64{1})
	require.NoError(t, err)

	rows, err := pool.Query(ctx, `SELECT version, changed_by, snapshot->>'name', snapshot->>'zone'
		FROM threat_history WHERE md5 = $1 ORDER BY version`, md5)
	require.NoError(t, err)
	type entry struct {
		Version        int64
		By, Name, Zone string
	}
	var got []entry
	for rows.Next() {
		var e entry
		require.NoError(t, rows.Scan(&e.Version, &e.By, &e.Name, &e.Zone))
		got = append(got, e)
	}
	require.NoError(t, rows.Err())
	assert.Equal(t, []entry{
		{1, "partner-a", "From A", "red"},
		{2, "partner-b", "From B", "green"},
	}, got, "the data of partner A survives the replacement")

	_, err = repo.Replace(ctx, md5, threat.Attributes{Name: "Stale"}.Normalize(), "partner-c", []int64{1})
	require.ErrorIs(t, err, threat.ErrVersionMismatch)
	var count int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM threat_history`).Scan(&count))
	assert.Equal(t, 2, count, "failed attempts leave no history")
}

func TestSHA256BelongsToOneRecord(t *testing.T) {
	t.Parallel()
	pool, _ := pgtest.NewDB(t)
	repo := postgres.NewThreatRepository(pool)
	ctx := context.Background()
	sha, sha1 := ptr(strings.Repeat("a", 64)), ptr(strings.Repeat("c", 40))
	other := strings.Repeat("b", 32)
	_, err := repo.Create(ctx, md5, threat.Attributes{Name: "X", SHA256: sha, SHA1: sha1}.Normalize(), "a")
	require.NoError(t, err)

	_, err = repo.Create(ctx, other, threat.Attributes{Name: "Y", SHA256: sha}.Normalize(), "a")
	assert.ErrorIs(t, err, threat.ErrHashConflict)

	_, err = repo.Create(ctx, other, threat.Attributes{Name: "Y", SHA1: sha1}.Normalize(), "a")
	require.NoError(t, err, "SHA-1 collisions exist, so equal SHA-1 is allowed")

	_, err = repo.Replace(ctx, other, threat.Attributes{Name: "Y", SHA256: sha}.Normalize(), "a", nil)
	assert.ErrorIs(t, err, threat.ErrHashConflict)
}

func TestHistoryAndMigrationsSurviveRollback(t *testing.T) {
	t.Parallel()
	pool, _ := pgtest.NewDB(t)
	ctx := context.Background()
	require.NoError(t, postgres.MigrateDown(ctx, pool), "the latest migration can be rolled back")
	var exists bool
	require.NoError(t, pool.QueryRow(ctx, `SELECT to_regclass('threat_history') IS NOT NULL`).Scan(&exists))
	assert.False(t, exists)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	require.NoError(t, postgres.Migrate(ctx, pool, logger), "and applied again")
}

// TestRepositoryConcurrentReplace verifies optimistic locking under a real
// race: of N writers holding the same version exactly one succeeds.
func TestRepositoryConcurrentReplace(t *testing.T) {
	t.Parallel()
	pool, _ := pgtest.NewDB(t)
	repo := postgres.NewThreatRepository(pool)
	ctx := context.Background()
	_, err := repo.Create(ctx, md5, threat.Attributes{Name: "v1"}.Normalize(), "a")
	require.NoError(t, err)

	const writers = 8
	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		ok, stale int
	)
	for range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := repo.Replace(ctx, md5, threat.Attributes{Name: "v2"}.Normalize(), "w", []int64{1})
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				ok++
			case errors.Is(err, threat.ErrVersionMismatch):
				stale++
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()
	assert.Equal(t, 1, ok)
	assert.Equal(t, writers-1, stale)
}

// TestDatabaseConstraints checks the last line of defence: even if the
// application were bypassed, the schema rejects invalid data.
func TestDatabaseConstraints(t *testing.T) {
	t.Parallel()
	pool, _ := pgtest.NewDB(t)
	ctx := context.Background()
	const insert = `INSERT INTO threats (md5, name, created_by, updated_by) VALUES ($1, $2, 'a', 'a')`

	tests := map[string]struct {
		sql  string
		args []any
	}{
		"upper-case md5":   {insert, []any{strings.ToUpper(md5), "X"}},
		"short md5":        {insert, []any{"abc", "X"}},
		"empty name":       {insert, []any{md5, ""}},
		"long name":        {insert, []any{md5, strings.Repeat("a", 256)}},
		"unknown zone":     {`INSERT INTO threats (md5, name, zone, created_by, updated_by) VALUES ($1, 'X', 'blue', 'a', 'a')`, []any{md5}},
		"unknown type":     {`INSERT INTO threats (md5, name, types, created_by, updated_by) VALUES ($1, 'X', '{Trojan}', 'a', 'a')`, []any{md5}},
		"severity vs zone": {`INSERT INTO threats (md5, name, zone, severity, created_by, updated_by) VALUES ($1, 'X', 'green', 'high', 'a', 'a')`, []any{md5}},
		"seen order":       {`INSERT INTO threats (md5, name, first_seen_at, last_seen_at, created_by, updated_by) VALUES ($1, 'X', now(), now() - interval '1 day', 'a', 'a')`, []any{md5}},
		"negative size":    {`INSERT INTO threats (md5, name, file_size, created_by, updated_by) VALUES ($1, 'X', -1, 'a', 'a')`, []any{md5}},
		"bad sha256":       {`INSERT INTO threats (md5, name, sha256, created_by, updated_by) VALUES ($1, 'X', 'abc', 'a', 'a')`, []any{md5}},
		"unknown tlp":      {`INSERT INTO threats (md5, name, tlp, created_by, updated_by) VALUES ($1, 'X', 'white', 'a', 'a')`, []any{md5}},
		"confidence range": {`INSERT INTO threats (md5, name, confidence, created_by, updated_by) VALUES ($1, 'X', 101, 'a', 'a')`, []any{md5}},
		"ancient date":     {`INSERT INTO threats (md5, name, first_seen_at, created_by, updated_by) VALUES ($1, 'X', '0001-01-01', 'a', 'a')`, []any{md5}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := pool.Exec(ctx, tt.sql, tt.args...)
			var pgErr *pgconn.PgError
			require.True(t, errors.As(err, &pgErr), "want a PostgreSQL error, got %v", err)
			assert.Equal(t, "23514", pgErr.Code, "check_violation")
		})
	}
}

func TestMigrationsAreIdempotent(t *testing.T) {
	t.Parallel()
	pool, _ := pgtest.NewDB(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	require.NoError(t, postgres.Migrate(context.Background(), pool, logger), "second run is a no-op")
}

func TestUnreachableDatabaseIsTemporary(t *testing.T) {
	t.Parallel()
	pool, err := pgxpool.New(context.Background(), "postgres://u:p@127.0.0.1:1/x?connect_timeout=1")
	require.NoError(t, err, "the pool connects lazily")
	defer pool.Close()

	_, err = postgres.NewThreatRepository(pool).Get(context.Background(), md5)
	assert.ErrorIs(t, err, threat.ErrUnavailable)
}

func TestNewPoolDoesNotLeakPassword(t *testing.T) {
	t.Parallel()
	_, err := postgres.NewPool(context.Background(), postgres.PoolConfig{URL: "postgres://user:s3cret@%zz"})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "s3cret")
}
