// Package postgres implements persistence of threats in PostgreSQL using pgx.
// Schema migrations are embedded into the binary and applied with goose.
package postgres

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// PoolConfig holds connection pool settings.
type PoolConfig struct {
	URL             string
	MaxConns        int32
	MinConns        int32
	MaxConnLifetime time.Duration
	MaxConnIdleTime time.Duration
	// StatementTimeout is applied server-side to every statement so that a
	// runaway query cannot hold a connection forever.
	StatementTimeout time.Duration
	// ConnectTimeout bounds one attempt to connect to the server.
	ConnectTimeout time.Duration
}

// NewPool creates a connection pool and verifies connectivity.
func NewPool(ctx context.Context, c PoolConfig) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(c.URL)
	if err != nil {
		// Do not wrap err: it may contain the password from the URL.
		return nil, errors.New("parse database URL: invalid format")
	}
	if c.MaxConns > 0 {
		cfg.MaxConns = c.MaxConns
	}
	if c.MinConns > 0 {
		cfg.MinConns = c.MinConns
	}
	if c.MaxConnLifetime > 0 {
		cfg.MaxConnLifetime = c.MaxConnLifetime
	}
	if c.MaxConnIdleTime > 0 {
		cfg.MaxConnIdleTime = c.MaxConnIdleTime
	}
	if c.StatementTimeout > 0 {
		cfg.ConnConfig.RuntimeParams["statement_timeout"] = fmt.Sprint(c.StatementTimeout.Milliseconds())
	}
	if c.ConnectTimeout > 0 {
		cfg.ConnConfig.ConnectTimeout = c.ConnectTimeout
		// pgx applies ConnectTimeout to connecting, but not to resolving the
		// host name, which is what takes long when a DNS name goes away.
		cfg.ConnConfig.LookupFunc = func(ctx context.Context, host string) ([]string, error) {
			ctx, cancel := context.WithTimeout(ctx, c.ConnectTimeout)
			defer cancel()
			return net.DefaultResolver.LookupHost(ctx, host)
		}
	}
	cfg.ConnConfig.RuntimeParams["application_name"] = "threat-exchange"

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}
	return pool, nil
}

// Migrate applies all pending migrations. A PostgreSQL advisory lock makes
// it safe to run concurrently from several replicas.
func Migrate(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger) error {
	db := stdlib.OpenDBFromPool(pool)
	defer func() { _ = db.Close() }()
	return migrate(ctx, db, logger)
}

func migrate(ctx context.Context, db *sql.DB, logger *slog.Logger) error {
	locker, err := lock.NewPostgresSessionLocker()
	if err != nil {
		return fmt.Errorf("create migration locker: %w", err)
	}
	fsys, err := subFS()
	if err != nil {
		return err
	}
	provider, err := goose.NewProvider(goose.DialectPostgres, db, fsys, goose.WithSessionLocker(locker))
	if err != nil {
		return fmt.Errorf("create migration provider: %w", err)
	}
	results, err := provider.Up(ctx)
	if err != nil {
		return fmt.Errorf("apply migrations: %w", err)
	}
	for _, r := range results {
		logger.InfoContext(ctx, "migration applied",
			slog.Int64("version", r.Source.Version),
			slog.String("file", r.Source.Path),
			slog.Duration("duration", r.Duration))
	}
	return nil
}

// MigrateDown rolls back the latest migration. It is used to verify that
// migrations are reversible.
func MigrateDown(ctx context.Context, pool *pgxpool.Pool) error {
	db := stdlib.OpenDBFromPool(pool)
	defer func() { _ = db.Close() }()
	fsys, err := subFS()
	if err != nil {
		return err
	}
	provider, err := goose.NewProvider(goose.DialectPostgres, db, fsys)
	if err != nil {
		return fmt.Errorf("create migration provider: %w", err)
	}
	if _, err := provider.Down(ctx); err != nil {
		return fmt.Errorf("roll back migration: %w", err)
	}
	return nil
}

func subFS() (fs.FS, error) {
	fsys, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		return nil, fmt.Errorf("open embedded migrations: %w", err)
	}
	return fsys, nil
}
