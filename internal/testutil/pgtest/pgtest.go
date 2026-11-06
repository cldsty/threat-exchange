//go:build integration

// Package pgtest provides isolated PostgreSQL databases for integration
// tests. Each call creates a fresh database (migrated to the latest schema)
// on the server given by TEST_DB_URL and drops it when the test ends, so
// tests can run in parallel and never see each other's data.
package pgtest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log/slog"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"threat-exchange/internal/storage/postgres"
)

// EnvURL names the variable with an admin connection URL, e.g.
// postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable
const EnvURL = "TEST_DB_URL"

// NewDB returns a pool connected to a new, migrated database and its URL.
func NewDB(t *testing.T) (*pgxpool.Pool, string) {
	t.Helper()
	admin := os.Getenv(EnvURL)
	if admin == "" {
		t.Fatalf("%s is not set; start PostgreSQL (make db-up) and export it", EnvURL)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, admin)
	if err != nil {
		t.Fatalf("connect to %s: %v", EnvURL, err)
	}
	defer func() { _ = conn.Close(context.Background()) }()

	b := make([]byte, 6)
	_, _ = rand.Read(b)
	name := "tx_test_" + hex.EncodeToString(b)
	if _, err := conn.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatalf("create database: %v", err)
	}

	u, err := url.Parse(admin)
	if err != nil {
		t.Fatalf("parse %s: %v", EnvURL, err)
	}
	u.Path = "/" + name
	dbURL := u.String()

	pool, err := postgres.NewPool(ctx, postgres.PoolConfig{URL: dbURL, MaxConns: 10, StatementTimeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("connect to test database: %v", err)
	}
	t.Cleanup(func() {
		pool.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		c, err := pgx.Connect(ctx, admin)
		if err != nil {
			t.Logf("cleanup: connect: %v", err)
			return
		}
		defer func() { _ = c.Close(context.Background()) }()
		if _, err := c.Exec(ctx, "DROP DATABASE IF EXISTS "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)"); err != nil {
			t.Logf("cleanup: drop database: %v", err)
		}
	})

	if err := postgres.Migrate(ctx, pool, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return pool, dbURL
}
