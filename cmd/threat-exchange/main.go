// Command threat-exchange runs the threat information exchange service.
//
// Usage:
//
//	threat-exchange [serve]            run the API and ops servers (default)
//	threat-exchange migrate            apply database migrations and exit
//	threat-exchange keygen -id ID -role reader|writer
//	                                   generate an API key and its config line
//	threat-exchange devcerts -dir DIR  generate development TLS certificates
//	threat-exchange healthcheck        probe the local ops server (for Docker)
//	threat-exchange version            print the version
//
// Configuration is read from environment variables; see README.md.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"threat-exchange/internal/auth"
	"threat-exchange/internal/config"
	"threat-exchange/internal/devcerts"
	"threat-exchange/internal/observability"
	"threat-exchange/internal/server"
	"threat-exchange/internal/storage/postgres"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	cmd := "serve"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	switch cmd {
	case "serve":
		return cmdServe()
	case "migrate":
		return cmdMigrate()
	case "keygen":
		return cmdKeygen(args, stdout)
	case "devcerts":
		return cmdDevcerts(args, stdout)
	case "healthcheck":
		return cmdHealthcheck()
	case "version":
		_, err := fmt.Fprintln(stdout, version)
		return err
	case "help", "-h", "--help":
		_, err := fmt.Fprintln(stderr, "commands: serve, migrate, keygen, devcerts, healthcheck, version")
		return err
	default:
		return fmt.Errorf("unknown command %q (try: serve, migrate, keygen, devcerts, healthcheck, version)", cmd)
	}
}

func loadConfigAndLogger(load func() (config.Config, error)) (config.Config, *slog.Logger, error) {
	cfg, err := load()
	if err != nil {
		return config.Config{}, nil, fmt.Errorf("configuration: %w", err)
	}
	logger, err := newLogger(cfg.Log)
	if err != nil {
		return config.Config{}, nil, err
	}
	return cfg, logger, nil
}

func newLogger(c config.Log) (*slog.Logger, error) {
	lvl, err := c.SlogLevel()
	if err != nil {
		return nil, err
	}
	opts := &slog.HandlerOptions{Level: lvl}
	var h slog.Handler = slog.NewJSONHandler(os.Stdout, opts)
	if c.Format == "text" {
		h = slog.NewTextHandler(os.Stdout, opts)
	}
	return slog.New(observability.NewLogHandler(h)).
		With(slog.String("service", "threat-exchange"), slog.String("app_version", version)), nil
}

func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

func cmdServe() error {
	cfg, logger, err := loadConfigAndLogger(config.Load)
	if err != nil {
		return err
	}
	slog.SetDefault(logger)
	ctx, cancel := signalContext()
	defer cancel()
	logger.Info("starting", slog.String("api_addr", cfg.HTTP.Addr), slog.String("ops_addr", cfg.Ops.Addr),
		slog.Bool("tls", cfg.TLS.Enabled), slog.Bool("rate_limit", cfg.RateLimit.Enabled))
	if err := server.Run(ctx, cfg, logger); err != nil {
		logger.Error("service failed", slog.Any("error", err))
		return err
	}
	return nil
}

func cmdMigrate() error {
	cfg, logger, err := loadConfigAndLogger(config.LoadForMigrate)
	if err != nil {
		return err
	}
	ctx, cancel := signalContext()
	defer cancel()
	pool, err := postgres.NewPool(ctx, postgres.PoolConfig{URL: cfg.DB.URL, MaxConns: 2})
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := postgres.Migrate(ctx, pool, logger); err != nil {
		return err
	}
	logger.Info("migrations are up to date")
	return nil
}

func cmdKeygen(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	id := fs.String("id", "", "non-secret key identifier, e.g. partner-a")
	role := fs.String("role", string(auth.RoleReader), "role: reader or writer")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id == "" {
		return errors.New("keygen: -id is required")
	}
	line := *id + ":" + *role + ":" + strings.Repeat("0", 64)
	if _, err := auth.ParseKeyStore(line); err != nil {
		return fmt.Errorf("keygen: %w", err)
	}
	key, digest, err := auth.GenerateKey()
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout,
		"API key (give to the client, shown once): %s\nConfig entry for AUTH_API_KEYS:        %s:%s:%s\n",
		key, *id, *role, digest)
	return err
}

func cmdDevcerts(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("devcerts", flag.ContinueOnError)
	dir := fs.String("dir", "certs", "output directory")
	hosts := fs.String("hosts", "localhost,127.0.0.1,::1,threat-exchange", "comma-separated server DNS names and IPs")
	client := fs.String("client", "dev-client", "client certificate common name")
	ifMissing := fs.Bool("if-missing", false, "do nothing if certificates already exist")
	owner := fs.Int("owner", -1, "uid/gid to own the server key (e.g. 65532 for the distroless nonroot user)")
	validity := fs.Duration("validity", 90*24*time.Hour, "certificate validity")
	dbDir := fs.String("db-dir", "", "also write a certificate for PostgreSQL into this directory")
	dbHosts := fs.String("db-hosts", "db", "comma-separated DNS names of the PostgreSQL server")
	dbOwner := fs.Int("db-owner", -1, "uid/gid to own the PostgreSQL key (e.g. 70 in postgres:alpine images)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	created, err := devcerts.Generate(devcerts.Options{
		Dir: *dir, Hosts: strings.Split(*hosts, ","), ClientID: *client,
		Validity: *validity, IfMissing: *ifMissing, Owner: *owner,
		DBDir: *dbDir, DBHosts: strings.Split(*dbHosts, ","), DBOwner: *dbOwner,
	})
	if err != nil {
		return err
	}
	if !created {
		_, err = fmt.Fprintf(stdout, "certificates already exist in %s, skipping\n", *dir)
		return err
	}
	_, err = fmt.Fprintf(stdout, "development certificates written to %s\n", *dir)
	return err
}

// cmdHealthcheck is used by the Docker HEALTHCHECK: the distroless image has
// no shell or curl, so the binary probes its own ops endpoint.
func cmdHealthcheck() error {
	addr := os.Getenv("OPS_ADDR")
	if addr == "" {
		addr = ":8081"
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid OPS_ADDR: %w", err)
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// Liveness, not readiness: restarting the service would not fix a database
	// outage, and restarting every replica at once would only make it worse.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+net.JoinHostPort(host, port)+"/healthz", nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unhealthy: %s", resp.Status)
	}
	return nil
}
