// Package server wires the application together (composition root) and runs
// the public API server and the internal ops server until shutdown.
package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"threat-exchange/internal/auth"
	"threat-exchange/internal/config"
	"threat-exchange/internal/observability"
	"threat-exchange/internal/ratelimit"
	"threat-exchange/internal/service"
	"threat-exchange/internal/storage/postgres"
	"threat-exchange/internal/transport/httpapi"
)

// Run starts the service and blocks until ctx is cancelled (e.g. on SIGTERM)
// or a server fails. Shutdown is graceful: readiness is withdrawn first, then
// in-flight requests are allowed to finish within HTTP_SHUTDOWN_TIMEOUT.
func Run(ctx context.Context, cfg config.Config, logger *slog.Logger) error {
	pool, err := postgres.NewPool(ctx, postgres.PoolConfig{
		URL:              cfg.DB.URL,
		MaxConns:         cfg.DB.MaxConns,
		MinConns:         cfg.DB.MinConns,
		MaxConnLifetime:  cfg.DB.MaxConnLifetime,
		MaxConnIdleTime:  cfg.DB.MaxConnIdleTime,
		StatementTimeout: cfg.DB.StatementTimeout,
		ConnectTimeout:   cfg.DB.ConnectTimeout,
	})
	if err != nil {
		return fmt.Errorf("connect to database: %w", err)
	}
	defer pool.Close()

	if cfg.MigrateOnStart {
		if err := postgres.Migrate(ctx, pool, logger); err != nil {
			return err
		}
	}

	app, err := New(cfg, pool, logger)
	if err != nil {
		return err
	}
	return app.Serve(ctx)
}

// App is an assembled, ready-to-serve application.
type App struct {
	cfg      config.Config
	logger   *slog.Logger
	pool     *pgxpool.Pool
	api      *http.Server
	ops      *http.Server
	reloader *certReloader
	keys     *auth.Reloadable
	limiters []*ratelimit.Limiter
	ready    atomic.Bool
}

// New assembles the application from its configuration and a database pool.
func New(cfg config.Config, pool *pgxpool.Pool, logger *slog.Logger) (*App, error) {
	keys, err := auth.ParseKeyStore(cfg.Auth.APIKeys)
	if err != nil {
		return nil, fmt.Errorf("load API keys: %w", err)
	}
	proxies, err := cfg.HTTP.TrustedProxyPrefixes()
	if err != nil {
		return nil, err
	}
	metrics := observability.NewMetrics()
	a := &App{cfg: cfg, logger: logger, pool: pool, keys: auth.NewReloadable(keys)}

	var authenticator auth.Authenticator = a.keys
	if cfg.Auth.BindClientCert {
		authenticator = auth.CertBound{Next: authenticator}
	}

	hc := httpapi.Config{
		Service:       service.New(postgres.NewThreatRepository(pool), nil),
		Authenticator: authenticator,
		ClientIP:      httpapi.NewClientIP(proxies),
		MaxBodyBytes:  cfg.HTTP.MaxBodyBytes,
		Logger:        logger,
		Metrics:       metrics,
	}
	if cfg.RateLimit.Enabled {
		hc.IPLimiter = ratelimit.New(ratelimit.Config{Rate: cfg.RateLimit.IPRate, Burst: cfg.RateLimit.IPBurst})
		hc.KeyLimiter = ratelimit.New(ratelimit.Config{Rate: cfg.RateLimit.KeyRate, Burst: cfg.RateLimit.KeyBurst})
		a.limiters = []*ratelimit.Limiter{hc.IPLimiter, hc.KeyLimiter}
	}
	apiHandler, err := httpapi.NewHandler(hc)
	if err != nil {
		return nil, err
	}

	a.api = &http.Server{
		Addr:              cfg.HTTP.Addr,
		Handler:           withTimeout(apiHandler, cfg.HTTP.HandlerTimeout),
		ReadHeaderTimeout: cfg.HTTP.ReadHeaderTimeout,
		ReadTimeout:       cfg.HTTP.ReadTimeout,
		WriteTimeout:      cfg.HTTP.WriteTimeout,
		IdleTimeout:       cfg.HTTP.IdleTimeout,
		MaxHeaderBytes:    cfg.HTTP.MaxHeaderBytes,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
	if cfg.TLS.Enabled {
		a.reloader, err = newCertReloader(cfg.TLS.CertFile, cfg.TLS.KeyFile)
		if err != nil {
			return nil, err
		}
		a.api.TLSConfig, err = buildTLSConfig(cfg.TLS, a.reloader)
		if err != nil {
			return nil, err
		}
	}

	opsMux := http.NewServeMux()
	opsMux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	opsMux.HandleFunc("GET /readyz", a.readyz)
	opsMux.Handle("GET /metrics", metrics.Handler())
	a.ops = &http.Server{
		Addr:              cfg.Ops.Addr,
		Handler:           opsMux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
	return a, nil
}

// readyz reports whether the instance can serve traffic: it is not shutting
// down and the database is reachable.
func (a *App) readyz(w http.ResponseWriter, r *http.Request) {
	if !a.ready.Load() {
		http.Error(w, "shutting down", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := a.pool.Ping(ctx); err != nil {
		a.logger.WarnContext(ctx, "readiness check failed", slog.Any("error", err))
		http.Error(w, "database unavailable", http.StatusServiceUnavailable)
		return
	}
	_, _ = w.Write([]byte("ready\n"))
}

// Serve listens on the configured addresses and blocks until ctx is done.
func (a *App) Serve(ctx context.Context) error {
	apiLn, err := net.Listen("tcp", a.cfg.HTTP.Addr)
	if err != nil {
		return fmt.Errorf("listen API: %w", err)
	}
	opsLn, err := net.Listen("tcp", a.cfg.Ops.Addr)
	if err != nil {
		_ = apiLn.Close()
		return fmt.Errorf("listen ops: %w", err)
	}
	return a.ServeListeners(ctx, apiLn, opsLn)
}

// ServeListeners serves on already opened listeners (used by tests).
func (a *App) ServeListeners(ctx context.Context, apiLn, opsLn net.Listener) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	for _, l := range a.limiters {
		go l.Run(ctx)
	}
	if a.reloader != nil || a.cfg.Auth.APIKeysFile != "" {
		// Register before serving so that an early SIGHUP is never handled
		// by the default action (process termination).
		hup := make(chan os.Signal, 1)
		signal.Notify(hup, syscall.SIGHUP)
		defer signal.Stop(hup)
		go a.reloadOnSignal(ctx, hup)
	}

	errc := make(chan error, 2)
	go func() {
		a.logger.Info("ops server listening", slog.String("addr", opsLn.Addr().String()))
		errc <- serveErr(a.ops.Serve(opsLn))
	}()
	go func() {
		if a.api.TLSConfig != nil {
			a.logger.Info("API server listening (TLS)", slog.String("addr", apiLn.Addr().String()),
				slog.Bool("mtls", a.api.TLSConfig.ClientAuth == tls.RequireAndVerifyClientCert))
			// ServeTLS, unlike Serve on a TLS listener, also enables HTTP/2.
			// The certificate comes from TLSConfig.GetCertificate.
			errc <- serveErr(a.api.ServeTLS(apiLn, "", ""))
			return
		}
		a.logger.Warn("API server listening WITHOUT TLS; use only behind a TLS-terminating proxy",
			slog.String("addr", apiLn.Addr().String()))
		errc <- serveErr(a.api.Serve(apiLn))
	}()
	a.ready.Store(true)

	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-errc:
	}

	a.ready.Store(false)
	a.logger.Info("shutting down")
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), a.cfg.HTTP.ShutdownTimeout)
	defer cancelShutdown()
	err := errors.Join(runErr, a.api.Shutdown(shutdownCtx), a.ops.Shutdown(shutdownCtx))
	a.logger.Info("stopped")
	return err
}

func (a *App) reloadOnSignal(ctx context.Context, ch <-chan os.Signal) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-ch:
			if err := a.Reload(); err != nil {
				a.logger.Error("reload failed; keeping the previous values for the failed parts", slog.Any("error", err))
				continue
			}
			a.logger.Info("reload completed", slog.Int("api_keys", a.keys.Len()))
		}
	}
}

// Reload rereads the TLS certificate and, when they come from a file, the API
// keys. A part that fails to load keeps its previous value. It runs on SIGHUP.
func (a *App) Reload() error {
	var errs []error
	if a.reloader != nil {
		errs = append(errs, a.reloader.Reload())
	}
	if path := a.cfg.Auth.APIKeysFile; path != "" {
		errs = append(errs, a.reloadKeys(path))
	}
	return errors.Join(errs...)
}

func (a *App) reloadKeys(path string) error {
	spec, err := os.ReadFile(path) //nolint:gosec // path comes from trusted configuration
	if err != nil {
		return fmt.Errorf("read API keys: %w", err)
	}
	keys, err := auth.ParseKeyStore(string(spec))
	if err != nil {
		return fmt.Errorf("load API keys: %w", err)
	}
	a.keys.Store(keys)
	return nil
}

func serveErr(err error) error {
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// withTimeout bounds request processing time; the deadline propagates to
// database queries through the context.
func withTimeout(next http.Handler, d time.Duration) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), d)
		defer cancel()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
