// Package config loads the service configuration from environment variables
// (twelve-factor app). Secrets may alternatively be read from files
// (VAR_FILE), which works with Docker/Kubernetes secrets. The configuration
// is validated on start-up so that the service fails fast with a clear error.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/caarlos0/env/v11"
)

// Config is the complete service configuration.
type Config struct {
	Log       Log       `envPrefix:"LOG_"`
	HTTP      HTTP      `envPrefix:"HTTP_"`
	TLS       TLS       `envPrefix:"TLS_"`
	Ops       Ops       `envPrefix:"OPS_"`
	DB        DB        `envPrefix:"DB_"`
	Auth      Auth      `envPrefix:"AUTH_"`
	RateLimit RateLimit `envPrefix:"RATE_LIMIT_"`

	// MigrateOnStart applies database migrations before serving. In
	// production prefer the separate `migrate` command.
	MigrateOnStart bool `env:"MIGRATE_ON_START" envDefault:"false"`
}

// Log configures logging.
type Log struct {
	Level  string `env:"LEVEL" envDefault:"info"`  // debug, info, warn, error
	Format string `env:"FORMAT" envDefault:"json"` // json, text
}

// HTTP configures the public API server.
type HTTP struct {
	Addr              string        `env:"ADDR" envDefault:":8443"`
	ReadHeaderTimeout time.Duration `env:"READ_HEADER_TIMEOUT" envDefault:"5s"`
	ReadTimeout       time.Duration `env:"READ_TIMEOUT" envDefault:"10s"`
	WriteTimeout      time.Duration `env:"WRITE_TIMEOUT" envDefault:"15s"`
	IdleTimeout       time.Duration `env:"IDLE_TIMEOUT" envDefault:"60s"`
	HandlerTimeout    time.Duration `env:"HANDLER_TIMEOUT" envDefault:"10s"`
	ShutdownTimeout   time.Duration `env:"SHUTDOWN_TIMEOUT" envDefault:"15s"`
	MaxHeaderBytes    int           `env:"MAX_HEADER_BYTES" envDefault:"16384"`
	MaxBodyBytes      int64         `env:"MAX_BODY_BYTES" envDefault:"65536"`
	// TrustedProxies are CIDRs of reverse proxies whose X-Forwarded-For
	// header is trusted for client IP resolution.
	TrustedProxies []string `env:"TRUSTED_PROXIES" envSeparator:","`
}

// TLS configures transport security of the public API.
type TLS struct {
	// Enabled is true by default: the service is secure unless explicitly
	// told otherwise (e.g. behind a TLS-terminating proxy).
	Enabled  bool   `env:"ENABLED" envDefault:"true"`
	CertFile string `env:"CERT_FILE"`
	KeyFile  string `env:"KEY_FILE"`
	// ClientCAFile enables mutual TLS: clients must present a certificate
	// signed by this CA.
	ClientCAFile string `env:"CLIENT_CA_FILE"`
	MinVersion   string `env:"MIN_VERSION" envDefault:"1.2"` // 1.2 or 1.3
}

// Ops configures the internal server with health checks and metrics. It is
// not authenticated and must not be exposed publicly.
type Ops struct {
	Addr string `env:"ADDR" envDefault:":8081"`
}

// DB configures PostgreSQL access.
type DB struct {
	URL              string        `env:"URL"`
	URLFile          string        `env:"URL_FILE"`
	MaxConns         int32         `env:"MAX_CONNS" envDefault:"10"`
	MinConns         int32         `env:"MIN_CONNS" envDefault:"1"`
	MaxConnLifetime  time.Duration `env:"MAX_CONN_LIFETIME" envDefault:"30m"`
	MaxConnIdleTime  time.Duration `env:"MAX_CONN_IDLE_TIME" envDefault:"5m"`
	StatementTimeout time.Duration `env:"STATEMENT_TIMEOUT" envDefault:"5s"`
	// ConnectTimeout bounds one connection attempt, so that a request fails
	// quickly with 503 when the database is down.
	ConnectTimeout time.Duration `env:"CONNECT_TIMEOUT" envDefault:"2s"`
}

// Auth configures API key authentication.
type Auth struct {
	// APIKeys holds definitions "id:role:sha256hex" separated by commas or
	// newlines; APIKeysFile points to a file with the same content.
	APIKeys     string `env:"API_KEYS"`
	APIKeysFile string `env:"API_KEYS_FILE"`
	// BindClientCert requires the client certificate Common Name to equal the
	// ID of the presented API key. It needs TLS_CLIENT_CA_FILE.
	BindClientCert bool `env:"BIND_CLIENT_CERT" envDefault:"false"`
}

// RateLimit configures request rate limiting.
type RateLimit struct {
	Enabled  bool    `env:"ENABLED" envDefault:"true"`
	IPRate   float64 `env:"IP_RPS" envDefault:"50"`
	IPBurst  int     `env:"IP_BURST" envDefault:"100"`
	KeyRate  float64 `env:"KEY_RPS" envDefault:"20"`
	KeyBurst int     `env:"KEY_BURST" envDefault:"40"`
}

// Load reads the configuration from the environment and validates it.
func Load() (Config, error) {
	return LoadFrom(nil)
}

// LoadFrom is like Load but reads variables from environ when it is not nil
// (useful in tests).
func LoadFrom(environ map[string]string) (Config, error) {
	cfg, err := parse(environ)
	if err != nil {
		return Config{}, err
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// LoadForMigrate reads the configuration needed by the `migrate` command:
// only logging and database settings are validated, so migrations can run
// without API keys or certificates.
func LoadForMigrate() (Config, error) {
	cfg, err := parse(nil)
	if err != nil {
		return Config{}, err
	}
	if err := errors.Join(cfg.validateLog(), cfg.validateDB()); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func parse(environ map[string]string) (Config, error) {
	var cfg Config
	opts := env.Options{}
	if environ != nil {
		opts.Environment = environ
	}
	if err := env.ParseWithOptions(&cfg, opts); err != nil {
		return Config{}, fmt.Errorf("parse environment: %w", err)
	}
	if err := cfg.resolveFiles(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c *Config) resolveFiles() error {
	var err error
	if c.DB.URL, err = fromFile(c.DB.URL, c.DB.URLFile, "DB_URL"); err != nil {
		return err
	}
	if c.Auth.APIKeys, err = fromFile(c.Auth.APIKeys, c.Auth.APIKeysFile, "AUTH_API_KEYS"); err != nil {
		return err
	}
	return nil
}

func fromFile(value, path, name string) (string, error) {
	if path == "" {
		return value, nil
	}
	if value != "" {
		return "", fmt.Errorf("%s and %s_FILE are mutually exclusive", name, name)
	}
	b, err := os.ReadFile(path) //nolint:gosec // path comes from trusted configuration
	if err != nil {
		return "", fmt.Errorf("read %s_FILE: %w", name, err)
	}
	return strings.TrimSpace(string(b)), nil
}

// Validate checks the configuration for consistency. All problems are
// reported together.
func (c Config) Validate() error {
	errs := []error{c.validateLog(), c.validateDB()}
	if c.Auth.APIKeys == "" {
		errs = append(errs, errors.New("AUTH_API_KEYS (or AUTH_API_KEYS_FILE) is required"))
	}
	if c.Auth.BindClientCert && c.TLS.ClientCAFile == "" {
		errs = append(errs, errors.New("AUTH_BIND_CLIENT_CERT requires TLS_CLIENT_CA_FILE"))
	}
	if c.TLS.Enabled {
		if c.TLS.CertFile == "" || c.TLS.KeyFile == "" {
			errs = append(errs, errors.New("TLS_CERT_FILE and TLS_KEY_FILE are required when TLS is enabled"))
		}
		if c.TLS.MinVersion != "1.2" && c.TLS.MinVersion != "1.3" {
			errs = append(errs, fmt.Errorf("TLS_MIN_VERSION must be 1.2 or 1.3, got %q", c.TLS.MinVersion))
		}
	} else if c.TLS.ClientCAFile != "" {
		errs = append(errs, errors.New("TLS_CLIENT_CA_FILE requires TLS_ENABLED=true"))
	}
	if c.HTTP.MaxBodyBytes <= 0 || c.HTTP.MaxHeaderBytes <= 0 {
		errs = append(errs, errors.New("HTTP_MAX_BODY_BYTES and HTTP_MAX_HEADER_BYTES must be positive"))
	}
	for name, d := range map[string]time.Duration{
		"HTTP_READ_HEADER_TIMEOUT": c.HTTP.ReadHeaderTimeout,
		"HTTP_READ_TIMEOUT":        c.HTTP.ReadTimeout,
		"HTTP_WRITE_TIMEOUT":       c.HTTP.WriteTimeout,
		"HTTP_HANDLER_TIMEOUT":     c.HTTP.HandlerTimeout,
		"HTTP_SHUTDOWN_TIMEOUT":    c.HTTP.ShutdownTimeout,
	} {
		if d <= 0 {
			errs = append(errs, fmt.Errorf("%s must be positive", name))
		}
	}
	if c.HTTP.HandlerTimeout >= c.HTTP.WriteTimeout {
		errs = append(errs, errors.New("HTTP_HANDLER_TIMEOUT must be less than HTTP_WRITE_TIMEOUT"))
	}
	if _, err := c.HTTP.TrustedProxyPrefixes(); err != nil {
		errs = append(errs, err)
	}
	if c.RateLimit.Enabled && (c.RateLimit.IPRate <= 0 || c.RateLimit.KeyRate <= 0 ||
		c.RateLimit.IPBurst < 1 || c.RateLimit.KeyBurst < 1) {
		errs = append(errs, errors.New("rate limit rates must be positive and bursts at least 1"))
	}
	return errors.Join(errs...)
}

func (c Config) validateLog() error {
	var errs []error
	if _, err := c.Log.SlogLevel(); err != nil {
		errs = append(errs, err)
	}
	if c.Log.Format != "json" && c.Log.Format != "text" {
		errs = append(errs, fmt.Errorf("LOG_FORMAT must be json or text, got %q", c.Log.Format))
	}
	return errors.Join(errs...)
}

func (c Config) validateDB() error {
	var errs []error
	if c.DB.URL == "" {
		errs = append(errs, errors.New("DB_URL (or DB_URL_FILE) is required"))
	}
	if c.DB.MaxConns < 1 || c.DB.MinConns < 0 || c.DB.MinConns > c.DB.MaxConns {
		errs = append(errs, errors.New("DB_MIN_CONNS/DB_MAX_CONNS are inconsistent"))
	}
	return errors.Join(errs...)
}

// SlogLevel converts the configured level to slog.Level.
func (l Log) SlogLevel() (slog.Level, error) {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(l.Level)); err != nil {
		return 0, fmt.Errorf("LOG_LEVEL must be debug, info, warn or error, got %q", l.Level)
	}
	return lvl, nil
}

// TrustedProxyPrefixes parses HTTP_TRUSTED_PROXIES.
func (h HTTP) TrustedProxyPrefixes() ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(h.TrustedProxies))
	for _, s := range h.TrustedProxies {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("HTTP_TRUSTED_PROXIES: invalid CIDR %q", s)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}
