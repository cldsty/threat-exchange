package httpapi

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/getkin/kin-openapi/openapi3filter"
	nethttpmiddleware "github.com/oapi-codegen/nethttp-middleware"

	"threat-exchange/internal/api"
	"threat-exchange/internal/auth"
	"threat-exchange/internal/observability"
	"threat-exchange/internal/ratelimit"
)

// Config holds the dependencies and settings of the API handler.
type Config struct {
	Service       ThreatService
	Authenticator auth.Authenticator
	// IPLimiter limits requests per client IP before authentication
	// (protects against key brute-forcing and floods).
	IPLimiter *ratelimit.Limiter
	// KeyLimiter limits requests per authenticated API key.
	KeyLimiter   *ratelimit.Limiter
	ClientIP     *ClientIP
	MaxBodyBytes int64
	Logger       *slog.Logger
	Metrics      *observability.Metrics
}

// NewHandler assembles the public API handler. Middleware order matters and
// is, from outermost to innermost:
//
//	request ID → panic recovery → metrics/access log → security headers →
//	per-IP rate limit → authentication → per-key rate limit →
//	authorization → body size limit → OpenAPI validation → handlers
//
// Unauthenticated and unauthorized requests are rejected before the body is
// read or validated, so anonymous clients learn nothing about the schema.
func NewHandler(c Config) (http.Handler, error) {
	if c.Service == nil || c.Authenticator == nil || c.Logger == nil || c.Metrics == nil {
		return nil, fmt.Errorf("httpapi: missing required dependency")
	}
	if c.ClientIP == nil {
		c.ClientIP = NewClientIP(nil)
	}
	if c.MaxBodyBytes <= 0 {
		c.MaxBodyBytes = 64 << 10
	}

	spec, err := api.GetSwagger()
	if err != nil {
		return nil, fmt.Errorf("load embedded OpenAPI spec: %w", err)
	}
	// Match routes by path only; the server URL in the spec is documentation.
	spec.Servers = nil

	validator := nethttpmiddleware.OapiRequestValidatorWithOptions(spec, &nethttpmiddleware.Options{
		Options: openapi3filter.Options{
			// Authentication is handled by our own middleware.
			AuthenticationFunc: openapi3filter.NoopAuthenticationFunc,
			MultiError:         true,
		},
		ErrorHandlerWithOpts: func(_ context.Context, err error, w http.ResponseWriter, r *http.Request, opts nethttpmiddleware.ErrorHandlerOpts) {
			validationErrorHandler(c.Logger)(w, r, err, opts.StatusCode)
		},
		SilenceServersWarning: true,
	})

	mux := http.NewServeMux()
	strict := api.NewStrictHandlerWithOptions(NewHandlers(c.Service, c.Logger), nil, api.StrictHTTPServerOptions{
		RequestErrorHandlerFunc:  requestErrorHandler,
		ResponseErrorHandlerFunc: responseErrorHandler(c.Logger),
	})
	api.HandlerWithOptions(strict, api.StdHTTPServerOptions{
		BaseRouter:       mux,
		ErrorHandlerFunc: requestErrorHandler,
	})

	var h http.Handler = mux
	h = validator(h)
	h = limitBody(c.MaxBodyBytes)(h)
	h = authorize(c.Logger, c.Metrics)(h)
	if c.KeyLimiter != nil {
		h = rateLimit(c.KeyLimiter, "key", principalKey, c.Metrics)(h)
	}
	h = authenticate(c.Authenticator, c.Logger, c.Metrics)(h)
	if c.IPLimiter != nil {
		h = rateLimit(c.IPLimiter, "ip", c.ClientIP.Resolve, c.Metrics)(h)
	}
	h = securityHeaders(h)
	h = observe(c.Logger, c.Metrics)(h)
	h = recoverer(c.Logger, c.Metrics)(h)
	h = requestContext(mux)(h)
	return h, nil
}

func principalKey(r *http.Request) string {
	if p, ok := auth.PrincipalFrom(r.Context()); ok {
		return p.ID
	}
	return ""
}
