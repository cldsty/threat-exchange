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
//	request ID → metrics/access log → panic recovery → security headers →
//	per-IP rate limit → authentication → per-key rate limit →
//	authorization → body size limit → media type and JSON syntax →
//	OpenAPI validation → handlers
//
// Panic recovery sits inside the access log so that recovered requests are
// still counted and logged as 500. Unauthenticated and unauthorized requests
// are rejected before the body is read or validated, so anonymous clients
// learn nothing about the schema.
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

	mux := http.NewServeMux()
	validator := nethttpmiddleware.OapiRequestValidatorWithOptions(spec, &nethttpmiddleware.Options{
		Options: openapi3filter.Options{
			// Authentication is handled by our own middleware.
			AuthenticationFunc: openapi3filter.NoopAuthenticationFunc,
			MultiError:         true,
		},
		ErrorHandlerWithOpts: func(_ context.Context, err error, w http.ResponseWriter, r *http.Request, opts nethttpmiddleware.ErrorHandlerOpts) {
			validationErrorHandler(c.Logger, mux)(w, r, err, opts.StatusCode)
		},
		SilenceServersWarning: true,
	})

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
	h = headAsGet(h)
	h = jsonBody(h)
	h = limitBody(c.MaxBodyBytes)(h)
	h = authorize(c.Logger, c.Metrics)(h)
	if c.KeyLimiter != nil {
		h = rateLimit(c.KeyLimiter, "key", principalKey, c.Metrics)(h)
	}
	h = authenticate(c.Authenticator, c.Logger, c.Metrics)(h)
	if c.IPLimiter != nil {
		h = rateLimit(c.IPLimiter, "ip", c.ClientIP.LimitKey, c.Metrics)(h)
	}
	h = securityHeaders(h)
	h = recoverer(c.Logger, c.Metrics)(h)
	h = observe(c.Logger, c.Metrics, c.ClientIP)(h)
	h = requestContext(mux)(h)
	return h, nil
}

func principalKey(r *http.Request) string {
	if p, ok := auth.PrincipalFrom(r.Context()); ok {
		return p.ID
	}
	return ""
}
