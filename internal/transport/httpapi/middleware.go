package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"threat-exchange/internal/api"
	"threat-exchange/internal/auth"
	"threat-exchange/internal/observability"
	"threat-exchange/internal/ratelimit"
)

// HeaderRequestID carries the request correlation ID.
const HeaderRequestID = "X-Request-ID"

var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// requestInfo is shared by the middleware chain through the context. Inner
// middleware fills fields (e.g. principal) that outer middleware (access log)
// reads after the request completes.
type requestInfo struct {
	id        string
	principal string
	route     string
}

type requestInfoKey struct{}

func infoFrom(ctx context.Context) *requestInfo {
	if ri, ok := ctx.Value(requestInfoKey{}).(*requestInfo); ok {
		return ri
	}
	return nil
}

// RequestIDFrom returns the request ID stored in ctx, if any.
func RequestIDFrom(ctx context.Context) string {
	if ri := infoFrom(ctx); ri != nil {
		return ri.id
	}
	return ""
}

// statusRecorder captures the response status code.
type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.wroteHeader {
		s.status = code
		s.wroteHeader = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if !s.wroteHeader {
		s.WriteHeader(http.StatusOK)
	}
	return s.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// requestContext assigns a request ID (accepting a well-formed one from the
// client or a proxy), resolves the route pattern for metrics and stores the
// shared requestInfo in the context.
func requestContext(mux *http.ServeMux) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := r.Header.Get(HeaderRequestID)
			if !requestIDPattern.MatchString(id) {
				id = uuid.NewString()
			}
			w.Header().Set(HeaderRequestID, id)
			ri := &requestInfo{id: id, route: "unmatched"}
			if _, pattern := mux.Handler(r); pattern != "" {
				ri.route = pattern
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestInfoKey{}, ri)))
		})
	}
}

// recoverer converts panics into 500 responses instead of dropping the
// connection, and logs the stack trace.
func recoverer(logger *slog.Logger, m *observability.Metrics) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			defer func() {
				v := recover()
				if v == nil {
					return
				}
				if err, ok := v.(error); ok && errors.Is(err, http.ErrAbortHandler) {
					panic(v)
				}
				m.PanicsTotal.Inc()
				logger.ErrorContext(r.Context(), "panic recovered",
					slog.Any("panic", v), slog.String("stack", string(debug.Stack())))
				if !rec.wroteHeader {
					writeError(rec, r, http.StatusInternalServerError, api.ErrorResponseCodeInternal, msgInternal, "", nil)
				}
			}()
			next.ServeHTTP(rec, r)
		})
	}
}

// observe records metrics and writes a structured access log entry.
// API keys and request bodies are never logged.
func observe(logger *slog.Logger, m *observability.Metrics) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			m.InFlight.Inc()
			defer m.InFlight.Dec()

			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, r)

			elapsed := time.Since(start)
			route := "unmatched"
			principal := ""
			if ri := infoFrom(r.Context()); ri != nil {
				route, principal = ri.route, ri.principal
			}
			m.RequestsTotal.WithLabelValues(r.Method, route, strconv.Itoa(rec.status)).Inc()
			m.RequestDuration.WithLabelValues(r.Method, route).Observe(elapsed.Seconds())

			level := slog.LevelInfo
			if rec.status >= 500 {
				level = slog.LevelError
			} else if rec.status >= 400 {
				level = slog.LevelWarn
			}
			logger.LogAttrs(r.Context(), level, "http request",
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.String("route", route),
				slog.Int("status", rec.status),
				slog.Duration("duration", elapsed),
				slog.String("principal", principal),
				slog.String("remote", r.RemoteAddr),
				slog.String("user_agent", r.UserAgent()),
			)
		})
	}
}

// securityHeaders sets defensive response headers. The API serves only JSON,
// so the strictest CSP and framing policy apply.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Cache-Control", "no-store")
		if r.TLS != nil {
			h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

// limitBody rejects declared oversized bodies early and caps the number of
// bytes read from any body.
func limitBody(maxBytes int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ContentLength > maxBytes {
				writeError(w, r, http.StatusRequestEntityTooLarge, api.ErrorResponseCodePayloadTooLarge, msgTooLarge, "", nil)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			next.ServeHTTP(w, r)
		})
	}
}

// rateLimit rejects requests that exceed the limit for the key returned by
// keyFn. An empty key skips limiting.
func rateLimit(l *ratelimit.Limiter, scope string, keyFn func(*http.Request) string, m *observability.Metrics) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := keyFn(r)
			if key != "" {
				if ok, wait := l.Allow(key); !ok {
					m.RateLimitedTotal.WithLabelValues(scope).Inc()
					w.Header().Set("Retry-After", strconv.Itoa(ratelimit.RetryAfterSeconds(wait)))
					writeError(w, r, http.StatusTooManyRequests, api.ErrorResponseCodeRateLimited, msgRateLimited, "", nil)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// authenticate identifies the client and stores the principal in the
// context. It responds 401 without revealing whether a key exists.
func authenticate(a auth.Authenticator, logger *slog.Logger, m *observability.Metrics) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, err := a.Authenticate(r)
			if err != nil {
				reason := "invalid"
				if errors.Is(err, auth.ErrMissingCredentials) {
					reason = "missing"
				}
				m.AuthFailuresTotal.WithLabelValues(reason).Inc()
				logger.WarnContext(r.Context(), "authentication failed", slog.String("reason", reason))
				w.Header().Set("WWW-Authenticate", `ApiKey header="`+auth.HeaderAPIKey+`"`)
				writeError(w, r, http.StatusUnauthorized, api.ErrorResponseCodeUnauthorized, msgUnauth,
					"Provide a valid API key in the "+auth.HeaderAPIKey+" header", nil)
				return
			}
			if ri := infoFrom(r.Context()); ri != nil {
				ri.principal = p.ID
			}
			next.ServeHTTP(w, r.WithContext(auth.WithPrincipal(r.Context(), p)))
		})
	}
}

// authorize enforces the role model: safe methods require any role, all
// other methods require a role that can write.
func authorize(logger *slog.Logger, m *observability.Metrics) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, ok := auth.PrincipalFrom(r.Context())
			if !ok {
				writeError(w, r, http.StatusUnauthorized, api.ErrorResponseCodeUnauthorized, msgUnauth, "", nil)
				return
			}
			safe := r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions
			if !safe && !p.Role.CanWrite() {
				m.AuthFailuresTotal.WithLabelValues("forbidden").Inc()
				logger.WarnContext(r.Context(), "access denied",
					slog.String("principal", p.ID), slog.String("role", string(p.Role)))
				writeError(w, r, http.StatusForbidden, api.ErrorResponseCodeForbidden, msgForbidden,
					"Role "+string(p.Role)+" is not allowed to perform "+r.Method, nil)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ClientIP resolves the client address. X-Forwarded-For is honoured only
// when the direct peer is a trusted proxy; the right-most untrusted address
// is taken so that a client cannot spoof its IP by prepending entries.
type ClientIP struct {
	trusted []netip.Prefix
}

// NewClientIP creates a resolver trusting the given proxy networks.
func NewClientIP(trusted []netip.Prefix) *ClientIP {
	return &ClientIP{trusted: trusted}
}

// Resolve returns the client IP of r as a string.
func (c *ClientIP) Resolve(r *http.Request) string {
	peer := remoteAddr(r.RemoteAddr)
	if !peer.IsValid() {
		return r.RemoteAddr
	}
	if !c.isTrusted(peer) {
		return peer.String()
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		addr, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			break
		}
		addr = addr.Unmap()
		if !c.isTrusted(addr) {
			return addr.String()
		}
	}
	return peer.String()
}

func (c *ClientIP) isTrusted(a netip.Addr) bool {
	for _, p := range c.trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func remoteAddr(s string) netip.Addr {
	host, _, err := net.SplitHostPort(s)
	if err != nil {
		host = s
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap()
}
