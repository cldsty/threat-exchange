package observability

import (
	"context"
	"log/slog"
)

type requestIDKey struct{}

// WithRequestID returns a context carrying the request correlation ID.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, id)
}

// RequestID returns the correlation ID stored by WithRequestID, if any.
func RequestID(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

// NewLogHandler wraps h so that every record logged with a request context
// carries a request_id attribute. This is what lets an operator find the log
// entries for the request_id a client received in an error response.
func NewLogHandler(h slog.Handler) slog.Handler {
	return contextHandler{Handler: h}
}

type contextHandler struct {
	slog.Handler
}

// Handle implements slog.Handler.
func (h contextHandler) Handle(ctx context.Context, r slog.Record) error {
	if id := RequestID(ctx); id != "" {
		r.AddAttrs(slog.String("request_id", id))
	}
	return h.Handler.Handle(ctx, r)
}

// WithAttrs implements slog.Handler.
func (h contextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return contextHandler{Handler: h.Handler.WithAttrs(attrs)}
}

// WithGroup implements slog.Handler.
func (h contextHandler) WithGroup(name string) slog.Handler {
	return contextHandler{Handler: h.Handler.WithGroup(name)}
}
