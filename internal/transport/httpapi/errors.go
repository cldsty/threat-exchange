package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"

	"threat-exchange/internal/api"
	"threat-exchange/internal/domain/threat"
)

// retryAfterUnavailable is the Retry-After value in seconds when the storage is
// unavailable: long enough for a database failover or restart to progress.
const retryAfterUnavailable = 5

const hashConflictDetails = "One file cannot have two MD5 digests: check the hashes of this record and of the existing one"

// Messages are stable and never include internal details (SQL errors, stack
// traces); those go only to the server log, correlated by request_id.
const (
	msgValidation      = "Request validation failed"
	msgBadRequest      = "Bad request"
	msgNotFound        = "Threat not found"
	msgConflict        = "Threat already exists"
	msgPrecond         = "Threat was modified concurrently"
	msgPrecondRequired = "If-Match is required to replace this threat"
	msgHashConflict    = "SHA-256 belongs to another threat"
	msgInternal        = "Internal server error"
	msgUnauth          = "Authentication required"
	msgForbidden       = "Insufficient permissions"
	msgRateLimited     = "Too many requests"
	msgTooLarge        = "Request body too large"
	msgMediaType       = "Unsupported media type"
	msgUnavailable     = "Service temporarily unavailable"
)

func errorBody(ctx context.Context, code api.ErrorResponseCode, message, details string, fields []api.FieldError) api.ErrorResponse {
	e := api.ErrorResponse{Code: code, Message: message}
	if details != "" {
		e.Details = &details
	}
	if len(fields) > 0 {
		e.Fields = &fields
	}
	if id := RequestIDFrom(ctx); id != "" {
		e.RequestId = &id
	}
	return e
}

// writeError writes an ErrorResponse outside of the generated handlers
// (middleware, validator, router).
func writeError(w http.ResponseWriter, r *http.Request, status int, code api.ErrorResponseCode, message, details string, fields []api.FieldError) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorBody(r.Context(), code, message, details, fields))
}

func fieldErrors(ve *threat.ValidationError) []api.FieldError {
	out := make([]api.FieldError, 0, len(ve.Fields))
	for _, f := range ve.Fields {
		out = append(out, api.FieldError{Field: f.Field, Message: f.Message})
	}
	return out
}

// validationErrorHandler converts errors of the OpenAPI request validator
// into ErrorResponse. It implements nethttpmiddleware.ErrorHandlerWithOpts.
func validationErrorHandler(logger *slog.Logger, mux *http.ServeMux) func(w http.ResponseWriter, r *http.Request, err error, statusCode int) {
	return func(w http.ResponseWriter, r *http.Request, err error, statusCode int) {
		var tooLarge *http.MaxBytesError
		switch {
		case errors.As(err, &tooLarge):
			writeError(w, r, http.StatusRequestEntityTooLarge, api.ErrorResponseCodePayloadTooLarge, msgTooLarge, "", nil)
		case errors.Is(err, routers.ErrPathNotFound):
			writeError(w, r, http.StatusNotFound, api.ErrorResponseCodeNotFound, "Resource not found", "", nil)
		case errors.Is(err, routers.ErrMethodNotAllowed):
			w.Header().Set("Allow", strings.Join(allowedMethods(mux, r), ", "))
			writeError(w, r, http.StatusMethodNotAllowed, api.ErrorResponseCodeMethodNotAllowed, "Method not allowed", "", nil)
		case statusCode >= 500:
			logger.ErrorContext(r.Context(), "request validator failed", slog.Any("error", err))
			writeError(w, r, http.StatusInternalServerError, api.ErrorResponseCodeInternal, msgInternal, "", nil)
		default:
			writeError(w, r, http.StatusBadRequest, api.ErrorResponseCodeValidationFailed, msgValidation, "", specFieldErrors(err))
		}
	}
}

// allowedMethods lists the methods that have a route for the path of r.
func allowedMethods(mux *http.ServeMux, r *http.Request) []string {
	var out []string
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut} {
		probe := r.Clone(r.Context())
		probe.Method = method
		if _, pattern := mux.Handler(probe); pattern != "" {
			out = append(out, method)
		}
	}
	return out
}

// specFieldErrors extracts per-field problems from kin-openapi errors without
// echoing whole schemas back to the client.
func specFieldErrors(err error) []api.FieldError {
	out := toFieldErrors(err, "")
	if len(out) == 0 {
		out = append(out, api.FieldError{Field: "request", Message: "does not match the API specification"})
	}
	return out
}

// toFieldErrors walks the (possibly nested) error tree produced by
// kin-openapi. prefix is the name of the enclosing parameter, if any.
func toFieldErrors(err error, prefix string) []api.FieldError {
	switch e := err.(type) { //nolint:errorlint // wrapped errors are unwrapped below
	case openapi3.MultiError:
		var out []api.FieldError
		for _, item := range e {
			out = append(out, toFieldErrors(item, prefix)...)
		}
		return out
	case *openapi3filter.RequestError:
		if e.Parameter != nil {
			prefix = e.Parameter.Name
		}
		if e.Err != nil {
			if out := toFieldErrors(e.Err, prefix); len(out) > 0 {
				return out
			}
		}
		msg := e.Reason
		if msg == "" && e.Err != nil {
			msg = e.Err.Error()
		}
		if msg == "" {
			msg = "invalid value"
		}
		return []api.FieldError{{Field: fieldName(prefix, nil), Message: msg}}
	case *openapi3.SchemaError:
		return []api.FieldError{{Field: fieldName(prefix, e.JSONPointer()), Message: e.Reason}}
	}
	if u := errors.Unwrap(err); u != nil {
		return toFieldErrors(u, prefix)
	}
	return nil
}

func fieldName(prefix string, pointer []string) string {
	path := strings.Join(pointer, ".")
	switch {
	case prefix != "" && path != "":
		return prefix + "." + path
	case prefix != "":
		return prefix
	case path != "":
		return path
	default:
		return "body"
	}
}

// requestErrorHandler handles errors raised by the generated code while
// decoding a request (malformed JSON, invalid path parameter).
func requestErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		writeError(w, r, http.StatusRequestEntityTooLarge, api.ErrorResponseCodePayloadTooLarge, msgTooLarge, "", nil)
		return
	}
	writeError(w, r, http.StatusBadRequest, api.ErrorResponseCodeBadRequest, msgBadRequest, "Malformed request", nil)
}

// responseErrorHandler handles unexpected errors returned by handlers.
func responseErrorHandler(logger *slog.Logger) func(w http.ResponseWriter, r *http.Request, err error) {
	return func(w http.ResponseWriter, r *http.Request, err error) {
		logger.ErrorContext(r.Context(), "request failed", slog.Any("error", err))
		if errors.Is(err, threat.ErrUnavailable) {
			w.Header().Set("Retry-After", strconv.Itoa(retryAfterUnavailable))
			writeError(w, r, http.StatusServiceUnavailable, api.ErrorResponseCodeUnavailable, msgUnavailable, "", nil)
			return
		}
		writeError(w, r, http.StatusInternalServerError, api.ErrorResponseCodeInternal, msgInternal, "", nil)
	}
}
