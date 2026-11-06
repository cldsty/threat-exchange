// Package httpapi is the HTTP transport of the service: handlers implementing
// the strict server interface generated from api/openapi.yaml, the mapping
// between API models and the domain, and the middleware chain (request IDs,
// logging, metrics, security headers, authentication, authorization, rate
// limiting, body size limits and OpenAPI request validation).
package httpapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"threat-exchange/internal/api"
	"threat-exchange/internal/auth"
	"threat-exchange/internal/domain/threat"
)

// ThreatService is the application port used by the handlers.
type ThreatService interface {
	Get(ctx context.Context, md5 string) (threat.Threat, error)
	Create(ctx context.Context, actor, md5 string, attrs threat.Attributes) (threat.Threat, error)
	Replace(ctx context.Context, actor, md5 string, attrs threat.Attributes, expectedVersions []int64) (threat.Threat, error)
}

// Handlers implements api.StrictServerInterface.
type Handlers struct {
	svc    ThreatService
	logger *slog.Logger
}

var _ api.StrictServerInterface = (*Handlers)(nil)

// NewHandlers creates the API handlers.
func NewHandlers(svc ThreatService, logger *slog.Logger) *Handlers {
	return &Handlers{svc: svc, logger: logger}
}

// GetInfoByMd5 implements api.StrictServerInterface.
func (h *Handlers) GetInfoByMd5(ctx context.Context, req api.GetInfoByMd5RequestObject) (api.GetInfoByMd5ResponseObject, error) {
	t, err := h.svc.Get(ctx, req.Md5)
	var ve *threat.ValidationError
	switch {
	case err == nil:
		return api.GetInfoByMd5200JSONResponse{
			Body:    toResponse(t),
			Headers: api.GetInfoByMd5200ResponseHeaders{ETag: etag(t.Version)},
		}, nil
	case errors.As(err, &ve):
		return api.GetInfoByMd5400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(
			errorBody(ctx, api.ErrorResponseCodeValidationFailed, msgValidation, "", fieldErrors(ve)))}, nil
	case errors.Is(err, threat.ErrNotFound):
		return api.GetInfoByMd5404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse(
			errorBody(ctx, api.ErrorResponseCodeNotFound, msgNotFound, notFoundDetails(req.Md5), nil))}, nil
	default:
		return nil, err
	}
}

// CreateThreat implements api.StrictServerInterface.
func (h *Handlers) CreateThreat(ctx context.Context, req api.CreateThreatRequestObject) (api.CreateThreatResponseObject, error) {
	if req.Body == nil {
		return api.CreateThreat400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(
			errorBody(ctx, api.ErrorResponseCodeBadRequest, msgBadRequest, "Request body is required", nil))}, nil
	}
	actor := actorFrom(ctx)
	t, err := h.svc.Create(ctx, actor, req.Body.Md5, fromCreateRequest(*req.Body))
	var ve *threat.ValidationError
	switch {
	case err == nil:
		h.logger.InfoContext(ctx, "threat created", slog.String("md5", t.MD5), slog.String("actor", actor))
		location := "/info/" + t.MD5
		return api.CreateThreat201JSONResponse{
			Body:    toResponse(t),
			Headers: api.CreateThreat201ResponseHeaders{ETag: etag(t.Version), Location: &location},
		}, nil
	case errors.As(err, &ve):
		return api.CreateThreat400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(
			errorBody(ctx, api.ErrorResponseCodeValidationFailed, msgValidation, "", fieldErrors(ve)))}, nil
	case errors.Is(err, threat.ErrAlreadyExists):
		return api.CreateThreat409JSONResponse(errorBody(ctx, api.ErrorResponseCodeConflict, msgConflict,
			fmt.Sprintf("Threat with MD5 %s already exists", strings.ToLower(req.Body.Md5)), nil)), nil
	case errors.Is(err, threat.ErrHashConflict):
		return api.CreateThreat409JSONResponse(errorBody(ctx, api.ErrorResponseCodeConflict, msgHashConflict, hashConflictDetails, nil)), nil
	default:
		return nil, err
	}
}

// UpdateThreat implements api.StrictServerInterface.
func (h *Handlers) UpdateThreat(ctx context.Context, req api.UpdateThreatRequestObject) (api.UpdateThreatResponseObject, error) {
	if req.Body == nil {
		return api.UpdateThreat400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(
			errorBody(ctx, api.ErrorResponseCodeBadRequest, msgBadRequest, "Request body is required", nil))}, nil
	}
	expected, err := parseIfMatch(req.Params.IfMatch)
	if err != nil {
		return api.UpdateThreat400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(
			errorBody(ctx, api.ErrorResponseCodeValidationFailed, msgValidation, "",
				[]api.FieldError{{Field: "If-Match", Message: err.Error()}}))}, nil
	}
	actor := actorFrom(ctx)
	t, err := h.svc.Replace(ctx, actor, req.Md5, fromUpdateRequest(*req.Body), expected)
	var ve *threat.ValidationError
	switch {
	case err == nil:
		h.logger.InfoContext(ctx, "threat replaced", slog.String("md5", t.MD5),
			slog.String("actor", actor), slog.Int64("version", t.Version))
		return api.UpdateThreat200JSONResponse{
			Body:    toResponse(t),
			Headers: api.UpdateThreat200ResponseHeaders{ETag: etag(t.Version)},
		}, nil
	case errors.As(err, &ve):
		return api.UpdateThreat400JSONResponse{BadRequestJSONResponse: api.BadRequestJSONResponse(
			errorBody(ctx, api.ErrorResponseCodeValidationFailed, msgValidation, "", fieldErrors(ve)))}, nil
	case errors.Is(err, threat.ErrNotFound):
		return api.UpdateThreat404JSONResponse{NotFoundJSONResponse: api.NotFoundJSONResponse(
			errorBody(ctx, api.ErrorResponseCodeNotFound, msgNotFound, notFoundDetails(req.Md5), nil))}, nil
	case errors.Is(err, threat.ErrVersionMismatch):
		return api.UpdateThreat412JSONResponse{PreconditionFailedJSONResponse: api.PreconditionFailedJSONResponse(
			errorBody(ctx, api.ErrorResponseCodePreconditionFailed, msgPrecond,
				"The record version does not match If-Match; fetch the record and retry", nil))}, nil
	case errors.Is(err, threat.ErrPreconditionRequired):
		return api.UpdateThreat428JSONResponse{PreconditionRequiredJSONResponse: api.PreconditionRequiredJSONResponse(
			errorBody(ctx, api.ErrorResponseCodePreconditionRequired, msgPrecondRequired,
				"The record was last modified by another client; fetch it, merge the data and send If-Match with its ETag", nil))}, nil
	case errors.Is(err, threat.ErrHashConflict):
		return api.UpdateThreat409JSONResponse(errorBody(ctx, api.ErrorResponseCodeConflict, msgHashConflict, hashConflictDetails, nil)), nil
	default:
		return nil, err
	}
}

func actorFrom(ctx context.Context) string {
	if p, ok := auth.PrincipalFrom(ctx); ok {
		return p.ID
	}
	// The authentication middleware guarantees a principal; this is a
	// safety net that keeps audit columns non-empty.
	return "unknown"
}

func notFoundDetails(md5 string) string {
	return fmt.Sprintf("No threat with MD5 %s found", strings.ToLower(md5))
}

// etag formats a record version as a strong entity tag, e.g. "3".
func etag(version int64) *string {
	s := `"` + strconv.FormatInt(version, 10) + `"`
	return &s
}

// parseIfMatch parses the If-Match header into the accepted versions. A missing
// header or "*" means that no specific version is requested (nil). Weak entity
// tags are rejected: If-Match requires strong comparison.
func parseIfMatch(h *string) ([]int64, error) {
	if h == nil {
		return nil, nil
	}
	v := strings.TrimSpace(*h)
	if v == "" || v == "*" {
		return nil, nil
	}
	tags := strings.Split(v, ",")
	versions := make([]int64, 0, len(tags))
	for _, tag := range tags {
		n, err := parseEntityTag(strings.TrimSpace(tag))
		if err != nil {
			return nil, err
		}
		versions = append(versions, n)
	}
	return versions, nil
}

func parseEntityTag(v string) (int64, error) {
	if strings.HasPrefix(v, "W/") {
		return 0, errors.New("weak entity tags are not supported")
	}
	if len(v) < 3 || v[0] != '"' || v[len(v)-1] != '"' {
		return 0, errors.New(`must be a quoted version, e.g. "3"`)
	}
	n, err := strconv.ParseInt(v[1:len(v)-1], 10, 64)
	if err != nil || n < 1 {
		return 0, errors.New(`must be a quoted positive version, e.g. "3"`)
	}
	return n, nil
}
