package threat

import (
	"errors"
	"strings"
)

// Sentinel errors returned by the service and repository layers. Callers
// should compare them with errors.Is.
var (
	// ErrNotFound means there is no threat with the requested MD5.
	ErrNotFound = errors.New("threat not found")
	// ErrAlreadyExists means a threat with the same MD5 is already stored.
	ErrAlreadyExists = errors.New("threat already exists")
	// ErrVersionMismatch means the expected version (If-Match) does not match
	// the stored version, i.e. somebody else modified the record.
	ErrVersionMismatch = errors.New("threat version mismatch")
	// ErrPreconditionRequired means the record was last modified by another
	// actor, so replacing it requires a specific expected version.
	ErrPreconditionRequired = errors.New("threat version is required to replace a record of another actor")
	// ErrHashConflict means the SHA-256 belongs to a threat with another MD5.
	// One file cannot have two MD5 digests, so one of the records is wrong.
	ErrHashConflict = errors.New("sha256 belongs to another threat")
)

// FieldError describes a validation problem of a single field.
type FieldError struct {
	Field   string
	Message string
}

// ValidationError aggregates all field-level violations of a request so that
// the client can fix them in one go.
type ValidationError struct {
	Fields []FieldError
}

// Add records a violation for field.
func (e *ValidationError) Add(field, message string) {
	e.Fields = append(e.Fields, FieldError{Field: field, Message: message})
}

// Error implements the error interface.
func (e *ValidationError) Error() string {
	parts := make([]string, 0, len(e.Fields))
	for _, f := range e.Fields {
		parts = append(parts, f.Field+": "+f.Message)
	}
	return "validation failed: " + strings.Join(parts, "; ")
}

// NewValidationError is a convenience constructor for a single violation.
func NewValidationError(field, message string) *ValidationError {
	return &ValidationError{Fields: []FieldError{{Field: field, Message: message}}}
}
