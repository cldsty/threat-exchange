// Package service implements the application use cases on top of the domain
// model. It is transport-agnostic: HTTP handlers, CLI tools and tests all use
// the same Service and therefore the same business rules.
package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"threat-exchange/internal/domain/threat"
)

// Repository is the persistence port required by the service. It is
// implemented by internal/storage/postgres and by in-memory fakes in tests.
type Repository interface {
	// Get returns the threat with the given (normalized) MD5 or
	// threat.ErrNotFound.
	Get(ctx context.Context, md5 string) (threat.Threat, error)
	// Create stores a new threat or returns threat.ErrAlreadyExists, or
	// threat.ErrHashConflict when the SHA-256 belongs to another threat.
	Create(ctx context.Context, md5 string, attrs threat.Attributes, actor string) (threat.Threat, error)
	// Replace overwrites the attributes of an existing threat. A non-empty
	// expectedVersions must contain the stored version, otherwise
	// threat.ErrVersionMismatch is returned. Without expected versions only
	// the actor who modified the record last may replace it, otherwise
	// threat.ErrPreconditionRequired is returned. threat.ErrNotFound is
	// returned when there is no such threat, threat.ErrHashConflict when the
	// SHA-256 belongs to another threat.
	Replace(ctx context.Context, md5 string, attrs threat.Attributes, actor string, expectedVersions []int64) (threat.Threat, error)
}

// Clock abstracts time for deterministic tests.
type Clock interface {
	Now() time.Time
}

// ClockFunc adapts a function to the Clock interface.
type ClockFunc func() time.Time

// Now implements Clock.
func (f ClockFunc) Now() time.Time { return f() }

// Service provides operations on threats.
type Service struct {
	repo  Repository
	clock Clock
}

// New creates a Service. A nil clock means the system clock.
func New(repo Repository, clock Clock) *Service {
	if clock == nil {
		clock = ClockFunc(time.Now)
	}
	return &Service{repo: repo, clock: clock}
}

// Get returns a threat by MD5 (case-insensitive).
func (s *Service) Get(ctx context.Context, md5 string) (threat.Threat, error) {
	key, err := threat.NormalizeMD5(md5)
	if err != nil {
		return threat.Threat{}, threat.NewValidationError("md5", err.Error())
	}
	t, err := s.repo.Get(ctx, key)
	if err != nil {
		return threat.Threat{}, fmt.Errorf("get threat: %w", err)
	}
	return t, nil
}

// Create validates and stores a new threat on behalf of actor.
func (s *Service) Create(ctx context.Context, actor, md5 string, attrs threat.Attributes) (threat.Threat, error) {
	key, attrs, err := s.prepare(md5, attrs)
	if err != nil {
		return threat.Threat{}, err
	}
	t, err := s.repo.Create(ctx, key, attrs, actor)
	if err != nil {
		return threat.Threat{}, fmt.Errorf("create threat: %w", err)
	}
	return t, nil
}

// Replace validates attrs and fully replaces the stored threat on behalf of
// actor. Non-empty expectedVersions enable optimistic concurrency control; they
// are mandatory for a record last modified by another actor.
func (s *Service) Replace(ctx context.Context, actor, md5 string, attrs threat.Attributes, expectedVersions []int64) (threat.Threat, error) {
	key, attrs, err := s.prepare(md5, attrs)
	if err != nil {
		return threat.Threat{}, err
	}
	t, err := s.repo.Replace(ctx, key, attrs, actor, expectedVersions)
	if err != nil {
		return threat.Threat{}, fmt.Errorf("replace threat: %w", err)
	}
	return t, nil
}

func (s *Service) prepare(md5 string, attrs threat.Attributes) (string, threat.Attributes, error) {
	verr := &threat.ValidationError{}
	key, err := threat.NormalizeMD5(md5)
	if err != nil {
		verr.Add("md5", err.Error())
	}
	attrs = attrs.Normalize()
	if err := attrs.Validate(s.clock.Now()); err != nil {
		var ve *threat.ValidationError
		if !errors.As(err, &ve) {
			return "", threat.Attributes{}, err
		}
		verr.Fields = append(verr.Fields, ve.Fields...)
	}
	if len(verr.Fields) > 0 {
		return "", threat.Attributes{}, verr
	}
	return key, attrs, nil
}
