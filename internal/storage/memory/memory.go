// Package memory provides an in-memory implementation of the threat
// repository. It mirrors the semantics of the PostgreSQL repository and is
// used in unit tests of the service and HTTP layers.
package memory

import (
	"context"
	"slices"
	"sync"
	"time"

	"threat-exchange/internal/domain/threat"
	"threat-exchange/internal/service"
)

// Repository is a concurrency-safe in-memory store.
type Repository struct {
	mu    sync.Mutex
	items map[string]threat.Threat
	now   func() time.Time
}

var _ service.Repository = (*Repository)(nil)

// New creates an empty repository. A nil now uses time.Now.
func New(now func() time.Time) *Repository {
	if now == nil {
		now = time.Now
	}
	return &Repository{items: map[string]threat.Threat{}, now: now}
}

// Get implements service.Repository.
func (r *Repository) Get(_ context.Context, md5 string) (threat.Threat, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.items[md5]
	if !ok {
		return threat.Threat{}, threat.ErrNotFound
	}
	return clone(t), nil
}

// Create implements service.Repository.
func (r *Repository) Create(_ context.Context, md5 string, a threat.Attributes, actor string) (threat.Threat, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.items[md5]; ok {
		return threat.Threat{}, threat.ErrAlreadyExists
	}
	if r.sha256TakenLocked(md5, a.SHA256) {
		return threat.Threat{}, threat.ErrHashConflict
	}
	now := r.now().UTC()
	t := threat.Threat{
		MD5:        md5,
		Attributes: a,
		Meta:       threat.Meta{CreatedAt: now, UpdatedAt: now, CreatedBy: actor, UpdatedBy: actor, Version: 1},
	}
	r.items[md5] = clone(t)
	return t, nil
}

// Replace implements service.Repository.
func (r *Repository) Replace(_ context.Context, md5 string, a threat.Attributes, actor string, expectedVersions []int64) (threat.Threat, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.items[md5]
	if !ok {
		return threat.Threat{}, threat.ErrNotFound
	}
	if len(expectedVersions) == 0 && t.UpdatedBy != actor {
		return threat.Threat{}, threat.ErrPreconditionRequired
	}
	if len(expectedVersions) > 0 && !slices.Contains(expectedVersions, t.Version) {
		return threat.Threat{}, threat.ErrVersionMismatch
	}
	if r.sha256TakenLocked(md5, a.SHA256) {
		return threat.Threat{}, threat.ErrHashConflict
	}
	t.Attributes = a
	t.UpdatedAt = r.now().UTC()
	t.UpdatedBy = actor
	t.Version++
	r.items[md5] = clone(t)
	return t, nil
}

func (r *Repository) sha256TakenLocked(md5 string, sha256 *string) bool {
	if sha256 == nil {
		return false
	}
	for k, t := range r.items {
		if k != md5 && t.SHA256 != nil && *t.SHA256 == *sha256 {
			return true
		}
	}
	return false
}

func clone(t threat.Threat) threat.Threat {
	types := make([]threat.Type, len(t.Types))
	copy(types, t.Types)
	t.Types = types
	return t
}
