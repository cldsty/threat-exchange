package service_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"threat-exchange/internal/domain/threat"
	"threat-exchange/internal/service"
	"threat-exchange/internal/storage/memory"
)

const (
	md5Upper = "D41D8CD98F00B204E9800998ECF8427E"
	md5Lower = "d41d8cd98f00b204e9800998ecf8427e"
)

var now = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

func newService(t *testing.T) *service.Service {
	t.Helper()
	clock := func() time.Time { return now }
	return service.New(memory.New(clock), service.ClockFunc(clock))
}

func TestCreateNormalizesAndApplyDefaults(t *testing.T) {
	t.Parallel()
	svc := newService(t)
	ctx := context.Background()

	got, err := svc.Create(ctx, "partner-a", md5Upper, threat.Attributes{Name: "Trojan.Win32.Generic"})
	require.NoError(t, err)

	assert.Equal(t, md5Lower, got.MD5, "MD5 is stored in lower case")
	assert.Equal(t, threat.ZoneGrey, got.Zone)
	assert.Equal(t, threat.SeverityUnknown, got.Severity)
	assert.Equal(t, []threat.Type{}, got.Types)
	assert.Equal(t, "partner-a", got.CreatedBy)
	assert.Equal(t, "partner-a", got.UpdatedBy)
	assert.EqualValues(t, 1, got.Version)

	fetched, err := svc.Get(ctx, md5Upper)
	require.NoError(t, err, "lookup is case-insensitive")
	assert.Equal(t, got, fetched)
}

func TestCreateDuplicateIsCaseInsensitive(t *testing.T) {
	t.Parallel()
	svc := newService(t)
	ctx := context.Background()
	_, err := svc.Create(ctx, "a", md5Lower, threat.Attributes{Name: "X"})
	require.NoError(t, err)
	_, err = svc.Create(ctx, "a", md5Upper, threat.Attributes{Name: "Y"})
	assert.ErrorIs(t, err, threat.ErrAlreadyExists)
}

func TestCreateCollectsAllValidationErrors(t *testing.T) {
	t.Parallel()
	svc := newService(t)
	_, err := svc.Create(context.Background(), "a", "bad", threat.Attributes{Name: " X", Zone: "blue"})

	var ve *threat.ValidationError
	require.True(t, errors.As(err, &ve))
	var fields []string
	for _, f := range ve.Fields {
		fields = append(fields, f.Field)
	}
	assert.ElementsMatch(t, []string{"md5", "name", "zone"}, fields)
}

func TestCreateRejectsFutureDates(t *testing.T) {
	t.Parallel()
	svc := newService(t)
	future := now.Add(time.Hour)
	_, err := svc.Create(context.Background(), "a", md5Lower, threat.Attributes{Name: "X", LastSeenAt: &future})
	var ve *threat.ValidationError
	require.True(t, errors.As(err, &ve))
	assert.Equal(t, "last_seen_at", ve.Fields[0].Field)
}

func TestGet(t *testing.T) {
	t.Parallel()
	svc := newService(t)
	_, err := svc.Get(context.Background(), md5Lower)
	assert.ErrorIs(t, err, threat.ErrNotFound)

	_, err = svc.Get(context.Background(), "not-an-md5")
	var ve *threat.ValidationError
	assert.True(t, errors.As(err, &ve))
}

func TestReplace(t *testing.T) {
	t.Parallel()
	svc := newService(t)
	ctx := context.Background()
	desc := "old"
	_, err := svc.Create(ctx, "creator", md5Lower, threat.Attributes{
		Name: "Old", Description: &desc, Zone: threat.ZoneRed, Severity: threat.SeverityHigh,
		Types: []threat.Type{threat.TypeWorm},
	})
	require.NoError(t, err)

	t.Run("full replacement resets omitted fields", func(t *testing.T) {
		got, err := svc.Replace(ctx, "editor", md5Upper, threat.Attributes{Name: "New"}, nil)
		require.NoError(t, err)
		assert.Equal(t, "New", got.Name)
		assert.Nil(t, got.Description)
		assert.Equal(t, threat.ZoneGrey, got.Zone)
		assert.Equal(t, threat.SeverityUnknown, got.Severity)
		assert.Empty(t, got.Types)
		assert.Equal(t, "creator", got.CreatedBy)
		assert.Equal(t, "editor", got.UpdatedBy)
		assert.EqualValues(t, 2, got.Version)
	})

	t.Run("matching version", func(t *testing.T) {
		v := int64(2)
		got, err := svc.Replace(ctx, "editor", md5Lower, threat.Attributes{Name: "Newer"}, &v)
		require.NoError(t, err)
		assert.EqualValues(t, 3, got.Version)
	})

	t.Run("stale version", func(t *testing.T) {
		v := int64(1)
		_, err := svc.Replace(ctx, "editor", md5Lower, threat.Attributes{Name: "Lost update"}, &v)
		assert.ErrorIs(t, err, threat.ErrVersionMismatch)
	})

	t.Run("not found", func(t *testing.T) {
		_, err := svc.Replace(ctx, "editor", "ffffffffffffffffffffffffffffffff", threat.Attributes{Name: "X"}, nil)
		assert.ErrorIs(t, err, threat.ErrNotFound)
	})

	t.Run("invalid attributes", func(t *testing.T) {
		_, err := svc.Replace(ctx, "editor", md5Lower, threat.Attributes{Name: ""}, nil)
		var ve *threat.ValidationError
		assert.True(t, errors.As(err, &ve))
	})
}

type failingRepo struct{ service.Repository }

var errBoom = errors.New("boom")

func (failingRepo) Get(context.Context, string) (threat.Threat, error) {
	return threat.Threat{}, errBoom
}

func TestRepositoryErrorsAreWrapped(t *testing.T) {
	t.Parallel()
	svc := service.New(failingRepo{}, nil)
	_, err := svc.Get(context.Background(), md5Lower)
	assert.ErrorIs(t, err, errBoom)
	assert.Contains(t, err.Error(), "get threat")
}
