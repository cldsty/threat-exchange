package httpapi

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseIfMatch(t *testing.T) {
	t.Parallel()
	s := func(v string) *string { return &v }

	for _, in := range []*string{nil, s(""), s("*"), s("  *  ")} {
		got, err := parseIfMatch(in)
		require.NoError(t, err)
		assert.Nil(t, got, "no precondition")
	}

	got, err := parseIfMatch(s(`"42"`))
	require.NoError(t, err)
	assert.EqualValues(t, 42, *got)

	for _, bad := range []string{`42`, `""`, `"abc"`, `"0"`, `"-1"`, `W/"1"`, `"1`, `"1", "2"`} {
		_, err := parseIfMatch(s(bad))
		assert.Error(t, err, bad)
	}
}

func TestETag(t *testing.T) {
	t.Parallel()
	assert.Equal(t, `"7"`, *etag(7))
}
