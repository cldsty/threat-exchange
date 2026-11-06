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
	assert.Equal(t, []int64{42}, got)

	got, err = parseIfMatch(s(`"1", "2" ,"3"`))
	require.NoError(t, err)
	assert.Equal(t, []int64{1, 2, 3}, got, "RFC 9110 allows a list of entity tags")

	for _, bad := range []string{`42`, `""`, `"abc"`, `"0"`, `"-1"`, `W/"1"`, `"1`, `"1", "2`, `"1", *`, `"1",`} {
		_, err := parseIfMatch(s(bad))
		assert.Error(t, err, bad)
	}
}

func TestETag(t *testing.T) {
	t.Parallel()
	assert.Equal(t, `"7"`, *etag(7))
}
