package threat_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"threat-exchange/internal/domain/threat"
)

var now = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

func ptr[T any](v T) *T { return &v }

func valid() threat.Attributes {
	return threat.Attributes{Name: "Trojan.Win32.Generic"}.Normalize()
}

func TestNormalizeMD5(t *testing.T) {
	t.Parallel()
	got, err := threat.NormalizeMD5("D41D8CD98F00B204E9800998ECF8427E")
	require.NoError(t, err)
	assert.Equal(t, "d41d8cd98f00b204e9800998ecf8427e", got)

	for _, bad := range []string{"", "d41d8cd98f00b204e9800998ecf8427", "d41d8cd98f00b204e9800998ecf8427eX", "g41d8cd98f00b204e9800998ecf8427e"} {
		_, err := threat.NormalizeMD5(bad)
		assert.Error(t, err, bad)
	}
}

func TestNormalize(t *testing.T) {
	t.Parallel()
	first := time.Date(2026, 1, 1, 3, 0, 0, 0, time.FixedZone("MSK", 3*3600))
	a := threat.Attributes{
		Name:        "X",
		SHA1:        ptr(strings.Repeat("A", 40)),
		SHA256:      ptr(strings.Repeat("B", 64)),
		FirstSeenAt: &first,
	}.Normalize()

	assert.Equal(t, threat.ZoneGrey, a.Zone, "default zone")
	assert.Equal(t, threat.SeverityUnknown, a.Severity, "default severity")
	assert.NotNil(t, a.Types, "types must be an empty slice, not nil")
	assert.Equal(t, strings.Repeat("a", 40), *a.SHA1)
	assert.Equal(t, strings.Repeat("b", 64), *a.SHA256)
	assert.Equal(t, time.UTC, a.FirstSeenAt.Location())
	assert.True(t, a.FirstSeenAt.Equal(first))
}

func TestNormalizeDoesNotAliasInput(t *testing.T) {
	t.Parallel()
	types := []threat.Type{threat.TypeTrojan}
	a := threat.Attributes{Name: "X", Types: types}.Normalize()
	a.Types[0] = threat.TypeWorm
	assert.Equal(t, threat.TypeTrojan, types[0])
}

func TestValidate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*threat.Attributes)
		fields []string // expected invalid fields; empty means valid
	}{
		{"minimal valid", func(*threat.Attributes) {}, nil},
		{"full valid", func(a *threat.Attributes) {
			a.SHA1 = ptr(strings.Repeat("a", 40))
			a.SHA256 = ptr(strings.Repeat("f", 64))
			a.Description = ptr("Line one\n\tline two")
			a.Types = []threat.Type{threat.TypeTrojan, threat.TypeDownloader}
			a.Zone = threat.ZoneRed
			a.Severity = threat.SeverityCritical
			a.FileSize = ptr[int64](0)
			a.FirstSeenAt = ptr(now.Add(-48 * time.Hour))
			a.LastSeenAt = ptr(now.Add(-time.Hour))
			a.Revoked = true
		}, nil},
		{"kaspersky name with prefix", func(a *threat.Attributes) { a.Name = "not-a-virus:HEUR:Downloader.Win32.LMN.a" }, nil},
		{"unicode name", func(a *threat.Attributes) { a.Name = "Троян.Тест" }, nil},
		{"name max length", func(a *threat.Attributes) { a.Name = strings.Repeat("я", 255) }, nil},
		{"empty types allowed", func(a *threat.Attributes) { a.Types = []threat.Type{} }, nil},
		{"12 types allowed", func(a *threat.Attributes) {
			a.Types = []threat.Type{"virus", "worm", "trojan", "backdoor", "rootkit", "exploit",
				"ransomware", "banker", "downloader", "dropper", "spyware", "stealer"}
		}, nil},
		{"equal seen dates", func(a *threat.Attributes) { a.FirstSeenAt = ptr(now); a.LastSeenAt = ptr(now) }, nil},
		{"within clock skew", func(a *threat.Attributes) { a.LastSeenAt = ptr(now.Add(threat.MaxClockSkew)) }, nil},
		{"green zone unknown severity", func(a *threat.Attributes) { a.Zone = threat.ZoneGreen }, nil},

		{"empty name", func(a *threat.Attributes) { a.Name = "" }, []string{"name"}},
		{"name too long", func(a *threat.Attributes) { a.Name = strings.Repeat("a", 256) }, []string{"name"}},
		{"name leading space", func(a *threat.Attributes) { a.Name = " X" }, []string{"name"}},
		{"name trailing nbsp", func(a *threat.Attributes) { a.Name = "X " }, []string{"name"}},
		{"name whitespace only", func(a *threat.Attributes) { a.Name = "   " }, []string{"name"}},
		{"name control char", func(a *threat.Attributes) { a.Name = "Tro\x00jan" }, []string{"name"}},
		{"name newline", func(a *threat.Attributes) { a.Name = "Tro\njan" }, []string{"name"}},
		{"name invalid utf8", func(a *threat.Attributes) { a.Name = "\xff" }, []string{"name"}},
		{"sha1 wrong length", func(a *threat.Attributes) { a.SHA1 = ptr("abc") }, []string{"sha1"}},
		{"sha256 not hex", func(a *threat.Attributes) { a.SHA256 = ptr(strings.Repeat("z", 64)) }, []string{"sha256"}},
		{"description empty", func(a *threat.Attributes) { a.Description = ptr("") }, []string{"description"}},
		{"description whitespace", func(a *threat.Attributes) { a.Description = ptr(" \n\t ") }, []string{"description"}},
		{"description too long", func(a *threat.Attributes) { a.Description = ptr(strings.Repeat("a", 2001)) }, []string{"description"}},
		{"description control char", func(a *threat.Attributes) { a.Description = ptr("bell\a") }, []string{"description"}},
		{"too many types", func(a *threat.Attributes) {
			a.Types = []threat.Type{"virus", "worm", "trojan", "backdoor", "rootkit", "exploit",
				"ransomware", "banker", "downloader", "dropper", "spyware", "stealer", "miner"}
		}, []string{"types"}},
		{"duplicate type", func(a *threat.Attributes) { a.Types = []threat.Type{"worm", "worm"} }, []string{"types"}},
		{"unknown type", func(a *threat.Attributes) { a.Types = []threat.Type{"Trojan"} }, []string{"types"}},
		{"unknown zone", func(a *threat.Attributes) { a.Zone = "blue" }, []string{"zone"}},
		{"unknown severity", func(a *threat.Attributes) { a.Severity = "extreme" }, []string{"severity"}},
		{"grey zone with severity", func(a *threat.Attributes) { a.Severity = threat.SeverityHigh }, []string{"severity"}},
		{"green zone with severity", func(a *threat.Attributes) {
			a.Zone = threat.ZoneGreen
			a.Severity = threat.SeverityLow
		}, []string{"severity"}},
		{"negative size", func(a *threat.Attributes) { a.FileSize = ptr[int64](-1) }, []string{"file_size"}},
		{"first seen in future", func(a *threat.Attributes) { a.FirstSeenAt = ptr(now.Add(time.Hour)) }, []string{"first_seen_at"}},
		{"last before first", func(a *threat.Attributes) {
			a.FirstSeenAt = ptr(now)
			a.LastSeenAt = ptr(now.Add(-time.Second))
		}, []string{"last_seen_at"}},
		{"several errors at once", func(a *threat.Attributes) {
			a.Name = ""
			a.Zone = "blue"
			a.FileSize = ptr[int64](-5)
		}, []string{"name", "zone", "file_size"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			a := valid()
			tt.mutate(&a)
			err := a.Validate(now)
			if len(tt.fields) == 0 {
				assert.NoError(t, err)
				return
			}
			var ve *threat.ValidationError
			require.True(t, errors.As(err, &ve), "want *ValidationError, got %v", err)
			var got []string
			for _, f := range ve.Fields {
				got = append(got, f.Field)
				assert.NotEmpty(t, f.Message)
			}
			assert.ElementsMatch(t, tt.fields, got)
			assert.Contains(t, err.Error(), "validation failed")
		})
	}
}

func TestEnums(t *testing.T) {
	t.Parallel()
	for _, z := range []threat.Zone{"red", "orange", "yellow", "green", "grey"} {
		assert.True(t, z.Valid(), z)
	}
	assert.False(t, threat.Zone("Red").Valid(), "enums are case-sensitive")
	for _, s := range []threat.Severity{"unknown", "low", "medium", "high", "critical"} {
		assert.True(t, s.Valid(), s)
	}
	assert.False(t, threat.Severity("").Valid())
	assert.True(t, threat.TypeHacktool.Valid())
	assert.False(t, threat.Type("").Valid())
}
