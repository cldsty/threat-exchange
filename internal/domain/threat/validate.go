package threat

import (
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Limits of the threat model. They mirror api/openapi.yaml and the database
// constraints (defence in depth).
const (
	MaxNameLength        = 255
	MaxDescriptionLength = 2000
	MaxTypes             = 12
	// MaxClockSkew is how far into the future a *_seen_at timestamp may be
	// to tolerate clock differences between exchange participants.
	MaxClockSkew = 5 * time.Minute
)

const (
	md5HexLen    = 32
	sha1HexLen   = 40
	sha256HexLen = 64
)

// NormalizeMD5 validates an MD5 hex digest and returns it in lower case.
func NormalizeMD5(s string) (string, error) {
	return normalizeHex(s, md5HexLen)
}

// Normalize returns a copy of a with canonical representation applied:
// lower-case hashes, default zone/severity and a non-nil Types slice.
// Normalize does not validate; call Validate on the result.
func (a Attributes) Normalize() Attributes {
	if a.SHA1 != nil {
		v := strings.ToLower(*a.SHA1)
		a.SHA1 = &v
	}
	if a.SHA256 != nil {
		v := strings.ToLower(*a.SHA256)
		a.SHA256 = &v
	}
	if a.Zone == "" {
		a.Zone = DefaultZone
	}
	if a.Severity == "" {
		a.Severity = DefaultSeverity
	}
	if a.Types == nil {
		a.Types = []Type{}
	} else {
		a.Types = append([]Type(nil), a.Types...)
	}
	if a.FirstSeenAt != nil {
		t := a.FirstSeenAt.UTC()
		a.FirstSeenAt = &t
	}
	if a.LastSeenAt != nil {
		t := a.LastSeenAt.UTC()
		a.LastSeenAt = &t
	}
	return a
}

// Validate checks a (normalized) set of attributes against the business
// rules. now is the current time used to reject timestamps in the future.
// All violations are collected and returned as a single *ValidationError.
func (a Attributes) Validate(now time.Time) error {
	var v ValidationError

	if a.SHA1 != nil {
		if _, err := normalizeHex(*a.SHA1, sha1HexLen); err != nil {
			v.Add("sha1", err.Error())
		}
	}
	if a.SHA256 != nil {
		if _, err := normalizeHex(*a.SHA256, sha256HexLen); err != nil {
			v.Add("sha256", err.Error())
		}
	}
	if msg := checkName(a.Name); msg != "" {
		v.Add("name", msg)
	}
	if a.Description != nil {
		if msg := checkDescription(*a.Description); msg != "" {
			v.Add("description", msg)
		}
	}
	checkTypes(a.Types, &v)
	if !a.Zone.Valid() {
		v.Add("zone", fmt.Sprintf("unknown zone %q", a.Zone))
	}
	if !a.Severity.Valid() {
		v.Add("severity", fmt.Sprintf("unknown severity %q", a.Severity))
	}
	if a.Zone.Valid() && a.Severity.Valid() &&
		(a.Zone == ZoneGreen || a.Zone == ZoneGrey) && a.Severity != SeverityUnknown {
		v.Add("severity", fmt.Sprintf("must be %q for zone %q", SeverityUnknown, a.Zone))
	}
	if a.FileSize != nil && *a.FileSize < 0 {
		v.Add("file_size", "must be non-negative")
	}
	limit := now.Add(MaxClockSkew)
	if a.FirstSeenAt != nil && a.FirstSeenAt.After(limit) {
		v.Add("first_seen_at", "must not be in the future")
	}
	if a.LastSeenAt != nil && a.LastSeenAt.After(limit) {
		v.Add("last_seen_at", "must not be in the future")
	}
	if a.FirstSeenAt != nil && a.LastSeenAt != nil && a.LastSeenAt.Before(*a.FirstSeenAt) {
		v.Add("last_seen_at", "must not be earlier than first_seen_at")
	}

	if len(v.Fields) > 0 {
		return &v
	}
	return nil
}

func normalizeHex(s string, n int) (string, error) {
	if len(s) != n {
		return "", fmt.Errorf("must be exactly %d hexadecimal characters", n)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F') {
			return "", fmt.Errorf("must be exactly %d hexadecimal characters", n)
		}
	}
	return strings.ToLower(s), nil
}

func checkName(s string) string {
	switch {
	case s == "":
		return "is required"
	case !utf8.ValidString(s):
		return "must be valid UTF-8"
	case utf8.RuneCountInString(s) > MaxNameLength:
		return fmt.Sprintf("must be at most %d characters", MaxNameLength)
	case strings.TrimSpace(s) != s:
		return "must not have leading or trailing whitespace"
	case strings.IndexFunc(s, unicode.IsControl) >= 0:
		return "must not contain control characters"
	}
	return ""
}

func checkDescription(s string) string {
	switch {
	case !utf8.ValidString(s):
		return "must be valid UTF-8"
	case utf8.RuneCountInString(s) > MaxDescriptionLength:
		return fmt.Sprintf("must be at most %d characters", MaxDescriptionLength)
	case strings.TrimSpace(s) == "":
		return "must not be empty or whitespace only"
	case strings.IndexFunc(s, func(r rune) bool {
		return unicode.IsControl(r) && r != '\t' && r != '\n' && r != '\r'
	}) >= 0:
		return "must not contain control characters other than tab and newline"
	}
	return ""
}

func checkTypes(types []Type, v *ValidationError) {
	if len(types) > MaxTypes {
		v.Add("types", fmt.Sprintf("must contain at most %d items", MaxTypes))
	}
	seen := make(map[Type]struct{}, len(types))
	for _, t := range types {
		if !t.Valid() {
			v.Add("types", fmt.Sprintf("unknown type %q", t))
			continue
		}
		if _, dup := seen[t]; dup {
			v.Add("types", fmt.Sprintf("duplicate type %q", t))
			continue
		}
		seen[t] = struct{}{}
	}
}
