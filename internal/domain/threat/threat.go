// Package threat contains the domain model of the service: the Threat entity,
// its enumerations and the business validation rules that apply regardless of
// the transport (HTTP, CLI, tests).
//
// The OpenAPI specification validates the shape of incoming requests. This
// package is the second line of defence: it enforces the same per-field rules
// for any caller and additionally checks rules that span several fields and
// therefore cannot be expressed in the specification
// (e.g. last_seen_at >= first_seen_at).
package threat

import "time"

// Zone is a colour zone of an object, modelled after Kaspersky Threat
// Intelligence Portal.
type Zone string

// Zone values.
const (
	ZoneRed    Zone = "red"    // malicious
	ZoneOrange Zone = "orange" // suspicious / not trusted
	ZoneYellow Zone = "yellow" // adware and other potentially unwanted software
	ZoneGreen  Zone = "green"  // no threats detected
	ZoneGrey   Zone = "grey"   // not enough information
)

// DefaultZone is assigned when the client does not provide a zone.
const DefaultZone = ZoneGrey

// Valid reports whether z is one of the known zones.
func (z Zone) Valid() bool {
	switch z {
	case ZoneRed, ZoneOrange, ZoneYellow, ZoneGreen, ZoneGrey:
		return true
	}
	return false
}

// Severity is the assessed danger level of a threat.
type Severity string

// Severity values.
const (
	SeverityUnknown  Severity = "unknown"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// DefaultSeverity is assigned when the client does not provide a severity.
// "unknown" honestly means "not assessed" rather than a guessed level.
const DefaultSeverity = SeverityUnknown

// Valid reports whether s is one of the known severities.
func (s Severity) Valid() bool {
	switch s {
	case SeverityUnknown, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	}
	return false
}

// TLP is a Traffic Light Protocol 2.0 label: how far the information may be
// shared. The service stores the label but does not enforce it on reads.
type TLP string

// TLP values.
const (
	TLPClear       TLP = "clear"
	TLPGreen       TLP = "green"
	TLPAmber       TLP = "amber"
	TLPAmberStrict TLP = "amber+strict"
	TLPRed         TLP = "red"
)

// DefaultTLP is assigned when the client does not provide a label. It errs on
// the side of restricting distribution.
const DefaultTLP = TLPAmber

// Valid reports whether t is one of the known labels.
func (t TLP) Valid() bool {
	switch t {
	case TLPClear, TLPGreen, TLPAmber, TLPAmberStrict, TLPRed:
		return true
	}
	return false
}

// Type is a behaviour category of a threat, based on the Behaviour part of
// Kaspersky detection names.
type Type string

// Type values.
const (
	TypeVirus      Type = "virus"
	TypeWorm       Type = "worm"
	TypeTrojan     Type = "trojan"
	TypeBackdoor   Type = "backdoor"
	TypeRootkit    Type = "rootkit"
	TypeExploit    Type = "exploit"
	TypeRansomware Type = "ransomware"
	TypeBanker     Type = "banker"
	TypeDownloader Type = "downloader"
	TypeDropper    Type = "dropper"
	TypeSpyware    Type = "spyware"
	TypeStealer    Type = "stealer"
	TypeMiner      Type = "miner"
	TypeAdware     Type = "adware"
	TypeRiskware   Type = "riskware"
	TypeHacktool   Type = "hacktool"
	TypeOther      Type = "other"
)

var knownTypes = map[Type]struct{}{
	TypeVirus: {}, TypeWorm: {}, TypeTrojan: {}, TypeBackdoor: {}, TypeRootkit: {},
	TypeExploit: {}, TypeRansomware: {}, TypeBanker: {}, TypeDownloader: {},
	TypeDropper: {}, TypeSpyware: {}, TypeStealer: {}, TypeMiner: {},
	TypeAdware: {}, TypeRiskware: {}, TypeHacktool: {}, TypeOther: {},
}

// Valid reports whether t belongs to the agreed vocabulary.
func (t Type) Valid() bool {
	_, ok := knownTypes[t]
	return ok
}

// Attributes are the threat fields that a client controls. They are used both
// for creation and for full replacement (PUT). Optional fields are pointers so
// that "not set" is distinguishable from a zero value.
type Attributes struct {
	SHA1        *string
	SHA256      *string
	Name        string
	Description *string
	Types       []Type
	Zone        Zone
	Severity    Severity
	FileSize    *int64
	FirstSeenAt *time.Time
	LastSeenAt  *time.Time
	TLP         TLP
	// Confidence is the author's confidence in the assessment, from 0 to 100.
	Confidence *int32
	Revoked    bool
}

// Meta is server-managed bookkeeping data of a stored threat.
type Meta struct {
	CreatedAt time.Time
	UpdatedAt time.Time
	CreatedBy string
	UpdatedBy string
	// Version starts at 1 and is incremented on every successful replacement.
	// It is exposed as a strong ETag for optimistic concurrency control.
	Version int64
}

// Threat is a stored record about a threat identified by the MD5 of a file.
type Threat struct {
	MD5 string
	Attributes
	Meta
}
