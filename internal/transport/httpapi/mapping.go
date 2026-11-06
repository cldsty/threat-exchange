package httpapi

import (
	"threat-exchange/internal/api"
	"threat-exchange/internal/domain/threat"
)

// Mapping between generated API models and domain types. Keeping them
// separate means the database and business logic do not depend on the wire
// format, and the wire format can evolve independently.

func fromCreateRequest(r api.ThreatCreateRequest) threat.Attributes {
	return attributes(r.Sha1, r.Sha256, r.Name, r.Description, r.Types, r.Zone, r.Severity,
		r.FileSize, r.FirstSeenAt, r.LastSeenAt, r.Revoked)
}

func fromUpdateRequest(r api.ThreatUpdateRequest) threat.Attributes {
	return attributes(r.Sha1, r.Sha256, r.Name, r.Description, r.Types, r.Zone, r.Severity,
		r.FileSize, r.FirstSeenAt, r.LastSeenAt, r.Revoked)
}

func attributes(sha1, sha256 *string, name string, description *string, types *api.ThreatTypes,
	zone *api.Zone, severity *api.Severity, fileSize *int64, firstSeen, lastSeen *api.SeenAt, revoked *bool,
) threat.Attributes {
	a := threat.Attributes{
		SHA1:        sha1,
		SHA256:      sha256,
		Name:        name,
		Description: description,
		FileSize:    fileSize,
		FirstSeenAt: firstSeen,
		LastSeenAt:  lastSeen,
	}
	if types != nil {
		a.Types = make([]threat.Type, len(*types))
		for i, t := range *types {
			a.Types[i] = threat.Type(t)
		}
	}
	if zone != nil {
		a.Zone = threat.Zone(*zone)
	}
	if severity != nil {
		a.Severity = threat.Severity(*severity)
	}
	if revoked != nil {
		a.Revoked = *revoked
	}
	return a
}

func toResponse(t threat.Threat) api.ThreatResponse {
	types := make(api.ThreatTypes, len(t.Types))
	for i, tt := range t.Types {
		types[i] = api.ThreatType(tt)
	}
	return api.ThreatResponse{
		Md5:         t.MD5,
		Sha1:        t.SHA1,
		Sha256:      t.SHA256,
		Name:        t.Name,
		Description: t.Description,
		Types:       types,
		Zone:        api.Zone(t.Zone),
		Severity:    api.Severity(t.Severity),
		FileSize:    t.FileSize,
		FirstSeenAt: t.FirstSeenAt,
		LastSeenAt:  t.LastSeenAt,
		Revoked:     t.Revoked,
		CreatedAt:   t.CreatedAt,
		UpdatedAt:   t.UpdatedAt,
		CreatedBy:   t.CreatedBy,
		UpdatedBy:   t.UpdatedBy,
	}
}
