package permit

import (
	"encoding/json"
	"fmt"
	"time"

	cry "permit-authority/internal/crypto"
)

// AccessPermit is the fully-configured, cryptographically signed access permit
type AccessPermit struct {
	PermitID    string    `json:"permit_id"`
	IssuedAt    time.Time `json:"issued_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	Issuer      string    `json:"issuer"`
	Description string    `json:"description"`
	TemplateID  string    `json:"template_id"`
	TemplateVer string    `json:"template_version"`

	Who       WhoSpec       `json:"who"`
	When      WhenSpec      `json:"when"`
	Where     WhereSpec     `json:"where"`
	What      WhatSpec      `json:"what"`
	How       HowSpec       `json:"how"`
	Why       WhySpec       `json:"why"`
	HowMany   HowManySpec   `json:"how_many"`
	Relations RelationsSpec `json:"relations"`
}

type WhoSpec struct {
	Type        string   `json:"type"`
	Groups      []string `json:"groups"`
	AuthMethod  string   `json:"auth_method"`
	TrustLevel  string   `json:"trust_level"`
	SPIFFEPatt  string   `json:"spiffe_pattern,omitempty"`
	JWTIssuers  []string `json:"jwt_issuers,omitempty"`
}

type WhenSpec struct {
	TTL         string `json:"ttl"`
	TimeWindow  string `json:"time_window"`
	AllowedDays string `json:"allowed_days"`
	Timezone    string `json:"timezone"`
}

type WhereSpec struct {
	Clusters     []string `json:"clusters"`
	Namespaces   []string `json:"namespaces"`
	Nodes        []string `json:"nodes"`
	IPRanges     []string `json:"ip_ranges"`
	GeoRegions   []string `json:"geo_regions"`
	Environments []string `json:"environments"`
}

type WhatSpec struct {
	ResourceTypes  []string `json:"resource_types"`
	APIs           []string `json:"apis"`
	Classification string   `json:"classification"`
	ResourceNS     []string `json:"resource_namespaces"`
}

type HowSpec struct {
	Verbs      []string `json:"verbs"`
	Protocol   string   `json:"protocol"`
	Encryption string   `json:"encryption"`
}

type WhySpec struct {
	Purpose              string `json:"purpose"`
	RequireJustification bool   `json:"require_justification"`
	TicketID             string `json:"ticket_id,omitempty"`
	Justification        string `json:"justification,omitempty"`
	BreakGlass           bool   `json:"break_glass"`
}

type HowManySpec struct {
	RateLimit  string `json:"rate_limit"`
	MaxResults string `json:"max_results"`
	BurstLimit string `json:"burst_limit"`
}

type RelationsSpec struct {
	AllowedRelations []string `json:"allowed_relations"`
}

// FromSigned extracts and parses an AccessPermit from a SignedDocument
func FromSigned(doc *cry.SignedDocument) (*AccessPermit, error) {
	var p AccessPermit
	if err := json.Unmarshal(doc.Payload, &p); err != nil {
		return nil, fmt.Errorf("unmarshal permit: %w", err)
	}
	return &p, nil
}
