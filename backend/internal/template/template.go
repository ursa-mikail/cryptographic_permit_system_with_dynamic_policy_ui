package template

import (
	"encoding/json"
	"fmt"
	"time"

	cry "permit-authority/internal/crypto"
)

// Option is a single selectable item in any policy dimension
type Option struct {
	Value       string `json:"value"`
	Label       string `json:"label"`
	Description string `json:"description,omitempty"`
	Risk        string `json:"risk"` // low | medium | high | critical
}

// PermitTemplate is the authoritative signed template that drives the UI
type PermitTemplate struct {
	TemplateID  string     `json:"template_id"`
	Name        string     `json:"name"`
	Version     string     `json:"version"`
	CreatedAt   time.Time  `json:"created_at"`
	Description string     `json:"description"`
	Dimensions  Dimensions `json:"dimensions"`
}

type Dimensions struct {
	Who       WhoOpts      `json:"who"`
	When      WhenOpts     `json:"when"`
	Where     WhereOpts    `json:"where"`
	What      WhatOpts     `json:"what"`
	How       HowOpts      `json:"how"`
	Why       WhyOpts      `json:"why"`
	HowMany   HowManyOpts  `json:"how_many"`
	Relations RelationOpts `json:"relations"`
}

type WhoOpts struct {
	ServiceTypes []Option `json:"service_types"`
	Groups       []Option `json:"groups"`
	AuthMethods  []Option `json:"auth_methods"`
	TrustLevels  []Option `json:"trust_levels"`
}
type WhenOpts struct {
	MaxTTLs     []Option `json:"max_ttls"`
	TimeWindows []Option `json:"time_windows"`
	AllowedDays []Option `json:"allowed_days"`
	Timezones   []Option `json:"timezones"`
}
type WhereOpts struct {
	Clusters     []Option `json:"clusters"`
	Namespaces   []Option `json:"namespaces"`
	Nodes        []Option `json:"nodes"`
	IPRanges     []Option `json:"ip_ranges"`
	GeoRegions   []Option `json:"geo_regions"`
	Environments []Option `json:"environments"`
}
type WhatOpts struct {
	ResourceTypes   []Option `json:"resource_types"`
	APIs            []Option `json:"apis"`
	Classifications []Option `json:"classifications"`
	Namespaces      []Option `json:"namespaces"`
}
type HowOpts struct {
	Verbs      []Option `json:"verbs"`
	Protocols  []Option `json:"protocols"`
	Encryption []Option `json:"encryption"`
}
type WhyOpts struct {
	Purposes          []Option `json:"purposes"`
	RequireTicket     bool     `json:"require_ticket"`
	BreakGlassAllowed bool     `json:"break_glass_allowed"`
}
type HowManyOpts struct {
	RateLimits  []Option `json:"rate_limits"`
	MaxResults  []Option `json:"max_results"`
	BurstLimits []Option `json:"burst_limits"`
}
type RelationOpts struct {
	Relations []Option `json:"relations"`
}

// GoldStandard returns the canonical permit template
func GoldStandard() *PermitTemplate {
	return &PermitTemplate{
		TemplateID:  "gold-standard-v1",
		Name:        "Unified Access Permit Template",
		Version:     "1.0.0",
		CreatedAt:   time.Now().UTC(),
		Description: "Authoritative gold-standard template combining OPA, OpenFGA, Zanzibar, X.509, K8s, Terraform dimensions",
		Dimensions: Dimensions{
			Who: WhoOpts{
				ServiceTypes: []Option{
					{Value: "service", Label: "Service Account", Description: "K8s service account or SPIFFE workload identity", Risk: "medium"},
					{Value: "user", Label: "Human User", Description: "Authenticated human principal via OIDC/SSO", Risk: "medium"},
					{Value: "node", Label: "Node / Host", Description: "Infrastructure node with hardware attestation", Risk: "high"},
					{Value: "pipeline", Label: "CI/CD Pipeline", Description: "Automated pipeline runner (GitHub Actions, Argo)", Risk: "medium"},
					{Value: "external", Label: "External Service", Description: "Third-party or federated external service", Risk: "high"},
					{Value: "operator", Label: "Human Operator", Description: "On-call or ops team member with elevated access", Risk: "medium"},
				},
				Groups: []Option{
					{Value: "auditors", Label: "Auditors", Description: "Read-only compliance and audit team", Risk: "low"},
					{Value: "devops", Label: "DevOps / Platform", Description: "Platform engineering team", Risk: "medium"},
					{Value: "sre", Label: "SRE", Description: "Site reliability engineers", Risk: "medium"},
					{Value: "finance-team", Label: "Finance Team", Description: "Finance department principals", Risk: "medium"},
					{Value: "security", Label: "Security / SIRT", Description: "InfoSec incident response team", Risk: "medium"},
					{Value: "data-science", Label: "Data Science", Description: "Data analysis and ML engineering team", Risk: "medium"},
					{Value: "readonly", Label: "Read-Only Users", Description: "Limited read-only access group", Risk: "low"},
					{Value: "emergency-admin", Label: "Emergency Admin", Description: "Break-glass emergency escalation group", Risk: "critical"},
				},
				AuthMethods: []Option{
					{Value: "x509_mtls", Label: "X.509 / mTLS", Description: "Certificate-based mutual TLS — strongest guarantee", Risk: "low"},
					{Value: "spiffe", Label: "SPIFFE / SPIRE", Description: "Cryptographic workload identity via SPIRE agent", Risk: "low"},
					{Value: "jwt_oidc", Label: "JWT / OIDC", Description: "OpenID Connect bearer token with issuer verification", Risk: "medium"},
					{Value: "aws_iam", Label: "AWS IAM Role", Description: "STS-issued instance profile or assumed role", Risk: "medium"},
					{Value: "k8s_sa_token", Label: "K8s Bound SA Token", Description: "Kubernetes projected service account token", Risk: "medium"},
					{Value: "github_oidc", Label: "GitHub OIDC", Description: "GitHub Actions OIDC federation token", Risk: "medium"},
				},
				TrustLevels: []Option{
					{Value: "hardware_attested", Label: "Hardware Attested", Description: "TPM/TEE attested, mTLS + SPIFFE identity", Risk: "low"},
					{Value: "high", Label: "High Trust", Description: "mTLS with org-issued cert plus MFA second factor", Risk: "low"},
					{Value: "medium", Label: "Medium Trust", Description: "OIDC token with verified MFA factor", Risk: "medium"},
					{Value: "low", Label: "Low Trust", Description: "Unverified or self-asserted identity claims", Risk: "high"},
				},
			},
			When: WhenOpts{
				MaxTTLs: []Option{
					{Value: "1h", Label: "1 Hour", Risk: "low"},
					{Value: "4h", Label: "4 Hours", Risk: "low"},
					{Value: "8h", Label: "8 Hours (workday)", Risk: "low"},
					{Value: "24h", Label: "24 Hours", Risk: "medium"},
					{Value: "7d", Label: "7 Days", Risk: "medium"},
					{Value: "30d", Label: "30 Days", Risk: "high"},
					{Value: "90d", Label: "90 Days", Risk: "high"},
					{Value: "365d", Label: "1 Year", Risk: "critical"},
				},
				TimeWindows: []Option{
					{Value: "business_hours", Label: "Business Hours 09:00–17:00", Description: "Restricted to weekday business hours only", Risk: "low"},
					{Value: "extended_hours", Label: "Extended 07:00–22:00", Description: "Extended coverage including early/late hours", Risk: "medium"},
					{Value: "always", Label: "24/7 Any Time", Description: "No time-of-day restriction applied", Risk: "high"},
					{Value: "maintenance", Label: "Maintenance Window Only", Description: "Pre-approved maintenance time slots only", Risk: "medium"},
				},
				AllowedDays: []Option{
					{Value: "weekdays", Label: "Mon–Fri Only", Risk: "low"},
					{Value: "mon_to_sat", Label: "Mon–Sat", Risk: "medium"},
					{Value: "all_days", Label: "All 7 Days", Risk: "high"},
				},
				Timezones: []Option{
					{Value: "UTC", Label: "UTC"},
					{Value: "America/New_York", Label: "US Eastern (ET)"},
					{Value: "America/Los_Angeles", Label: "US Pacific (PT)"},
					{Value: "Europe/London", Label: "London (GMT/BST)"},
					{Value: "Europe/Berlin", Label: "Berlin (CET/CEST)"},
					{Value: "Asia/Singapore", Label: "Singapore (SGT)"},
					{Value: "Asia/Tokyo", Label: "Tokyo (JST)"},
				},
			},
			Where: WhereOpts{
				Clusters: []Option{
					{Value: "prod-us-east1", Label: "prod-us-east1", Description: "Primary US production cluster", Risk: "high"},
					{Value: "prod-eu-west1", Label: "prod-eu-west1", Description: "EU production cluster (GDPR zone)", Risk: "high"},
					{Value: "prod-ap-southeast1", Label: "prod-ap-southeast1", Description: "APAC production cluster", Risk: "high"},
					{Value: "staging", Label: "staging", Description: "Pre-production staging cluster", Risk: "medium"},
					{Value: "dev", Label: "dev", Description: "Development cluster", Risk: "low"},
					{Value: "dr-standby", Label: "dr-standby", Description: "Disaster recovery standby cluster", Risk: "high"},
					{Value: "all", Label: "All Clusters (*)", Description: "Unrestricted cluster scope — maximum blast radius", Risk: "critical"},
				},
				Namespaces: []Option{
					{Value: "finance", Label: "finance", Risk: "high"},
					{Value: "auth-system", Label: "auth-system", Risk: "critical"},
					{Value: "data-platform", Label: "data-platform", Risk: "medium"},
					{Value: "monitoring", Label: "monitoring", Risk: "low"},
					{Value: "ingress", Label: "ingress", Risk: "medium"},
					{Value: "default", Label: "default", Risk: "medium"},
					{Value: "kube-system", Label: "kube-system", Risk: "critical"},
					{Value: "all", Label: "All Namespaces (*)", Risk: "critical"},
				},
				Nodes: []Option{
					{Value: "finance-nodes", Label: "Finance Node Pool", Description: "Dedicated finance workload nodes", Risk: "high"},
					{Value: "general-nodes", Label: "General Node Pool", Description: "Shared general-purpose compute nodes", Risk: "medium"},
					{Value: "gpu-nodes", Label: "GPU Node Pool", Description: "GPU compute nodes for ML workloads", Risk: "medium"},
					{Value: "control-plane", Label: "Control Plane Nodes", Description: "K8s control plane — highest privilege", Risk: "critical"},
					{Value: "all", Label: "All Nodes (*)", Risk: "critical"},
				},
				IPRanges: []Option{
					{Value: "10.0.0.0/8", Label: "10.x RFC1918 Internal", Risk: "low"},
					{Value: "172.16.0.0/12", Label: "172.x RFC1918 Internal", Risk: "low"},
					{Value: "192.168.0.0/16", Label: "192.168.x RFC1918", Risk: "low"},
					{Value: "vpn-egress", Label: "VPN Egress IPs Only", Risk: "medium"},
					{Value: "office-cidrs", Label: "Office Network CIDRs", Risk: "medium"},
					{Value: "0.0.0.0/0", Label: "Any IP (public internet)", Risk: "critical"},
				},
				GeoRegions: []Option{
					{Value: "US", Label: "United States", Risk: "medium"},
					{Value: "EU", Label: "European Union (GDPR)", Risk: "medium"},
					{Value: "APAC", Label: "Asia-Pacific", Risk: "medium"},
					{Value: "domestic-only", Label: "Domestic Only", Risk: "low"},
				},
				Environments: []Option{
					{Value: "production", Label: "Production", Risk: "high"},
					{Value: "staging", Label: "Staging", Risk: "medium"},
					{Value: "development", Label: "Development", Risk: "low"},
					{Value: "dr", Label: "Disaster Recovery", Risk: "high"},
				},
			},
			What: WhatOpts{
				ResourceTypes: []Option{
					{Value: "s3:object", Label: "S3 Object / Blob Storage", Risk: "medium"},
					{Value: "k8s:secret", Label: "Kubernetes Secret", Risk: "high"},
					{Value: "k8s:configmap", Label: "Kubernetes ConfigMap", Risk: "low"},
					{Value: "k8s:pod", Label: "Kubernetes Pod", Risk: "medium"},
					{Value: "k8s:deployment", Label: "Kubernetes Deployment", Risk: "high"},
					{Value: "k8s:node", Label: "Kubernetes Node Object", Risk: "critical"},
					{Value: "k8s:rbac", Label: "RBAC Roles / Bindings", Risk: "critical"},
					{Value: "db:table", Label: "Database Table (SQL)", Risk: "high"},
					{Value: "db:schema", Label: "Database Schema / DDL", Risk: "critical"},
					{Value: "api:endpoint", Label: "API Endpoint / Route", Risk: "medium"},
					{Value: "vault:secret", Label: "HashiCorp Vault Secret", Risk: "critical"},
					{Value: "iam:role", Label: "IAM Role (AWS/GCP/Azure)", Risk: "critical"},
					{Value: "network:policy", Label: "Network / Firewall Policy", Risk: "critical"},
					{Value: "kafka:topic", Label: "Kafka Topic / Event Stream", Risk: "medium"},
				},
				APIs: []Option{
					{Value: "finance-api", Label: "Finance API", Risk: "high"},
					{Value: "user-api", Label: "User / Identity API", Risk: "medium"},
					{Value: "audit-api", Label: "Audit Log API (read-only)", Risk: "low"},
					{Value: "admin-api", Label: "Admin API", Risk: "critical"},
					{Value: "data-api", Label: "Data Pipeline API", Risk: "medium"},
					{Value: "metrics-api", Label: "Metrics / Observability API", Risk: "low"},
					{Value: "payment-api", Label: "Payment Processing API", Risk: "critical"},
				},
				Classifications: []Option{
					{Value: "public", Label: "Public", Description: "No sensitivity restrictions apply", Risk: "low"},
					{Value: "internal", Label: "Internal", Description: "Internal-only, no external disclosure", Risk: "low"},
					{Value: "confidential", Label: "Confidential", Description: "Business confidential data", Risk: "high"},
					{Value: "pii", Label: "PII / Personal Data", Description: "GDPR-regulated personal data subject", Risk: "high"},
					{Value: "restricted", Label: "Restricted", Description: "Highly restricted, limited distribution", Risk: "high"},
					{Value: "secret", Label: "Secret", Description: "Maximum restriction, need-to-know only", Risk: "critical"},
				},
				Namespaces: []Option{
					{Value: "finance", Label: "finance", Risk: "high"},
					{Value: "auth-system", Label: "auth-system", Risk: "critical"},
					{Value: "data-platform", Label: "data-platform", Risk: "medium"},
					{Value: "monitoring", Label: "monitoring", Risk: "low"},
				},
			},
			How: HowOpts{
				Verbs: []Option{
					{Value: "get", Label: "GET / Read", Description: "Read a single resource by name or ID", Risk: "low"},
					{Value: "list", Label: "LIST / Enumerate", Description: "List or enumerate resources in a scope", Risk: "low"},
					{Value: "watch", Label: "WATCH / Subscribe", Description: "Subscribe to real-time resource change events", Risk: "medium"},
					{Value: "create", Label: "CREATE / Write", Description: "Create new resources in the target scope", Risk: "medium"},
					{Value: "update", Label: "UPDATE / Modify", Description: "Replace an existing resource fully", Risk: "high"},
					{Value: "patch", Label: "PATCH / Partial Update", Description: "Partially modify a resource in place", Risk: "high"},
					{Value: "delete", Label: "DELETE / Remove", Description: "Permanently remove resources", Risk: "critical"},
					{Value: "exec", Label: "EXEC / Execute", Description: "Execute commands inside pods or containers", Risk: "critical"},
					{Value: "escalate", Label: "ESCALATE / Privilege", Description: "Privilege escalation operations", Risk: "critical"},
					{Value: "impersonate", Label: "IMPERSONATE", Description: "Act as another principal identity", Risk: "critical"},
				},
				Protocols: []Option{
					{Value: "https", Label: "HTTPS REST", Risk: "low"},
					{Value: "grpc_tls", Label: "gRPC + TLS", Risk: "low"},
					{Value: "mtls", Label: "Mutual TLS (mTLS)", Risk: "low"},
					{Value: "sql_tls", Label: "SQL over TLS", Risk: "medium"},
					{Value: "kafka_sasl", Label: "Kafka + SASL/TLS", Risk: "medium"},
					{Value: "ssh", Label: "SSH / Bastion", Risk: "high"},
				},
				Encryption: []Option{
					{Value: "tls13_required", Label: "TLS 1.3 Required", Risk: "low"},
					{Value: "tls12_min", Label: "TLS 1.2 Minimum", Risk: "medium"},
					{Value: "mtls_required", Label: "mTLS Mandatory", Risk: "low"},
					{Value: "e2e_encrypted", Label: "End-to-End Payload Encryption", Risk: "low"},
					{Value: "none", Label: "No Encryption (plaintext)", Risk: "critical"},
				},
			},
			Why: WhyOpts{
				Purposes: []Option{
					{Value: "audit", Label: "Audit / Compliance Review", Description: "Scheduled compliance or regulatory audit", Risk: "low"},
					{Value: "operations", Label: "Routine Operations", Description: "Normal day-to-day operational access", Risk: "medium"},
					{Value: "incident_response", Label: "Incident Response", Description: "Active incident investigation or mitigation", Risk: "high"},
					{Value: "data_migration", Label: "Data Migration", Description: "One-time or periodic data migration task", Risk: "high"},
					{Value: "development", Label: "Development / Testing", Description: "Development and integration testing work", Risk: "medium"},
					{Value: "analytics", Label: "Analytics / Reporting", Description: "Business intelligence and reporting queries", Risk: "medium"},
					{Value: "gdpr_request", Label: "GDPR / Privacy Request", Description: "Data subject rights request processing", Risk: "medium"},
					{Value: "break_glass", Label: "Break-Glass Emergency", Description: "Emergency override — maximum audit trail required", Risk: "critical"},
				},
				RequireTicket:     true,
				BreakGlassAllowed: false,
			},
			HowMany: HowManyOpts{
				RateLimits: []Option{
					{Value: "10/min", Label: "10 req/min (low)", Risk: "low"},
					{Value: "100/min", Label: "100 req/min", Risk: "low"},
					{Value: "1000/min", Label: "1,000 req/min", Risk: "medium"},
					{Value: "10000/min", Label: "10,000 req/min", Risk: "high"},
					{Value: "unlimited", Label: "Unlimited", Risk: "critical"},
				},
				MaxResults: []Option{
					{Value: "50", Label: "50 rows", Risk: "low"},
					{Value: "500", Label: "500 rows", Risk: "low"},
					{Value: "1000", Label: "1,000 rows", Risk: "medium"},
					{Value: "10000", Label: "10,000 rows", Risk: "high"},
					{Value: "unlimited", Label: "Unlimited rows", Risk: "critical"},
				},
				BurstLimits: []Option{
					{Value: "5", Label: "Burst 5", Risk: "low"},
					{Value: "20", Label: "Burst 20", Risk: "low"},
					{Value: "100", Label: "Burst 100", Risk: "medium"},
					{Value: "500", Label: "Burst 500", Risk: "high"},
					{Value: "unlimited", Label: "No burst cap", Risk: "critical"},
				},
			},
			Relations: RelationOpts{
				Relations: []Option{
					{Value: "viewer", Label: "viewer", Description: "Read-only relationship (OpenFGA)", Risk: "low"},
					{Value: "editor", Label: "editor", Description: "Read and write relationship access", Risk: "high"},
					{Value: "owner", Label: "owner", Description: "Full control over object", Risk: "critical"},
					{Value: "member", Label: "member", Description: "Group or team membership relation", Risk: "medium"},
					{Value: "admin", Label: "admin", Description: "Administrative relationship access", Risk: "critical"},
					{Value: "auditor", Label: "auditor", Description: "Audit-log access relationship", Risk: "low"},
					{Value: "parent", Label: "parent", Description: "Zanzibar parent namespace relation", Risk: "high"},
				},
			},
		},
	}
}

// FromSigned extracts and parses a PermitTemplate from a SignedDocument
func FromSigned(doc *cry.SignedDocument) (*PermitTemplate, error) {
	var t PermitTemplate
	if err := json.Unmarshal(doc.Payload, &t); err != nil {
		return nil, fmt.Errorf("unmarshal template: %w", err)
	}
	return &t, nil
}
