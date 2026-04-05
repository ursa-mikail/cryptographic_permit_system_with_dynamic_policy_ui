// ── Option & Risk ─────────────────────────────────────────────────────────────

export type Risk = 'low' | 'medium' | 'high' | 'critical'

export interface Option {
  value: string
  label: string
  description?: string
  risk: Risk
}

// ── Template shape (mirrors Go PermitTemplate) ────────────────────────────────

export interface WhoOpts {
  service_types: Option[]
  groups:        Option[]
  auth_methods:  Option[]
  trust_levels:  Option[]
}
export interface WhenOpts {
  max_ttls:      Option[]
  time_windows:  Option[]
  allowed_days:  Option[]
  timezones:     Option[]
}
export interface WhereOpts {
  clusters:      Option[]
  namespaces:    Option[]
  nodes:         Option[]
  ip_ranges:     Option[]
  geo_regions:   Option[]
  environments:  Option[]
}
export interface WhatOpts {
  resource_types:  Option[]
  apis:            Option[]
  classifications: Option[]
  namespaces:      Option[]
}
export interface HowOpts {
  verbs:      Option[]
  protocols:  Option[]
  encryption: Option[]
}
export interface WhyOpts {
  purposes:            Option[]
  require_ticket:      boolean
  break_glass_allowed: boolean
}
export interface HowManyOpts {
  rate_limits:  Option[]
  max_results:  Option[]
  burst_limits: Option[]
}
export interface RelationOpts {
  relations: Option[]
}

export interface Dimensions {
  who:       WhoOpts
  when:      WhenOpts
  where:     WhereOpts
  what:      WhatOpts
  how:       HowOpts
  why:       WhyOpts
  how_many:  HowManyOpts
  relations: RelationOpts
}

export interface PermitTemplate {
  template_id:  string
  name:         string
  version:      string
  created_at:   string
  description:  string
  dimensions:   Dimensions
}

// ── Signed document (mirrors Go SignedDocument) ───────────────────────────────

export interface DocHeader {
  alg:        string
  ver:        string
  doc_type:   string
  issuer:     string
  issued_at:  string
  expires_at?: string
}

export interface SignedDocument {
  header:  DocHeader
  payload: unknown        // raw JSON — may be string or object depending on parse
  digest:  string
  sig:     string
  key_id:  string
}

// ── UI form state ─────────────────────────────────────────────────────────────

export interface FormState {
  // meta
  permitId:    string
  description: string
  ticketId:    string
  justification: string

  // who
  whoType:       string
  whoGroups:     string[]
  whoAuthMethod: string
  whoTrustLevel: string
  whoSpiffe:     string

  // when
  whenTTL:        string
  whenTimeWindow: string
  whenDays:       string
  whenTimezone:   string

  // where
  whereClusters:    string[]
  whereNamespaces:  string[]
  whereNodes:       string[]
  whereIPRanges:    string[]
  whereGeoRegions:  string[]
  whereEnvironments: string[]

  // what
  whatResources:      string[]
  whatAPIs:           string[]
  whatClassification: string
  whatNamespaces:     string[]

  // how
  howVerbs:      string[]
  howProtocol:   string
  howEncryption: string

  // why
  whyPurpose:              string
  whyRequireJustification: boolean
  whyBreakGlass:           boolean

  // how many
  howManyRate:  string
  howManyMax:   string
  howManyBurst: string

  // relations
  relations: string[]
}

// ── Nav ───────────────────────────────────────────────────────────────────────

export type DimKey =
  | 'meta' | 'who' | 'when' | 'where' | 'what'
  | 'how' | 'why' | 'howmany' | 'relations' | 'issued' | 'verify'

export interface NavItem {
  id:    DimKey
  label: string
  glyph: string
  sub:   string
}
