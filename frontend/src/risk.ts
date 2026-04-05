import type { FormState, PermitTemplate, Risk } from './types'

// ── Risk colour palette (matches CSS classes in App.css) ──────────────────────

export const RISK_COLOR: Record<Risk, string> = {
  low:      '#22c55e',   // green-500
  medium:   '#f59e0b',   // amber-500
  high:     '#f97316',   // orange-500
  critical: '#ef4444',   // red-500
}

// ── Numeric risk weights ──────────────────────────────────────────────────────

const WEIGHT: Record<Risk, number> = { low: 1, medium: 3, high: 6, critical: 10 }

function optRisk(
  opts: Array<{ value: string; risk: Risk }> | undefined,
  values: string[]
): number {
  if (!opts) return 0
  return values.reduce((acc, v) => {
    const o = opts.find(x => x.value === v)
    return acc + (o ? WEIGHT[o.risk] : 0)
  }, 0)
}

function singleRisk(
  opts: Array<{ value: string; risk: Risk }> | undefined,
  value: string
): number {
  if (!opts || !value) return 0
  const o = opts.find(x => x.value === value)
  return o ? WEIGHT[o.risk] : 0
}

// ── Compute aggregate risk score (0–100) ─────────────────────────────────────

export function computeRiskScore(form: FormState, template: PermitTemplate | null): number {
  if (!template) return 0
  const d = template.dimensions

  let score = 0
  let maxScore = 0

  const add = (s: number, max: number) => { score += s; maxScore += max }

  // WHO
  add(singleRisk(d.who.service_types, form.whoType), 10)
  add(optRisk(d.who.groups, form.whoGroups), 10)
  add(singleRisk(d.who.auth_methods, form.whoAuthMethod), 10)
  add(singleRisk(d.who.trust_levels, form.whoTrustLevel), 10)

  // WHERE
  add(optRisk(d.where.clusters, form.whereClusters), 30)
  add(optRisk(d.where.namespaces, form.whereNamespaces), 20)
  add(optRisk(d.where.nodes, form.whereNodes), 20)
  add(optRisk(d.where.ip_ranges, form.whereIPRanges), 20)
  add(optRisk(d.where.environments, form.whereEnvironments), 20)

  // WHAT
  add(optRisk(d.what.resource_types, form.whatResources), 30)
  add(optRisk(d.what.apis, form.whatAPIs), 20)
  add(singleRisk(d.what.classifications, form.whatClassification), 20)

  // HOW
  add(optRisk(d.how.verbs, form.howVerbs), 40)
  add(singleRisk(d.how.protocols, form.howProtocol), 10)
  add(singleRisk(d.how.encryption, form.howEncryption), 10)

  // WHY
  add(singleRisk(d.why.purposes, form.whyPurpose), 20)
  if (form.whyBreakGlass) add(WEIGHT.critical, 10)
  else add(0, 10)

  // HOW MANY
  add(singleRisk(d.how_many.rate_limits, form.howManyRate), 10)
  add(singleRisk(d.how_many.max_results, form.howManyMax), 10)
  add(singleRisk(d.how_many.burst_limits, form.howManyBurst), 10)

  // RELATIONS
  add(optRisk(d.relations.relations, form.relations), 20)

  if (maxScore === 0) return 0
  return Math.min(100, Math.round((score / maxScore) * 100))
}

// ── Risk colour & label from 0–100 score ─────────────────────────────────────

export function riskColor(score: number): string {
  if (score >= 75) return RISK_COLOR.critical
  if (score >= 50) return RISK_COLOR.high
  if (score >= 25) return RISK_COLOR.medium
  return RISK_COLOR.low
}

export function riskLabel(score: number): string {
  if (score >= 75) return 'CRITICAL'
  if (score >= 50) return 'HIGH'
  if (score >= 25) return 'MEDIUM'
  return 'LOW'
}

// ── Default empty form ────────────────────────────────────────────────────────

export function makeDefaultForm(): FormState {
  return {
    permitId:    '',
    description: '',
    ticketId:    '',
    justification: '',

    whoType:       '',
    whoGroups:     [],
    whoAuthMethod: '',
    whoTrustLevel: '',
    whoSpiffe:     '',

    whenTTL:        '',
    whenTimeWindow: '',
    whenDays:       '',
    whenTimezone:   '',

    whereClusters:     [],
    whereNamespaces:   [],
    whereNodes:        [],
    whereIPRanges:     [],
    whereGeoRegions:   [],
    whereEnvironments: [],

    whatResources:      [],
    whatAPIs:           [],
    whatClassification: '',
    whatNamespaces:     [],

    howVerbs:      [],
    howProtocol:   '',
    howEncryption: '',

    whyPurpose:              '',
    whyRequireJustification: true,
    whyBreakGlass:           false,

    howManyRate:  '',
    howManyMax:   '',
    howManyBurst: '',

    relations: [],
  }
}

// ── Timestamp-seeded random form generator ────────────────────────────────────

function seededPick<T>(arr: T[], seed: number): T {
  return arr[seed % arr.length]
}

function seededPickMulti<T>(arr: T[], seed: number, min: number, max: number): T[] {
  const count = min + (seed % (max - min + 1))
  const picked: T[] = []
  for (let i = 0; i < count && i < arr.length; i++) {
    const item = arr[(seed + i * 7) % arr.length]
    if (!picked.includes(item)) picked.push(item)
  }
  return picked
}

export function makeRandomForm(template: import('./types').PermitTemplate): FormState {
  const ts  = Date.now()
  const s1  = Math.floor(ts / 1000)       // seconds
  const s2  = Math.floor(ts / 100) % 1000 // deciseconds
  const s3  = ts % 100                    // centiseconds

  const d = template.dimensions

  // Generate permit ID from timestamp
  const hex  = ts.toString(16).toUpperCase()
  const permitId = `PA-${hex.slice(0, 4)}-${hex.slice(4, 8)}`

  // Ticket from timestamp
  const ticketId = `INC-${String(ts).slice(-6)}`

  // Pick WHO
  const whoType       = seededPick(d.who.service_types, s1).value
  const whoGroups     = seededPickMulti(d.who.groups, s2, 1, 2).map(o => o.value)
  const whoAuthMethod = seededPick(d.who.auth_methods, s3).value
  const whoTrustLevel = seededPick(d.who.trust_levels, s1 + s2).value
  const whoSpiffe     = `spiffe://cluster.local/ns/${seededPick(['finance','platform','auth-system','data'], s2)}/sa/${whoType}-${hex.slice(-4).toLowerCase()}`

  // Pick WHEN
  const whenTTL        = seededPick(d.when.max_ttls, s2).value
  const whenTimeWindow = seededPick(d.when.time_windows, s1).value
  const whenDays       = seededPick(d.when.allowed_days, s3).value
  const whenTimezone   = seededPick(d.when.timezones, s2).value

  // Pick WHERE
  const whereClusters     = seededPickMulti(d.where.clusters.filter(o => o.value !== 'all'), s1, 1, 2).map(o => o.value)
  const whereNamespaces   = seededPickMulti(d.where.namespaces.filter(o => o.value !== 'all'), s3, 1, 3).map(o => o.value)
  const whereNodes        = seededPickMulti(d.where.nodes.filter(o => o.value !== 'all'), s2, 1, 1).map(o => o.value)
  const whereIPRanges     = seededPickMulti(d.where.ip_ranges, s1 + 3, 1, 2).map(o => o.value)
  const whereGeoRegions   = seededPickMulti(d.where.geo_regions, s2 + 5, 1, 2).map(o => o.value)
  const whereEnvironments = [seededPick(d.where.environments.filter(o => o.value !== 'production' || s1 % 3 === 0), s1 + s3).value]

  // Pick WHAT
  const whatResources     = seededPickMulti(d.what.resource_types, s3, 1, 3).map(o => o.value)
  const whatAPIs          = seededPickMulti(d.what.apis, s1, 1, 2).map(o => o.value)
  const whatClassification = seededPick(d.what.classifications, s2 + 1).value
  const whatNamespaces    = seededPickMulti(d.where.namespaces.filter(o => o.value !== 'all'), s3 + 2, 1, 2).map(o => o.value)

  // Pick HOW — low-risk verbs for demo
  const safeVerbs   = d.how.verbs.filter(o => o.risk === 'low' || o.risk === 'medium')
  const howVerbs    = seededPickMulti(safeVerbs.length ? safeVerbs : d.how.verbs, s2, 1, 3).map(o => o.value)
  const howProtocol  = seededPick(d.how.protocols, s1).value
  const howEncryption = seededPick(d.how.encryption.filter(o => o.value !== 'none'), s3).value

  // Pick WHY
  const safePurposes = d.why.purposes.filter(o => o.value !== 'break_glass')
  const whyPurpose  = seededPick(safePurposes.length ? safePurposes : d.why.purposes, s1 + s2).value

  const purposeLabels: Record<string, string> = {
    audit:            'Quarterly compliance audit per CTRL-42 / SOC2 requirement',
    operations:       'Routine operational access for platform maintenance',
    incident_response:'Active incident P2 investigation — tracking anomalous auth pattern',
    data_migration:   'One-time data migration from legacy cluster to new region',
    development:      'Development integration testing on staging environment',
    analytics:        'BI dashboard refresh — exec reporting Q4 metrics',
    gdpr_request:     'GDPR Article 15 data subject access request #DSR-' + String(ts).slice(-4),
    break_glass:      'Emergency break-glass — SEV1 production outage',
  }
  const justification = purposeLabels[whyPurpose] ?? `Access required for ${whyPurpose} — ticket ${ticketId}`

  const descLabels: Record<string, string> = {
    audit:            'Read-only audit access to finance resources',
    operations:       'Platform ops access for routine maintenance',
    incident_response:'IR team read access during active incident',
    data_migration:   'Elevated access for one-time data migration',
    development:      'Dev environment access for integration testing',
    analytics:        'Read access for analytics and BI reporting',
    gdpr_request:     'Limited read access for GDPR DSR processing',
    break_glass:      'Emergency full access — break glass protocol',
  }
  const description = descLabels[whyPurpose] ?? `${whyPurpose} access permit`

  // HOW MANY
  const howManyRate  = seededPick(d.how_many.rate_limits.filter(o => o.value !== 'unlimited'), s1).value
  const howManyMax   = seededPick(d.how_many.max_results.filter(o => o.value !== 'unlimited'), s2).value
  const howManyBurst = seededPick(d.how_many.burst_limits.filter(o => o.value !== 'unlimited'), s3).value

  // Relations
  const relations = seededPickMulti(d.relations.relations, s1 + s2, 1, 2).map(o => o.value)

  return {
    permitId, description, ticketId, justification,
    whoType, whoGroups, whoAuthMethod, whoTrustLevel, whoSpiffe,
    whenTTL, whenTimeWindow, whenDays, whenTimezone,
    whereClusters, whereNamespaces, whereNodes, whereIPRanges, whereGeoRegions, whereEnvironments,
    whatResources, whatAPIs, whatClassification, whatNamespaces,
    howVerbs, howProtocol, howEncryption,
    whyPurpose, whyRequireJustification: true, whyBreakGlass: false,
    howManyRate, howManyMax, howManyBurst,
    relations,
  }
}
