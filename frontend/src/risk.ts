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
