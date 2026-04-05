import { useState, useEffect, useCallback, useRef } from 'react'
import type { PermitTemplate, SignedDocument, FormState, DimKey, NavItem, Option, Risk } from './types'
import { checkHealth, fetchTemplate, issuePermit, verifyPermit, clientVerifySignature } from './api'
import { computeRiskScore, riskColor, riskLabel, makeDefaultForm, RISK_COLOR } from './risk'
import './App.css'

const NAV_ITEMS: NavItem[] = [
  { id: 'meta',      label: 'METADATA',   glyph: '◈', sub: 'Identity & ticket' },
  { id: 'who',       label: 'WHO',        glyph: '▣', sub: 'Subject identity' },
  { id: 'when',      label: 'WHEN',       glyph: '◷', sub: 'Temporal bounds' },
  { id: 'where',     label: 'WHERE',      glyph: '◉', sub: 'Scope & location' },
  { id: 'what',      label: 'WHAT',       glyph: '◆', sub: 'Resources & APIs' },
  { id: 'how',       label: 'HOW',        glyph: '◐', sub: 'Actions & protocol' },
  { id: 'why',       label: 'WHY',        glyph: '◑', sub: 'Purpose & consent' },
  { id: 'howmany',   label: 'HOW MANY',   glyph: '◫', sub: 'Rate & quota' },
  { id: 'relations', label: 'RELATIONS',  glyph: '◎', sub: 'ReBAC tuples' },
  { id: 'issued',    label: 'SIGNED JSON',glyph: '✦', sub: 'Last issued permit' },
  { id: 'verify',    label: 'VERIFY',     glyph: '◍', sub: 'Check signature' },
]

// ─── Option Card ─────────────────────────────────────────────────────────────
function OptCard({ opt, selected, onToggle }: { opt: Option; selected: boolean; onToggle: () => void }) {
  const rc = RISK_COLOR[opt.risk as Risk]
  return (
    <div
      className={`opt-card opt-card--${opt.risk}${selected ? ' opt-card--selected' : ''}`}
      onClick={onToggle}
      style={selected ? { borderColor: rc, background: `${rc}10`, color: rc } : {}}
    >
      {selected && <span className="opt-check">✓</span>}
      <div className="opt-label">
        <span className="opt-dot" style={{ background: rc }} />
        {opt.label}
        {!selected && <span className="risk-tag" style={{ color: rc, borderColor: `${rc}40`, background: `${rc}10` }}>{opt.risk}</span>}
      </div>
      {opt.description && <div className="opt-desc">{opt.description}</div>}
    </div>
  )
}

// ─── Option Grid ──────────────────────────────────────────────────────────────
function OptGrid({ children, compact, wide }: { children: React.ReactNode; compact?: boolean; wide?: boolean }) {
  return (
    <div className={`opt-grid${compact ? ' opt-grid--compact' : ''}${wide ? ' opt-grid--wide' : ''}`}>
      {children}
    </div>
  )
}

// ─── Field Label ──────────────────────────────────────────────────────────────
function FL({ children, req }: { children: React.ReactNode; req?: boolean }) {
  return (
    <div className="field-label">
      <span className="field-label-line" />
      {children}
      {req && <span className="field-req">*</span>}
      <span className="field-label-line" />
    </div>
  )
}

// ─── CRT Input ────────────────────────────────────────────────────────────────
function CrtInput({ value, onChange, placeholder }: { value: string; onChange: (v: string) => void; placeholder?: string }) {
  return (
    <input
      className="crt-input"
      value={value}
      onChange={e => onChange(e.target.value)}
      placeholder={placeholder}
      spellCheck={false}
    />
  )
}

// ─── CRT Select ───────────────────────────────────────────────────────────────
function CrtSelect({ value, onChange, children }: { value: string; onChange: (v: string) => void; children: React.ReactNode }) {
  return (
    <select className="crt-select" value={value} onChange={e => onChange(e.target.value)}>
      {children}
    </select>
  )
}

// ─── Toggle ───────────────────────────────────────────────────────────────────
function Toggle({ label, desc, value, onChange }: { label: string; desc: string; value: boolean; onChange: (v: boolean) => void }) {
  return (
    <div className="toggle-row" onClick={() => onChange(!value)}>
      <div>
        <div className="toggle-label">{label}</div>
        <div className="toggle-desc">{desc}</div>
      </div>
      <div className={`toggle-switch${value ? ' toggle-switch--on' : ''}`}>
        <div className="toggle-knob" />
      </div>
    </div>
  )
}

// ─── Section header ───────────────────────────────────────────────────────────
function SectionHead({ glyph, label, sub }: { glyph: string; label: string; sub: string }) {
  return (
    <div className="section-head">
      <div className="section-title">{glyph} {label}</div>
      <div className="section-sub">{sub}</div>
      <div className="section-rule" />
    </div>
  )
}

// ─── Status Pill ─────────────────────────────────────────────────────────────
function Pill({ label, state }: { label: string; state: 'ok' | 'warn' | 'err' | 'loading' }) {
  return (
    <div className={`pill pill--${state}`}>
      <span className="pill-dot" />
      {label}
    </div>
  )
}

// ─── Main App ─────────────────────────────────────────────────────────────────
export default function App() {
  const [activeDim, setActiveDim] = useState<DimKey>('meta')
  const [template, setTemplate]   = useState<PermitTemplate | null>(null)
  const [pubKeyB64, setPubKeyB64] = useState('')
  const [keyId, setKeyId]         = useState('')
  const [serverOk, setServerOk]   = useState<'loading'|'ok'|'err'>('loading')
  const [tmplState, setTmplState] = useState<'loading'|'verified'|'err'>('loading')
  const [tmplMsg, setTmplMsg]     = useState('Fetching signed template from authority…')
  const [form, setForm]           = useState<FormState>(makeDefaultForm())
  const [signedPermit, setSignedPermit] = useState<SignedDocument | null>(null)
  const [showModal, setShowModal] = useState(false)
  const [issuing, setIssuing]     = useState(false)
  const [verifyInput, setVerifyInput] = useState('')
  const [verifyResult, setVerifyResult] = useState<any>(null)
  const [verifying, setVerifying] = useState(false)
  const [toast, setToast]         = useState<{ msg: string; type: 'ok'|'err'|'info' } | null>(null)
  const toastRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  const notify = useCallback((msg: string, type: 'ok'|'err'|'info' = 'info') => {
    setToast({ msg, type })
    if (toastRef.current) clearTimeout(toastRef.current)
    toastRef.current = setTimeout(() => setToast(null), 3500)
  }, [])

  const patch = (u: Partial<FormState>) => setForm(f => ({ ...f, ...u }))

  const toggleMulti = (key: keyof FormState, val: string) => {
    const arr = (form[key] as string[]) ?? []
    patch({ [key]: arr.includes(val) ? arr.filter(x => x !== val) : [...arr, val] })
  }

  const toggleSingle = (key: keyof FormState, val: string) => {
    patch({ [key]: (form[key] as string) === val ? '' : val })
  }

  // ── Bootstrap: load signed template ──────────────────────────────────────
  useEffect(() => {
    ;(async () => {
      const ok = await checkHealth()
      setServerOk(ok ? 'ok' : 'err')
      if (!ok) {
        setTmplState('err')
        setTmplMsg('SERVER OFFLINE — cannot load signed template')
        return
      }
      try {
        const data = await fetchTemplate()
        const doc: SignedDocument = data.signed_template
        setPubKeyB64(data.public_key)
        setKeyId(data.key_id)

        // Client-side signature verification
        const { digestOk, sigOk } = await clientVerifySignature(doc, data.public_key)
        if (!digestOk) {
          setTmplState('err')
          setTmplMsg('⚠ PAYLOAD DIGEST MISMATCH — template may be tampered. REFUSING TO LOAD.')
          return
        }

        const parsed: PermitTemplate = typeof doc.payload === 'string'
          ? JSON.parse(doc.payload) : doc.payload
        setTemplate(parsed)
        setTmplState('verified')
        setTmplMsg(
          sigOk
            ? `Ed25519 VERIFIED ✓  ·  ${parsed.name} v${parsed.version}  ·  key_id: ${data.key_id}  ·  digest: ${doc.digest.slice(0,16)}…`
            : `Digest VALID ✓ (Ed25519 partial)  ·  ${parsed.name} v${parsed.version}  ·  key_id: ${data.key_id}`
        )
      } catch (e: any) {
        setTmplState('err')
        setTmplMsg(`Failed to load template: ${e.message}`)
      }
    })()
  }, [])

  // ── Issue permit ──────────────────────────────────────────────────────────
  const handleIssue = async () => {
    if (!form.permitId || !form.description) { notify('Fill METADATA: Permit ID + Description', 'err'); setActiveDim('meta'); return }
    if (!form.whoType)          { notify('Select a WHO type', 'err'); setActiveDim('who'); return }
    if (!form.whenTTL)          { notify('Select a TTL in WHEN', 'err'); setActiveDim('when'); return }
    if (!form.howVerbs.length)  { notify('Select at least one verb in HOW', 'err'); setActiveDim('how'); return }
    if (!form.whyPurpose)       { notify('Select a purpose in WHY', 'err'); setActiveDim('why'); return }

    setIssuing(true)
    const payload = {
      permit_id:    form.permitId,
      description:  form.description,
      issued_at:    new Date().toISOString(),
      expires_at:   new Date().toISOString(),
      issuer:       '',
      template_id:  template?.template_id ?? 'gold-standard-v1',
      template_version: template?.version ?? '1.0.0',
      who: {
        type: form.whoType, groups: form.whoGroups,
        auth_method: form.whoAuthMethod, trust_level: form.whoTrustLevel,
        spiffe_pattern: form.whoSpiffe,
      },
      when: { ttl: form.whenTTL, time_window: form.whenTimeWindow, allowed_days: form.whenDays, timezone: form.whenTimezone },
      where: { clusters: form.whereClusters, namespaces: form.whereNamespaces, nodes: form.whereNodes, ip_ranges: form.whereIPRanges, geo_regions: form.whereGeoRegions, environments: form.whereEnvironments },
      what: { resource_types: form.whatResources, apis: form.whatAPIs, classification: form.whatClassification, resource_namespaces: form.whatNamespaces },
      how: { verbs: form.howVerbs, protocol: form.howProtocol, encryption: form.howEncryption },
      why: { purpose: form.whyPurpose, require_justification: form.whyRequireJustification, ticket_id: form.ticketId, justification: form.justification, break_glass: form.whyBreakGlass },
      how_many: { rate_limit: form.howManyRate, max_results: form.howManyMax, burst_limit: form.howManyBurst },
      relations: { allowed_relations: form.relations },
    }

    try {
      const data = await issuePermit(payload)
      setSignedPermit(data.signed_permit)
      setVerifyInput(JSON.stringify(data.signed_permit, null, 2))
      setActiveDim('issued')
      notify('Permit signed with Ed25519 ✓ — see SIGNED JSON tab', 'ok')
    } catch (e: any) {
      notify(`Issue failed: ${e.message}`, 'err')
    } finally {
      setIssuing(false)
    }
  }

  // ── Verify permit ─────────────────────────────────────────────────────────
  const handleVerify = async () => {
    if (!verifyInput.trim()) { notify('Paste signed permit JSON first', 'err'); return }
    setVerifying(true)
    setVerifyResult(null)
    try {
      let doc: SignedDocument
      try { doc = JSON.parse(verifyInput) } catch { throw new Error('Invalid JSON') }
      const data = await verifyPermit(doc)
      setVerifyResult(data)
    } catch (e: any) {
      // Client-side fallback
      try {
        const doc: SignedDocument = JSON.parse(verifyInput)
        if (pubKeyB64) {
          const { digestOk, sigOk } = await clientVerifySignature(doc, pubKeyB64)
          setVerifyResult({ valid: digestOk && sigOk, reason: digestOk && sigOk ? null : 'Signature or digest invalid', key_id: doc.key_id })
        } else {
          setVerifyResult({ valid: false, reason: e.message })
        }
      } catch (e2: any) {
        setVerifyResult({ valid: false, reason: e2.message })
      }
    } finally {
      setVerifying(false)
    }
  }

  // ── Dimension completion count ────────────────────────────────────────────
  const dimCount = (id: DimKey): number => {
    switch (id) {
      case 'meta':      return [form.permitId, form.description].filter(Boolean).length
      case 'who':       return [form.whoType, form.whoAuthMethod, form.whoTrustLevel].filter(Boolean).length + form.whoGroups.length
      case 'when':      return [form.whenTTL, form.whenTimeWindow, form.whenDays].filter(Boolean).length
      case 'where':     return form.whereClusters.length + form.whereNamespaces.length + form.whereNodes.length + form.whereIPRanges.length + form.whereEnvironments.length
      case 'what':      return form.whatResources.length + form.whatAPIs.length + (form.whatClassification ? 1 : 0)
      case 'how':       return form.howVerbs.length + [form.howProtocol, form.howEncryption].filter(Boolean).length
      case 'why':       return (form.whyPurpose ? 1 : 0) + (form.whyRequireJustification ? 1 : 0)
      case 'howmany':   return [form.howManyRate, form.howManyMax, form.howManyBurst].filter(Boolean).length
      case 'relations': return form.relations.length
      case 'issued':    return signedPermit ? 1 : 0
      case 'verify':    return 0
      default:          return 0
    }
  }

  const riskScore = computeRiskScore(form, template)
  const rc        = riskColor(riskScore)
  const rl        = riskLabel(riskScore)
  const d         = template?.dimensions

  const copy = (text: string) => { navigator.clipboard.writeText(text); notify('Copied ✓', 'ok') }
  const download = (content: string, name: string) => {
    const a = document.createElement('a')
    a.href = URL.createObjectURL(new Blob([content], { type: 'application/json' }))
    a.download = name
    a.click()
  }

  // ─── RENDER ───────────────────────────────────────────────────────────────
  return (
    <div className="app">

      {/* ── Header ── */}
      <header className="header">
        <div className="header-left">
          <span className="logo">◈ PERMIT.AUTHORITY</span>
          <span className="logo-sep">│</span>
          <span className="logo-sub">CRYPTOGRAPHIC ACCESS PERMIT ISSUANCE SYSTEM v1.0<span className="blink">_</span></span>
        </div>
        <div className="header-right">
          {keyId && <span className="key-badge">KEY {keyId}</span>}
          <Pill label={serverOk === 'ok' ? 'SERVER ONLINE' : serverOk === 'err' ? 'SERVER OFFLINE' : 'CONNECTING…'} state={serverOk === 'ok' ? 'ok' : serverOk === 'err' ? 'err' : 'loading'} />
          <Pill label={tmplState === 'verified' ? 'TEMPLATE VERIFIED' : tmplState === 'err' ? 'TEMPLATE ERROR' : 'LOADING TEMPLATE'} state={tmplState === 'verified' ? 'ok' : tmplState === 'err' ? 'err' : 'loading'} />
        </div>
      </header>

      {/* ── Template Banner ── */}
      <div className={`tmpl-banner tmpl-banner--${tmplState}`}>
        {tmplState === 'verified' ? '◈ GOLD STANDARD TEMPLATE ' : tmplState === 'err' ? '⚠ TEMPLATE STATUS ' : '◷ LOADING '}
        — {tmplMsg}
      </div>

      {/* ── Main ── */}
      <div className="main">

        {/* ── Sidebar ── */}
        <nav className="sidebar">
          <div className="sidebar-group-label">── DIMENSIONS ──</div>
          {NAV_ITEMS.map(item => {
            const cnt = (item.id !== 'verify' && item.id !== 'issued') ? dimCount(item.id) : (item.id === 'issued' && signedPermit ? 1 : 0)
            const active = activeDim === item.id
            return (
              <div key={item.id} className={`nav-item${active ? ' nav-item--active' : ''}`} onClick={() => setActiveDim(item.id)}>
                <span className="nav-glyph">{item.glyph}</span>
                <div className="nav-info">
                  <div className="nav-label">{item.label}</div>
                  <div className="nav-sub">{item.sub}</div>
                </div>
                {item.id !== 'verify' && (
                  <span className={`nav-cnt${cnt > 0 ? ' nav-cnt--has' : ''}`}>{cnt}</span>
                )}
              </div>
            )
          })}
        </nav>

        {/* ── Form Area ── */}
        <main className="form-area">

          {/* META */}
          {activeDim === 'meta' && (
            <div className="dim-section">
              <SectionHead glyph="◈" label="METADATA" sub="Permit identity, administrative fields, and written justification" />
              <div className="two-col">
                <div><FL req>PERMIT ID</FL><CrtInput value={form.permitId} onChange={v => patch({ permitId: v })} placeholder="PA-XXXXXXXX" /></div>
                <div><FL req>DESCRIPTION</FL><CrtInput value={form.description} onChange={v => patch({ description: v })} placeholder="Finance audit read access" /></div>
                <div><FL>TICKET ID</FL><CrtInput value={form.ticketId} onChange={v => patch({ ticketId: v })} placeholder="INC-456789 / JIRA-123" /></div>
                <div><FL>WRITTEN JUSTIFICATION</FL><CrtInput value={form.justification} onChange={v => patch({ justification: v })} placeholder="Quarterly audit per CTRL-42" /></div>
              </div>
            </div>
          )}

          {/* WHO */}
          {activeDim === 'who' && d && (
            <div className="dim-section">
              <SectionHead glyph="▣" label="WHO — Subject Identity" sub="Who is requesting access? Service, user, node, or pipeline." />
              <FL req>PRINCIPAL TYPE</FL>
              <OptGrid>
                {d.who.service_types.map(o => (
                  <OptCard key={o.value} opt={o} selected={form.whoType === o.value} onToggle={() => toggleSingle('whoType', o.value)} />
                ))}
              </OptGrid>
              <FL>GROUPS / ROLES</FL>
              <OptGrid>
                {d.who.groups.map(o => (
                  <OptCard key={o.value} opt={o} selected={form.whoGroups.includes(o.value)} onToggle={() => toggleMulti('whoGroups', o.value)} />
                ))}
              </OptGrid>
              <FL req>AUTHENTICATION METHOD</FL>
              <OptGrid>
                {d.who.auth_methods.map(o => (
                  <OptCard key={o.value} opt={o} selected={form.whoAuthMethod === o.value} onToggle={() => toggleSingle('whoAuthMethod', o.value)} />
                ))}
              </OptGrid>
              <FL req>TRUST LEVEL</FL>
              <OptGrid compact>
                {d.who.trust_levels.map(o => (
                  <OptCard key={o.value} opt={o} selected={form.whoTrustLevel === o.value} onToggle={() => toggleSingle('whoTrustLevel', o.value)} />
                ))}
              </OptGrid>
              <FL>SPIFFE PATTERN (optional)</FL>
              <CrtInput value={form.whoSpiffe} onChange={v => patch({ whoSpiffe: v })} placeholder="spiffe://cluster.local/ns/*/sa/*" />
            </div>
          )}

          {/* WHEN */}
          {activeDim === 'when' && d && (
            <div className="dim-section">
              <SectionHead glyph="◷" label="WHEN — Temporal Bounds" sub="Validity window, expiry TTL, allowed hours, and timezone." />
              <FL req>MAXIMUM TTL / EXPIRY</FL>
              <OptGrid compact>
                {d.when.max_ttls.map(o => (
                  <OptCard key={o.value} opt={o} selected={form.whenTTL === o.value} onToggle={() => toggleSingle('whenTTL', o.value)} />
                ))}
              </OptGrid>
              <FL>ALLOWED TIME WINDOW</FL>
              <OptGrid>
                {d.when.time_windows.map(o => (
                  <OptCard key={o.value} opt={o} selected={form.whenTimeWindow === o.value} onToggle={() => toggleSingle('whenTimeWindow', o.value)} />
                ))}
              </OptGrid>
              <FL>ALLOWED DAYS</FL>
              <OptGrid compact>
                {d.when.allowed_days.map(o => (
                  <OptCard key={o.value} opt={o} selected={form.whenDays === o.value} onToggle={() => toggleSingle('whenDays', o.value)} />
                ))}
              </OptGrid>
              <FL>TIMEZONE</FL>
              <CrtSelect value={form.whenTimezone} onChange={v => patch({ whenTimezone: v })}>
                {d.when.timezones.map(tz => <option key={tz.value} value={tz.value}>{tz.label}</option>)}
              </CrtSelect>
            </div>
          )}

          {/* WHERE */}
          {activeDim === 'where' && d && (
            <div className="dim-section">
              <SectionHead glyph="◉" label="WHERE — Scope & Location" sub="Clusters, namespaces, nodes, network ranges, and geographic regions." />
              <FL>CLUSTERS</FL>
              <OptGrid>
                {d.where.clusters.map(o => (
                  <OptCard key={o.value} opt={o} selected={form.whereClusters.includes(o.value)} onToggle={() => toggleMulti('whereClusters', o.value)} />
                ))}
              </OptGrid>
              <FL>NAMESPACES</FL>
              <OptGrid compact>
                {d.where.namespaces.map(o => (
                  <OptCard key={o.value} opt={o} selected={form.whereNamespaces.includes(o.value)} onToggle={() => toggleMulti('whereNamespaces', o.value)} />
                ))}
              </OptGrid>
              <FL>NODE POOLS</FL>
              <OptGrid>
                {d.where.nodes.map(o => (
                  <OptCard key={o.value} opt={o} selected={form.whereNodes.includes(o.value)} onToggle={() => toggleMulti('whereNodes', o.value)} />
                ))}
              </OptGrid>
              <FL>IP / NETWORK RANGES</FL>
              <OptGrid>
                {d.where.ip_ranges.map(o => (
                  <OptCard key={o.value} opt={o} selected={form.whereIPRanges.includes(o.value)} onToggle={() => toggleMulti('whereIPRanges', o.value)} />
                ))}
              </OptGrid>
              <div className="two-col">
                <div>
                  <FL>GEO REGIONS</FL>
                  <OptGrid compact>
                    {d.where.geo_regions.map(o => (
                      <OptCard key={o.value} opt={o} selected={form.whereGeoRegions.includes(o.value)} onToggle={() => toggleMulti('whereGeoRegions', o.value)} />
                    ))}
                  </OptGrid>
                </div>
                <div>
                  <FL>ENVIRONMENTS</FL>
                  <OptGrid compact>
                    {d.where.environments.map(o => (
                      <OptCard key={o.value} opt={o} selected={form.whereEnvironments.includes(o.value)} onToggle={() => toggleMulti('whereEnvironments', o.value)} />
                    ))}
                  </OptGrid>
                </div>
              </div>
            </div>
          )}

          {/* WHAT */}
          {activeDim === 'what' && d && (
            <div className="dim-section">
              <SectionHead glyph="◆" label="WHAT — Resources & APIs" sub="Target resource types, API surfaces, and data classification." />
              <FL>RESOURCE TYPES</FL>
              <OptGrid wide>
                {d.what.resource_types.map(o => (
                  <OptCard key={o.value} opt={o} selected={form.whatResources.includes(o.value)} onToggle={() => toggleMulti('whatResources', o.value)} />
                ))}
              </OptGrid>
              <FL>API SURFACES</FL>
              <OptGrid>
                {d.what.apis.map(o => (
                  <OptCard key={o.value} opt={o} selected={form.whatAPIs.includes(o.value)} onToggle={() => toggleMulti('whatAPIs', o.value)} />
                ))}
              </OptGrid>
              <FL req>DATA CLASSIFICATION</FL>
              <OptGrid compact>
                {d.what.classifications.map(o => (
                  <OptCard key={o.value} opt={o} selected={form.whatClassification === o.value} onToggle={() => toggleSingle('whatClassification', o.value)} />
                ))}
              </OptGrid>
              <FL>RESOURCE NAMESPACES</FL>
              <OptGrid compact>
                {d.what.namespaces.map(o => (
                  <OptCard key={o.value} opt={o} selected={form.whatNamespaces.includes(o.value)} onToggle={() => toggleMulti('whatNamespaces', o.value)} />
                ))}
              </OptGrid>
            </div>
          )}

          {/* HOW */}
          {activeDim === 'how' && d && (
            <div className="dim-section">
              <SectionHead glyph="◐" label="HOW — Actions & Protocol" sub="Allowed verbs, communication protocols, and minimum encryption." />
              <FL req>VERBS / ACTIONS</FL>
              <OptGrid wide>
                {d.how.verbs.map(o => (
                  <OptCard key={o.value} opt={o} selected={form.howVerbs.includes(o.value)} onToggle={() => toggleMulti('howVerbs', o.value)} />
                ))}
              </OptGrid>
              <div className="two-col">
                <div>
                  <FL>PROTOCOL</FL>
                  <OptGrid compact>
                    {d.how.protocols.map(o => (
                      <OptCard key={o.value} opt={o} selected={form.howProtocol === o.value} onToggle={() => toggleSingle('howProtocol', o.value)} />
                    ))}
                  </OptGrid>
                </div>
                <div>
                  <FL>MINIMUM ENCRYPTION</FL>
                  <OptGrid compact>
                    {d.how.encryption.map(o => (
                      <OptCard key={o.value} opt={o} selected={form.howEncryption === o.value} onToggle={() => toggleSingle('howEncryption', o.value)} />
                    ))}
                  </OptGrid>
                </div>
              </div>
            </div>
          )}

          {/* WHY */}
          {activeDim === 'why' && d && (
            <div className="dim-section">
              <SectionHead glyph="◑" label="WHY — Purpose & Consent" sub="Business justification, purpose basis, and compliance flags." />
              <FL req>ACCESS PURPOSE</FL>
              <OptGrid>
                {d.why.purposes.map(o => (
                  <OptCard key={o.value} opt={o} selected={form.whyPurpose === o.value} onToggle={() => toggleSingle('whyPurpose', o.value)} />
                ))}
              </OptGrid>
              <FL>POLICY FLAGS</FL>
              <Toggle label="REQUIRE WRITTEN JUSTIFICATION" desc="Enforce that submitter provides written justification text in the permit" value={form.whyRequireJustification} onChange={v => patch({ whyRequireJustification: v })} />
              <Toggle label="⚠ ALLOW BREAK-GLASS OVERRIDE" desc="HIGH RISK: allows emergency bypass of all other policy constraints" value={form.whyBreakGlass} onChange={v => patch({ whyBreakGlass: v })} />
            </div>
          )}

          {/* HOW MANY */}
          {activeDim === 'howmany' && d && (
            <div className="dim-section">
              <SectionHead glyph="◫" label="HOW MANY — Rate & Quota" sub="Rate limits, maximum result sizes, and burst thresholds (OPA / Zanzibar)." />
              <FL>RATE LIMIT</FL>
              <OptGrid compact>
                {d.how_many.rate_limits.map(o => (
                  <OptCard key={o.value} opt={o} selected={form.howManyRate === o.value} onToggle={() => toggleSingle('howManyRate', o.value)} />
                ))}
              </OptGrid>
              <FL>MAX RESULTS PER REQUEST</FL>
              <OptGrid compact>
                {d.how_many.max_results.map(o => (
                  <OptCard key={o.value} opt={o} selected={form.howManyMax === o.value} onToggle={() => toggleSingle('howManyMax', o.value)} />
                ))}
              </OptGrid>
              <FL>BURST LIMIT</FL>
              <OptGrid compact>
                {d.how_many.burst_limits.map(o => (
                  <OptCard key={o.value} opt={o} selected={form.howManyBurst === o.value} onToggle={() => toggleSingle('howManyBurst', o.value)} />
                ))}
              </OptGrid>
            </div>
          )}

          {/* RELATIONS */}
          {activeDim === 'relations' && d && (
            <div className="dim-section">
              <SectionHead glyph="◎" label="RELATIONS — ReBAC Tuples" sub="Relationship-based access control (OpenFGA / Zanzibar) — allowed relation types on target objects." />
              <FL>ALLOWED RELATION TYPES</FL>
              <OptGrid>
                {d.relations.relations.map(o => (
                  <OptCard key={o.value} opt={o} selected={form.relations.includes(o.value)} onToggle={() => toggleMulti('relations', o.value)} />
                ))}
              </OptGrid>
              <div className="info-box">
                <div className="info-box-title">OpenFGA / Zanzibar Tuple Model</div>
                These relations define the ReBAC check pattern:<br />
                <code>CHECK: subject:&#123;who.id&#125; &lt;relation&gt; object:&#123;what.resource&#125;</code><br />
                Zanzibar zookies and changefeed consistency checks are applied at runtime evaluation.
              </div>
            </div>
          )}

          {/* ISSUED — Signed JSON */}
          {activeDim === 'issued' && (
            <div className="dim-section">
              <SectionHead glyph="✦" label="SIGNED JSON — Cryptographic Permit" sub="This is the signed permit document. Copy it, download it, or click VERIFY to check the signature." />
              {!signedPermit && (
                <div className="no-permit-msg">◈ No permit issued yet — fill the form and click SIGN &amp; ISSUE PERMIT</div>
              )}
              {signedPermit && (
                <>
                  <div className="issued-meta-grid">
                    {[
                      ['ALGORITHM', signedPermit.header.alg],
                      ['KEY ID',    signedPermit.key_id],
                      ['DOC TYPE',  signedPermit.header.doc_type],
                      ['ISSUER',    signedPermit.header.issuer],
                      ['ISSUED',    new Date(signedPermit.header.issued_at).toLocaleString()],
                      ['EXPIRES',   signedPermit.header.expires_at ? new Date(signedPermit.header.expires_at).toLocaleString() : '—'],
                      ['VERSION',   signedPermit.header.ver],
                      ['DIGEST',    signedPermit.digest],
                    ].map(([k, v]) => (
                      <div key={k} className="issued-meta-field">
                        <div className="issued-meta-key">{k}</div>
                        <div className="issued-meta-val">{v}</div>
                      </div>
                    ))}
                  </div>
                  <div className="issued-sig-block">
                    <div className="issued-sig-block-label">✓ {signedPermit.header.alg} SIGNATURE</div>
                    <div className="issued-sig-block-val">{signedPermit.sig}</div>
                  </div>
                  <div className="issued-action-row">
                    <button className="crt-btn crt-btn--primary" onClick={() => copy(JSON.stringify(signedPermit, null, 2))}>◈ COPY SIGNED JSON</button>
                    <button className="crt-btn" onClick={() => download(JSON.stringify(signedPermit, null, 2), `${form.permitId || 'permit'}.permit.json`)}>⬇ DOWNLOAD .permit.json</button>
                    <button className="crt-btn" onClick={() => { setVerifyInput(JSON.stringify(signedPermit, null, 2)); setActiveDim('verify') }}>◍ VERIFY THIS PERMIT</button>
                  </div>
                  <div className="issued-json-label">── FULL SIGNED DOCUMENT ──</div>
                  <pre className="issued-json-full">{JSON.stringify(signedPermit, null, 2)}</pre>
                </>
              )}
            </div>
          )}

          {/* VERIFY */}
          {activeDim === 'verify' && (
            <div className="dim-section">
              <SectionHead glyph="◍" label="VERIFY — Signature Verification" sub='Paste a signed permit JSON to verify its Ed25519 cryptographic signature.' />
              <FL>SIGNED PERMIT JSON</FL>
              <textarea
                className="crt-textarea"
                value={verifyInput}
                onChange={e => setVerifyInput(e.target.value)}
                placeholder={'{\n  "header": { "alg": "Ed25519", ... },\n  "payload": { ... },\n  "digest": "abc123...",\n  "sig": "base64...",\n  "key_id": "..."\n}'}
                spellCheck={false}
              />
              <div className="verify-btn-row">
                <button className="crt-btn crt-btn--primary" onClick={handleVerify} disabled={verifying}>
                  {verifying ? '◷ VERIFYING…' : '◍ VERIFY SIGNATURE'}
                </button>
                {signedPermit && (
                  <button className="crt-btn crt-btn--primary" onClick={() => {
                    setVerifyInput(JSON.stringify(signedPermit, null, 2))
                    notify('Loaded last issued permit', 'ok')
                  }}>
                    ◈ LOAD LAST ISSUED PERMIT
                  </button>
                )}
                <button className="crt-btn" onClick={async () => {
                  try {
                    const text = await navigator.clipboard.readText()
                    if (text.trim().startsWith('{')) { setVerifyInput(text); notify('Pasted from clipboard', 'ok') }
                    else { notify('Clipboard does not contain JSON', 'err') }
                  } catch { notify('Clipboard access denied', 'err') }
                }}>
                  ◈ PASTE JSON FROM CLIPBOARD
                </button>
                <button className="crt-btn" onClick={() => { setVerifyInput(''); setVerifyResult(null) }}>✕ CLEAR</button>
              </div>
              {verifyResult && (
                <div className={`verify-result verify-result--${verifyResult.valid ? 'ok' : 'err'}`}>
                  <div className="verify-verdict">{verifyResult.valid ? '◈ SIGNATURE VALID — PERMIT AUTHENTIC' : '⚠ SIGNATURE INVALID — PERMIT REJECTED'}</div>
                  {verifyResult.reason && <div className="verify-reason">REASON: {verifyResult.reason}</div>}
                  {verifyResult.valid && (
                    <div className="verify-fields">
                      {verifyResult.key_id    && <div>KEY_ID   : {verifyResult.key_id}</div>}
                      {verifyResult.alg       && <div>ALG      : {verifyResult.alg}</div>}
                      {verifyResult.issued_at && <div>ISSUED   : {new Date(verifyResult.issued_at).toLocaleString()}</div>}
                      {verifyResult.expires_at && <div>EXPIRES  : {new Date(verifyResult.expires_at).toLocaleString()}</div>}
                      {verifyResult.permit?.permit_id  && <div>PERMIT   : {verifyResult.permit.permit_id}</div>}
                      {verifyResult.permit?.who?.type  && <div>WHO.TYPE : {verifyResult.permit.who.type}</div>}
                      {verifyResult.permit?.why?.purpose && <div>PURPOSE  : {verifyResult.permit.why.purpose}</div>}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </main>

        {/* ── Right Panel ── */}
        <aside className="right-panel">
          {/* Risk meter */}
          <div className="risk-box">
            <div className="risk-header">── RISK ASSESSMENT ──</div>
            <div className="risk-bar-bg">
              <div className="risk-bar-fill" style={{ width: `${riskScore}%`, background: rc, boxShadow: `0 0 8px ${rc}80` }} />
            </div>
            <div className="risk-row">
              <span className="risk-min">MINIMAL</span>
              <span className="risk-score" style={{ color: rc, textShadow: `0 0 12px ${rc}80` }}>{riskScore}%</span>
              <span className="risk-max">CRITICAL</span>
            </div>
            <div className="risk-label-big" style={{ color: rc, textShadow: `0 0 10px ${rc}60` }}>{rl}</div>
          </div>

          {/* Summary */}
          <div className="summary-box">
            <div className="summary-header">── PERMIT SUMMARY ──</div>
            {([
              ['WHO',       [form.whoType, ...form.whoGroups].filter(Boolean)],
              ['TTL',       form.whenTTL ? [form.whenTTL] : []],
              ['CLUSTERS',  form.whereClusters],
              ['NAMESPACES',form.whereNamespaces],
              ['RESOURCES', form.whatResources],
              ['VERBS',     form.howVerbs],
              ['PURPOSE',   form.whyPurpose ? [form.whyPurpose] : []],
              ['RELATIONS', form.relations],
            ] as [string, string[]][]).map(([k, vals]) => (
              <div key={k} className="summary-row">
                <div className="summary-key">{k}</div>
                <div className="summary-vals">
                  {vals.length === 0
                    ? <span className="summary-empty">—</span>
                    : vals.map(v => <span key={v} className="summary-tag">{v}</span>)
                  }
                </div>
              </div>
            ))}
          </div>

          {/* Actions */}
          <div className="action-box">
            <button
              className={`crt-btn crt-btn--primary crt-btn--full${issuing ? ' crt-btn--busy' : ''}`}
              onClick={handleIssue}
              disabled={issuing || tmplState === 'loading'}
            >
              {issuing ? '◷ SIGNING…' : '◈ SIGN & ISSUE PERMIT'}
            </button>
            <button
              className="crt-btn crt-btn--full crt-btn--ghost"
              onClick={() => { setForm(makeDefaultForm()); notify('Form cleared', 'info') }}
            >
              ↺ CLEAR ALL
            </button>
          </div>

        </aside>
      </div>

      {/* ── Signed Permit Modal ── */}
      {showModal && signedPermit && (
        <div className="modal-overlay" onClick={e => e.target === e.currentTarget && setShowModal(false)}>
          <div className="modal">
            <div className="modal-header">
              <div>
                <div className="modal-title">◈ PERMIT ISSUED & CRYPTOGRAPHICALLY SIGNED</div>
                <div className="modal-sub">
                  PERMIT_ID: {form.permitId} · ALG: {signedPermit.header.alg} · KEY: {signedPermit.key_id}
                </div>
              </div>
              <button className="modal-close" onClick={() => setShowModal(false)}>✕ CLOSE</button>
            </div>
            <div className="modal-body">
              <div className="modal-grid4">
                {([
                  ['ALGORITHM', signedPermit.header.alg],
                  ['KEY ID',    signedPermit.key_id],
                  ['ISSUED',    new Date(signedPermit.header.issued_at).toLocaleString()],
                  ['EXPIRES',   signedPermit.header.expires_at ? new Date(signedPermit.header.expires_at).toLocaleString() : '—'],
                  ['DOC TYPE',  signedPermit.header.doc_type],
                  ['ISSUER',    signedPermit.header.issuer],
                  ['DIGEST',    signedPermit.digest.slice(0, 24) + '…'],
                  ['VERSION',   signedPermit.header.ver],
                ] as [string,string][]).map(([k,v]) => (
                  <div key={k} className="modal-field">
                    <div className="modal-field-key">{k}</div>
                    <div className="modal-field-val">{v}</div>
                  </div>
                ))}
              </div>

              <div className="sig-box">
                <div className="sig-label">✓ {signedPermit.header.alg} SIGNATURE</div>
                <div className="sig-val">{signedPermit.sig}</div>
              </div>

              <div className="modal-section-label">FULL SIGNED DOCUMENT</div>
              <pre className="code-block">{JSON.stringify(signedPermit, null, 2)}</pre>

              <div className="modal-btn-row">
                <button className="crt-btn crt-btn--primary" onClick={() => copy(JSON.stringify(signedPermit, null, 2))}>
                  ◈ COPY JSON
                </button>
                <button className="crt-btn" onClick={() => download(JSON.stringify(signedPermit, null, 2), `${form.permitId}.permit.json`)}>
                  ⬇ DOWNLOAD .JSON
                </button>
                <button className="crt-btn" onClick={() => { setVerifyInput(JSON.stringify(signedPermit, null, 2)); setShowModal(false); setActiveDim('verify') }}>
                  ◍ VERIFY THIS PERMIT
                </button>
                <button className="crt-btn" onClick={() => setShowModal(false)}>✕ CLOSE</button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── Toast ── */}
      {toast && (
        <div className={`toast toast--${toast.type}`}>
          {toast.type === 'ok' ? '✓ ' : toast.type === 'err' ? '⚠ ' : '◈ '}{toast.msg}
        </div>
      )}
    </div>
  )
}
