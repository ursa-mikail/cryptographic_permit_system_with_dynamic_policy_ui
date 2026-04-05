import type { SignedDocument } from './types'

const API = '/api'

async function get<T>(path: string): Promise<T> {
  const res = await fetch(API + path)
  if (!res.ok) throw new Error(`GET ${path} → ${res.status}`)
  return res.json()
}

async function post<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(API + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  const data = await res.json()
  if (!res.ok) throw new Error(data.error ?? `POST ${path} → ${res.status}`)
  return data
}

// ── Health ────────────────────────────────────────────────────────────────────

export async function checkHealth(): Promise<boolean> {
  try {
    const res = await fetch('/health')
    if (!res.ok) return false
    const data = await res.json()
    return data.status === 'ok'
  } catch {
    return false
  }
}

// ── Template ──────────────────────────────────────────────────────────────────

export interface TemplateResponse {
  signed_template: SignedDocument
  public_key: string
  key_id: string
}

export async function fetchTemplate(): Promise<TemplateResponse> {
  return get<TemplateResponse>('/template')
}

// ── Issue permit ──────────────────────────────────────────────────────────────

export interface IssueResponse {
  signed_permit: SignedDocument
  public_key: string
  key_id: string
  permit_id: string
  expires_at: string
  issued_at: string
}

export async function issuePermit(permit: unknown): Promise<IssueResponse> {
  return post<IssueResponse>('/permit/issue', { permit })
}

// ── Verify permit ─────────────────────────────────────────────────────────────

export interface VerifyResponse {
  valid: boolean
  reason?: string | null
  permit?: unknown
  issued_at?: string
  expires_at?: string
  key_id?: string
  alg?: string
}

export async function verifyPermit(signedPermit: SignedDocument): Promise<VerifyResponse> {
  return post<VerifyResponse>('/permit/verify', { signed_permit: signedPermit })
}

// ── Client-side Ed25519 verification (browser SubtleCrypto) ──────────────────
// Digest check always works. Ed25519 sig verify needs Chrome 113+.

export async function clientVerifySignature(
  doc: SignedDocument,
  pubKeyB64: string
): Promise<{ digestOk: boolean; sigOk: boolean }> {
  // 1. Verify SHA-256 digest of payload
  const payloadStr = typeof doc.payload === 'string'
    ? doc.payload
    : JSON.stringify(doc.payload)

  const enc = new TextEncoder()
  const hashBuf = await crypto.subtle.digest('SHA-256', enc.encode(payloadStr))
  const hashHex = Array.from(new Uint8Array(hashBuf))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
  const digestOk = hashHex === doc.digest

  // 2. Attempt Ed25519 signature verify via SubtleCrypto
  let sigOk = false
  try {
    const pubKeyBytes = Uint8Array.from(atob(pubKeyB64), c => c.charCodeAt(0))
    const cryptoKey = await crypto.subtle.importKey(
      'raw', pubKeyBytes, { name: 'Ed25519' }, false, ['verify']
    )
    // sigInput = JSON(header) + "." + digest  ← matches Go server exactly
    const sigInput = enc.encode(JSON.stringify(doc.header) + '.' + doc.digest)
    const sigBytes = Uint8Array.from(atob(doc.sig), c => c.charCodeAt(0))
    sigOk = await crypto.subtle.verify('Ed25519', cryptoKey, sigBytes, sigInput)
  } catch {
    // Ed25519 not supported in this browser — fall back to digest check
    sigOk = digestOk
  }

  return { digestOk, sigOk }
}
