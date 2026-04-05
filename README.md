# PERMIT.AUTHORITY

**Cryptographic Access Permit Issuance System** — Ed25519 signed permits covering every dimension of modern access control, unified from OPA/Rego, OpenFGA, Zanzibar, X.509/SPIFFE, Kubernetes RBAC, Terraform, and more.

---

## Quick Start

```bash
unzip permit-authority.zip
cd permit-forge

# Clear Docker build cache (required on first run / after updates)
docker builder prune -af

./start.sh          # builds, starts, waits for health
# → http://localhost:3000

./stop.sh           # stop
./clean.sh          # stop + remove images + free ports
```

---

## Getting a Signed Permit

### Manual
1. Fill each tab: **METADATA → WHO → WHEN → WHERE → WHAT → HOW → WHY → HOW MANY → RELATIONS**
2. Click **◈ SIGN & ISSUE PERMIT** in the right sidebar
3. UI auto-jumps to **✦ SIGNED JSON** tab — the complete signed permit is shown

### Demo / Random
Click **⚄ RANDOMIZE (DEMO)** — fills all text fields and selects options using a timestamp seed, writing realistic permit IDs (`PA-018F-A3B2`), ticket numbers (`INC-042891`), SPIFFE URIs, and justifications. Then click **◈ SIGN & ISSUE PERMIT**.

### Downloading the Signed JSON
From the **✦ SIGNED JSON** tab:
- **◈ COPY SIGNED JSON** — copies full document to clipboard
- **⬇ DOWNLOAD .permit.json** — downloads the file
- **◍ VERIFY THIS PERMIT** — loads into Verify tab and checks the Ed25519 signature

---

## How It Covers Every Policy Model

This system unifies **eight policy dimensions** drawn from the world's major access control frameworks. Every signed permit encodes all eight dimensions in a single cryptographically bound document.

---

### Dimension 1 — WHO (Identity & Authentication)
*OPA subject claims · X.509 CN/SAN · SPIFFE SVID · OIDC JWT · K8s ServiceAccount · AWS IAM*

| Field | Encodes |
|-------|---------|
| `who.type` | Principal category: `service`, `user`, `node`, `pipeline`, `external`, `operator` |
| `who.auth_method` | Trust mechanism: `x509_mtls`, `spiffe`, `jwt_oidc`, `aws_iam`, `k8s_sa_token`, `github_oidc` |
| `who.trust_level` | Assurance level: `hardware_attested` (TPM), `high` (mTLS+MFA), `medium` (OIDC+MFA), `low` |
| `who.groups` | RBAC groups: `auditors`, `devops`, `sre`, `security`, `emergency-admin` |
| `who.spiffe_pattern` | SPIFFE URI: `spiffe://cluster.local/ns/finance/sa/audit-svc` |

**OPA/Rego:**
```rego
allow {
  input.who.auth_method == "x509_mtls"
  input.who.trust_level == "high"
  input.who.groups[_] == "auditors"
  time.now_ns() < time.parse_rfc3339_ns(input.who.x509_not_after)
}
```

**X.509 mapping:** `who.auth_method = x509_mtls` + `who.spiffe_pattern` maps to the X.509 Subject Alternative Name `URI:spiffe://...` validated during the mTLS handshake. `who.trust_level = hardware_attested` requires a TPM-backed key.

---

### Dimension 2 — WHEN (Temporal Bounds)
*X.509 notBefore/notAfter · JWT exp/nbf · OPA time() · Zanzibar TTL conditions*

| Field | Encodes |
|-------|---------|
| `when.ttl` | Lifetime: `1h`, `4h`, `8h`, `24h`, `7d`, `30d`, `90d`, `365d` |
| `when.time_window` | Allowed hours: `business_hours` (09:00–17:00), `extended_hours`, `always`, `maintenance` |
| `when.allowed_days` | `weekdays`, `mon_to_sat`, `all_days` |
| `when.timezone` | Window timezone: `UTC`, `America/New_York`, `Asia/Singapore`, `Europe/London` |

The backend sets `header.expires_at = issued_at + ttl`. Verify checks this before returning valid.

**OPA/Rego:**
```rego
allow {
  now := time.now_ns()
  now >= time.parse_rfc3339_ns(input.when.not_before)
  now <= time.parse_rfc3339_ns(input.when.expires_at)
  hour := time.clock([now])[0]
  hour >= 9; hour < 17       # business_hours window
  day  := time.weekday(now)
  day  >= 1; day <= 5        # weekdays only
}
```

**X.509 mapping:** `when.ttl` → `notAfter` on the issued certificate or SPIFFE SVID.

---

### Dimension 3 — WHERE (Scope & Location)
*K8s namespace/node scoping · Network CIDR policies · Geo-fencing · Environment labels*

| Field | Encodes |
|-------|---------|
| `where.clusters` | K8s clusters: `prod-us-east1`, `prod-eu-west1`, `prod-ap-southeast1`, `staging`, `dev` |
| `where.namespaces` | K8s namespaces: `finance`, `auth-system`, `data-platform`, `kube-system` |
| `where.nodes` | Node pools: `finance-nodes`, `control-plane`, `gpu-nodes`, `general-nodes` |
| `where.ip_ranges` | Source CIDRs: `10.0.0.0/8`, `172.16.0.0/12`, `vpn-egress`, `office-cidrs` |
| `where.geo_regions` | Regions: `US`, `EU` (GDPR zone), `APAC`, `domestic-only` |
| `where.environments` | `production`, `staging`, `development`, `dr` |

**K8s RBAC mapping:** `where.namespaces` scopes a generated `RoleBinding`. `where.nodes` maps to a `NodeSelector` or `nodeAffinity` in a pod security policy.

**Terraform:**
```hcl
resource "kubernetes_role_binding" "permit" {
  metadata { namespace = permit.where.namespaces[0] }
  subject  { name = permit.who.spiffe_pattern }
  role_ref { name = "permit-${permit.permit_id}" }
}
```

**OPA/Rego:**
```rego
allow {
  input.where.clusters[_] == "prod-us-east1"
  net.cidr_contains("10.0.0.0/8", input.source_ip)
  input.where.environments[_] != "production"  # dev/staging only
}
```

---

### Dimension 4 — WHAT (Resources & Classification)
*AWS IAM resource ARNs · K8s resource types · Vault paths · Data classification labels · Kafka topics*

| Field | Encodes |
|-------|---------|
| `what.resource_types` | `s3:object`, `k8s:secret`, `k8s:pod`, `k8s:deployment`, `k8s:rbac`, `db:table`, `db:schema`, `vault:secret`, `iam:role`, `kafka:topic`, `network:policy`, `api:endpoint` |
| `what.apis` | Named services: `finance-api`, `payment-api`, `admin-api`, `audit-api`, `data-api` |
| `what.classification` | Sensitivity: `public`, `internal`, `confidential`, `pii`, `restricted`, `secret` |
| `what.resource_namespaces` | Namespace scope for the target resource |

**Data governance:** `what.classification = pii` triggers GDPR controls — only permits with `why.purpose = gdpr_request` or `audit` can target PII resources, enforced in OPA:
```rego
deny {
  input.what.classification == "pii"
  not input.why.purpose == "gdpr_request"
  not input.why.purpose == "audit"
}
```

**Vault mapping:** `what.resource_types = ["vault:secret"]` with `where.namespaces = ["finance"]` generates a Vault policy:
```hcl
path "secret/data/finance/*" { capabilities = ["read"] }
```

---

### Dimension 5 — HOW (Actions & Protocol)
*K8s RBAC verbs · HTTP methods · SQL operations · gRPC methods · Encryption requirements*

| Field | Encodes |
|-------|---------|
| `how.verbs` | `get`, `list`, `watch`, `create`, `update`, `patch`, `delete`, `exec`, `escalate`, `impersonate` |
| `how.protocol` | `https`, `grpc_tls`, `mtls`, `sql_tls`, `kafka_sasl`, `ssh` |
| `how.encryption` | `tls13_required`, `tls12_min`, `mtls_required`, `e2e_encrypted`, `none` |

**K8s RBAC mapping:** `how.verbs` maps 1:1 to Kubernetes PolicyRule verbs:
```yaml
rules:
- apiGroups: [""]
  resources: ["secrets"]    # ← from what.resource_types
  verbs: ["get", "list"]    # ← from how.verbs
```

**Risk escalation:** `how.verbs` containing `exec`, `escalate`, or `impersonate` are flagged `critical` risk and require `who.trust_level = hardware_attested` and `why.break_glass = true`.

---

### Dimension 6 — WHY (Purpose & Consent)
*GDPR lawful basis · SOC2 audit requirements · Break-glass protocols · ITSM ticket linkage*

| Field | Encodes |
|-------|---------|
| `why.purpose` | `audit`, `operations`, `incident_response`, `data_migration`, `development`, `analytics`, `gdpr_request`, `break_glass` |
| `why.justification` | Free-text rationale — cryptographically bound to the permit |
| `why.ticket_id` | ITSM/JIRA reference: `INC-042`, `JIRA-1234` |
| `why.require_justification` | Template-enforced: justification is mandatory for all permits |
| `why.break_glass` | Emergency override flag — triggers maximum audit logging and alerts |

**GDPR Article 6 mapping:** `why.purpose = gdpr_request` declares lawful basis as *legal obligation* (Art. 6(1)(c)). The Ed25519-signed permit is cryptographic proof of the processing decision, satisfying Art. 5(2) accountability principle.

**Non-repudiation:** The `why.justification` text is embedded in the signed payload. Tampering with the justification after signing invalidates the Ed25519 signature — creating an immutable audit record of *why* access was granted.

---

### Dimension 7 — HOW MANY (Quotas & Rate Limits)
*API gateway throttling · Zanzibar token buckets · OPA cardinality limits*

| Field | Encodes |
|-------|---------|
| `how_many.rate_limit` | Requests per minute: `10/min`, `100/min`, `1000/min`, `10000/min`, `unlimited` |
| `how_many.max_results` | Max rows/objects per response: `50`, `500`, `1000`, `10000`, `unlimited` |
| `how_many.burst_limit` | Burst allowance: `5`, `20`, `100`, `500`, `unlimited` |

**Zanzibar mapping:** Zanzibar uses *zookies* for consistency tokens. The `how_many` limits map to per-client quota enforcement at the Zanzibar Check endpoint, preventing enumeration attacks.

**OPA/Rego:**
```rego
allow {
  count_requests_last_minute(input.who.id) < 100
  input.how_many.max_results <= 500
  not data.quota_exceeded[input.who.id]
}
```

---

### Dimension 8 — RELATIONS (Relationship-Based Access Control)
*Google Zanzibar · OpenFGA · ReBAC*

| Field | Encodes |
|-------|---------|
| `relations.allowed_relations` | Relation types: `viewer`, `editor`, `owner`, `member`, `admin`, `auditor`, `parent` |

**OpenFGA tuple:** A permit with `relations = ["viewer"]` on `what.resource_types = ["k8s:secret"]` generates:
```
tuple_key:
  user: "service:spiffe://cluster.local/ns/finance/sa/audit"
  relation: "viewer"
  object: "k8s_secret:finance/*"
```

**Zanzibar namespace config:**
```
name: "k8s_secret"
relation { name: "viewer" }
relation { name: "editor"
  userset_rewrite {
    union {
      child { computed_userset { relation: "viewer" } }
      child { this {} }
    }
  }
}
```

**Inheritance:** `parent` relation enables Zanzibar-style namespace inheritance — a `viewer` on a parent bucket implicitly gets `viewer` on all child objects.

---

## Cryptographic Permit Format

Signed with **Ed25519** — 64-byte signatures, no nonce, constant-time verify, no padding oracle attacks.

```json
{
  "header": {
    "alg":        "Ed25519",
    "ver":        "1.0",
    "doc_type":   "permit",
    "issuer":     "permit-authority/key/<key_id>",
    "issued_at":  "2025-06-01T10:00:00Z",
    "expires_at": "2025-06-02T10:00:00Z"
  },
  "payload": {
    "permit_id":   "PA-018F-A3B2",
    "who":   { "type": "service", "auth_method": "x509_mtls", "trust_level": "high", "groups": ["auditors"], "spiffe_pattern": "spiffe://cluster.local/ns/finance/sa/audit" },
    "when":  { "ttl": "8h", "time_window": "business_hours", "allowed_days": "weekdays", "timezone": "UTC" },
    "where": { "clusters": ["prod-us-east1"], "namespaces": ["finance"], "ip_ranges": ["10.0.0.0/8"], "environments": ["production"] },
    "what":  { "resource_types": ["k8s:secret", "db:table"], "classification": "confidential" },
    "how":   { "verbs": ["get","list"], "protocol": "mtls", "encryption": "tls13_required" },
    "why":   { "purpose": "audit", "justification": "Q4 SOC2 audit per CTRL-42", "ticket_id": "INC-042" },
    "how_many":  { "rate_limit": "100/min", "max_results": "500", "burst_limit": "20" },
    "relations": { "allowed_relations": ["viewer"] }
  },
  "digest": "<sha256hex(JSON(payload))>",
  "sig":    "<base64(Ed25519Sign(JSON(header) + '.' + digest))>",
  "key_id": "<sha256hex(public_key)[:12]>"
}
```

**Verification steps:**
1. `SHA-256(payload_json)` must equal `digest`
2. `Ed25519.Verify(pubkey, JSON(header) + "." + digest, base64decode(sig))` must be true
3. `header.expires_at > now()`

**Offline verification:**
```bash
# Get the public key
curl http://localhost:8080/api/pubkey | jq -r .public_key | base64 -d > pub.key

# Extract and check digest
PAYLOAD=$(cat permit.json | jq -c .payload)
DIGEST=$(echo -n "$PAYLOAD" | sha256sum | cut -d' ' -f1)
echo "Expected: $(cat permit.json | jq -r .digest)"
echo "Computed: $DIGEST"

# Verify Ed25519 signature (sigInput = JSON(header) + "." + digest)
HEADER=$(cat permit.json | jq -c .header)
SIG=$(cat permit.json | jq -r .sig | base64 -d > /tmp/permit.sig && echo /tmp/permit.sig)
printf '%s.%s' "$HEADER" "$DIGEST" > /tmp/siginput
openssl pkeyutl -verify -pubin -inkey pub.key -sigfile /tmp/permit.sig -in /tmp/siginput
```

---

## Policy Engine Cross-Reference

| Dimension | OPA/Rego | OpenFGA/Zanzibar | X.509/SPIFFE | K8s RBAC | Terraform |
|-----------|----------|-----------------|--------------|----------|-----------|
| WHO | `input.principal` | `tuple.user` | CN / SAN URI | `subjects[].name` | `var.principal` |
| WHEN | `time.now_ns()` | condition TTL | notAfter | annotation | `duration` |
| WHERE | `input.namespace` | object namespace | N/A | `metadata.namespace` | `namespace` block |
| WHAT | `input.resource` | object type+id | N/A | `resources[]` | `resource` block |
| HOW | `input.action` | relation name | N/A | `verbs[]` | `actions[]` |
| WHY | custom data claim | condition context | OID extension | audit annotation | tag / label |
| HOW MANY | `count(...)` check | quota enforcement | N/A | ResourceQuota | `quota` resource |
| RELATIONS | ReBAC rule | tuple relation | N/A | ClusterRole ref | IAM binding |

---

## API Reference

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check + key ID |
| `GET` | `/api/pubkey` | Ed25519 public key (base64) |
| `GET` | `/api/template` | Signed gold-standard template |
| `POST` | `/api/permit/issue` | Issue a signed permit |
| `POST` | `/api/permit/verify` | Verify a permit (sig + expiry) |

---

## Architecture

```
┌────────────────────────────────────────────────────┐
│  React + TypeScript  (nginx proxy :3000)            │
│                                                    │
│  Gold-standard template (fetched, sig-verified)    │
│  9 policy dimension tabs — checkboxes + selects    │
│  ⚄ Timestamp-seeded random demo fill               │
│  ✦ SIGNED JSON tab — copy / ⬇ download             │
│  ◍ Verify — Ed25519 client-side + server check     │
└────────────────────┬───────────────────────────────┘
                     │  /api/* nginx proxy
┌────────────────────▼───────────────────────────────┐
│  Go 1.22 (stdlib only)  :8080                       │
│  Ed25519 keygen · template sign · permit sign       │
│  Verify endpoint · health check                     │
└────────────────────────────────────────────────────┘
```
