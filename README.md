# PERMIT.AUTHORITY

Cryptographic access permit issuance system — Ed25519 signed permits, dynamic policy UI.

## Quick Start

```bash
# 1. Unzip
unzip permit-authority.zip
cd permit-forge

# 2. IMPORTANT — clear Docker cache first (fixes any stale build issues)
docker builder prune -af

# 3. Start
./start.sh
```

Open **http://localhost:3000**

```bash
./stop.sh    # stop
./clean.sh   # stop + wipe images + free ports
```

## How to get your signed JSON

1. Fill in the form (WHO → WHEN → WHERE → WHAT → HOW → WHY)
2. Click **◈ SIGN & ISSUE PERMIT** in the right sidebar
3. The UI automatically switches to the **✦ SIGNED JSON** tab
4. The full signed permit document is displayed — you can:
   - **◈ COPY SIGNED JSON** — copies to clipboard
   - **⬇ DOWNLOAD .permit.json** — saves as file
   - **◍ VERIFY THIS PERMIT** — loads into Verify tab and checks signature

## To verify a permit

- Go to the **◍ VERIFY** tab
- Click **◈ LOAD LAST ISSUED PERMIT** (if you just issued one), OR paste JSON manually
- Click **◍ VERIFY SIGNATURE**

## Architecture

```
Frontend (React/TypeScript)  :3000   nginx → /api/* proxy
Backend  (Go, stdlib only)   :8080   Ed25519 key gen + signing
```

### API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | /health | Health check |
| GET | /api/pubkey | Public key (base64) |
| GET | /api/template | Signed gold-standard template |
| POST | /api/permit/issue | Issue a signed permit |
| POST | /api/permit/verify | Verify a signed permit |

### Signed Document Format

```json
{
  "header": {
    "alg": "Ed25519",
    "ver": "1.0",
    "doc_type": "permit",
    "issuer": "permit-authority/key/<key_id>",
    "issued_at": "2025-01-01T00:00:00Z",
    "expires_at": "2025-01-02T00:00:00Z"
  },
  "payload": { ...permit fields... },
  "digest": "<sha256hex of payload>",
  "sig": "<base64 Ed25519 signature>",
  "key_id": "<hex>"
}
```

### Offline Verification

```bash
# Get public key
curl http://localhost:8080/api/pubkey | jq -r .public_key | base64 -d > pub.key

# The signature covers: JSON(header) + "." + sha256hex(payload)
```
