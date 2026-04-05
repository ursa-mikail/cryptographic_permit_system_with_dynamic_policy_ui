package crypto

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// KeyPair holds an Ed25519 key pair
type KeyPair struct {
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
	KeyID      string
	CreatedAt  time.Time
}

// SignedDocument is the canonical signed envelope
type SignedDocument struct {
	Header  DocHeader       `json:"header"`
	Payload json.RawMessage `json:"payload"`
	Digest  string          `json:"digest"`
	Sig     string          `json:"sig"`
	KeyID   string          `json:"key_id"`
}

// DocHeader identifies document type, algorithm, and validity window
type DocHeader struct {
	Alg       string    `json:"alg"`
	Ver       string    `json:"ver"`
	DocType   string    `json:"doc_type"`
	Issuer    string    `json:"issuer"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

// GenerateKeyPair creates a fresh Ed25519 key pair
func GenerateKeyPair() (*KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	h := sha256.Sum256(pub)
	kid := hex.EncodeToString(h[:6])
	return &KeyPair{
		PublicKey:  pub,
		PrivateKey: priv,
		KeyID:      kid,
		CreatedAt:  time.Now().UTC(),
	}, nil
}

// Sign signs any JSON-serialisable payload
func (kp *KeyPair) Sign(payload any, docType string, ttl time.Duration) (*SignedDocument, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}

	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])

	now := time.Now().UTC()
	hdr := DocHeader{
		Alg:      "Ed25519",
		Ver:      "1.0",
		DocType:  docType,
		Issuer:   fmt.Sprintf("permit-authority/key/%s", kp.KeyID),
		IssuedAt: now,
	}
	if ttl > 0 {
		hdr.ExpiresAt = now.Add(ttl)
	}

	hdrRaw, _ := json.Marshal(hdr)
	// sigInput = header_json + "." + sha256_hex(payload)
	sigInput := append(append(hdrRaw, '.'), []byte(digest)...)

	sig, err := kp.PrivateKey.Sign(rand.Reader, sigInput, crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}

	return &SignedDocument{
		Header:  hdr,
		Payload: raw,
		Digest:  digest,
		Sig:     base64.StdEncoding.EncodeToString(sig),
		KeyID:   kp.KeyID,
	}, nil
}

// Verify verifies a SignedDocument against a public key
func Verify(doc *SignedDocument, pub ed25519.PublicKey) error {
	sum := sha256.Sum256(doc.Payload)
	if hex.EncodeToString(sum[:]) != doc.Digest {
		return fmt.Errorf("payload digest mismatch — document may be tampered")
	}

	hdrRaw, err := json.Marshal(doc.Header)
	if err != nil {
		return fmt.Errorf("re-marshal header: %w", err)
	}
	sigInput := append(append(hdrRaw, '.'), []byte(doc.Digest)...)

	sigBytes, err := base64.StdEncoding.DecodeString(doc.Sig)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}

	if !ed25519.Verify(pub, sigInput, sigBytes) {
		return fmt.Errorf("Ed25519 signature invalid")
	}

	if !doc.Header.ExpiresAt.IsZero() && time.Now().UTC().After(doc.Header.ExpiresAt) {
		return fmt.Errorf("document expired at %s", doc.Header.ExpiresAt.Format(time.RFC3339))
	}
	return nil
}

// PublicKeyB64 returns base64-encoded public key for wire transport
func (kp *KeyPair) PublicKeyB64() string {
	return base64.StdEncoding.EncodeToString(kp.PublicKey)
}
