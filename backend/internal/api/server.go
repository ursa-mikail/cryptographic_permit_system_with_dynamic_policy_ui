package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	cry "permit-authority/internal/crypto"
	"permit-authority/internal/permit"
	tmpl "permit-authority/internal/template"
)

// Server holds all server state
type Server struct {
	mux        *http.ServeMux
	keyPair    *cry.KeyPair
	signedTmpl *cry.SignedDocument
}

func NewServer() *Server {
	kp, err := cry.GenerateKeyPair()
	if err != nil {
		log.Fatalf("FATAL: generate key pair: %v", err)
	}
	log.Printf("[BOOT] Ed25519 key pair generated  key_id=%s", kp.KeyID)

	gs := tmpl.GoldStandard()
	signed, err := kp.Sign(gs, "template", 365*24*time.Hour)
	if err != nil {
		log.Fatalf("FATAL: sign gold standard template: %v", err)
	}
	log.Printf("[BOOT] Gold standard template signed  key_id=%s  digest=%s…", kp.KeyID, signed.Digest[:16])

	s := &Server{mux: http.NewServeMux(), keyPair: kp, signedTmpl: signed}
	s.routes()
	return s
}

func (s *Server) routes() {
	s.mux.HandleFunc("/health", s.handleHealth)
	s.mux.HandleFunc("/api/pubkey", s.handlePubKey)
	s.mux.HandleFunc("/api/template", s.handleTemplate)
	s.mux.HandleFunc("/api/permit/issue", s.handleIssuePermit)
	s.mux.HandleFunc("/api/permit/verify", s.handleVerifyPermit)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	log.Printf("[REQ] %s %s", r.Method, r.URL.Path)
	s.mux.ServeHTTP(w, r)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"status": "ok", "key_id": s.keyPair.KeyID, "time": time.Now().UTC(),
	})
}

func (s *Server) handlePubKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, 405, "GET only")
		return
	}
	writeJSON(w, 200, map[string]any{
		"algorithm":  "Ed25519",
		"key_id":     s.keyPair.KeyID,
		"public_key": s.keyPair.PublicKeyB64(),
		"created_at": s.keyPair.CreatedAt,
	})
}

func (s *Server) handleTemplate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, 405, "GET only")
		return
	}
	writeJSON(w, 200, map[string]any{
		"signed_template": s.signedTmpl,
		"public_key":      s.keyPair.PublicKeyB64(),
		"key_id":          s.keyPair.KeyID,
	})
}

type issueReq struct {
	Permit permit.AccessPermit `json:"permit"`
}

func (s *Server) handleIssuePermit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, 405, "POST only")
		return
	}
	var req issueReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, 400, "invalid JSON: "+err.Error())
		return
	}
	p := req.Permit
	if p.PermitID == "" {
		writeError(w, 400, "permit_id required")
		return
	}
	if p.Who.Type == "" {
		writeError(w, 400, "who.type required")
		return
	}
	if len(p.How.Verbs) == 0 {
		writeError(w, 400, "how.verbs must not be empty")
		return
	}
	if p.Why.Purpose == "" {
		writeError(w, 400, "why.purpose required")
		return
	}
	if p.When.TTL == "" {
		writeError(w, 400, "when.ttl required")
		return
	}
	ttl, err := parseTTL(p.When.TTL)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}

	now := time.Now().UTC()
	p.IssuedAt = now
	p.ExpiresAt = now.Add(ttl)
	p.Issuer = fmt.Sprintf("permit-authority/key/%s", s.keyPair.KeyID)
	p.TemplateID = "gold-standard-v1"
	p.TemplateVer = "1.0.0"

	signed, err := s.keyPair.Sign(p, "permit", ttl)
	if err != nil {
		writeError(w, 500, "signing failed: "+err.Error())
		return
	}
	log.Printf("[SIGN] permit_id=%s  who=%s  purpose=%s  ttl=%s  digest=%s…",
		p.PermitID, p.Who.Type, p.Why.Purpose, p.When.TTL, signed.Digest[:16])

	writeJSON(w, 200, map[string]any{
		"signed_permit": signed,
		"public_key":    s.keyPair.PublicKeyB64(),
		"key_id":        s.keyPair.KeyID,
		"permit_id":     p.PermitID,
		"expires_at":    p.ExpiresAt,
		"issued_at":     p.IssuedAt,
	})
}

type verifyReq struct {
	SignedPermit cry.SignedDocument `json:"signed_permit"`
}

func (s *Server) handleVerifyPermit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, 405, "POST only")
		return
	}
	var req verifyReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, 400, "invalid JSON")
		return
	}
	if err := cry.Verify(&req.SignedPermit, s.keyPair.PublicKey); err != nil {
		writeJSON(w, 200, map[string]any{"valid": false, "reason": err.Error()})
		return
	}
	p, err := permit.FromSigned(&req.SignedPermit)
	if err != nil {
		writeError(w, 500, "parse permit: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{
		"valid":      true,
		"permit":     p,
		"issued_at":  req.SignedPermit.Header.IssuedAt,
		"expires_at": req.SignedPermit.Header.ExpiresAt,
		"key_id":     req.SignedPermit.KeyID,
		"alg":        req.SignedPermit.Header.Alg,
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

var ttlMap = map[string]time.Duration{
	"1h": time.Hour, "4h": 4 * time.Hour, "8h": 8 * time.Hour,
	"24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour,
	"30d": 30 * 24 * time.Hour, "90d": 90 * 24 * time.Hour,
	"365d": 365 * 24 * time.Hour,
}

func parseTTL(s string) (time.Duration, error) {
	if d, ok := ttlMap[strings.TrimSpace(s)]; ok {
		return d, nil
	}
	return 0, fmt.Errorf("unknown TTL %q — valid: 1h 4h 8h 24h 7d 30d 90d 365d", s)
}
