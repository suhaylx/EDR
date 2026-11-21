package edr

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// NewIssuerChallengeHandler is mounted ONLY on the dedicated, pinned issuer
// TLS 1.3 mTLS listener. Unlike agent onboarding, an authorized issuer
// creates challenges and receives their one-time secrets. The handler never
// accepts a tenant/actor claim in JSON or an HTTP header as authority.
func NewIssuerChallengeHandler(store EnrollmentChallengeIssuer, issuers []TrustedEnrollmentIssuer) (http.Handler, error) {
	if store == nil || len(issuers) == 0 {
		return nil, errors.New("challenge issuance requires storage and issuer grants")
	}
	grants := make(map[issuerTenantKey]string, len(issuers))
	for _, i := range issuers {
		if i.ClientCertificateFingerprintSHA256 == ([32]byte{}) ||
			!validQueueIdentity(i.TenantID, "issuer") ||
			len(i.ActorID) < 1 || len(i.ActorID) > 256 ||
			strings.TrimSpace(i.ActorID) != i.ActorID {
			return nil, errors.New("invalid pinned challenge issuer grant")
		}
		k := issuerTenantKey{i.ClientCertificateFingerprintSHA256, i.TenantID}
		if _, exists := grants[k]; exists {
			return nil, errors.New("duplicate challenge issuer grant")
		}
		grants[k] = i.ActorID
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.URL.RawQuery != "" {
			http.Error(w, "invalid query", http.StatusBadRequest)
			return
		}
		id, valid := issuerChallengeRoute(r.URL)
		if !valid {
			http.NotFound(w, r)
			return
		}
		issuerFP, verified := verifiedIssuerLeafFingerprint(r.TLS, time.Now().UTC())
		if !verified {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		actorID, allowed := grants[issuerTenantKey{issuerFP, id.TenantID}]
		if !allowed {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || media != "application/json" {
			http.Error(w, "application/json required", http.StatusUnsupportedMediaType)
			return
		}
		// Only TTL is client-configurable; identity comes from pinned issuer
		// and canonical URL. An issuer is responsible for secure delivery.
		r.Body = http.MaxBytesReader(w, r.Body, 1024)
		var input struct {
			TTLSeconds int `json:"ttl_seconds"`
		}
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&input); err != nil {
			http.Error(w, "invalid challenge request", http.StatusBadRequest)
			return
		}
		var extra json.RawMessage
		if err := decoder.Decode(&extra); err != io.EOF {
			http.Error(w, "invalid challenge request", http.StatusBadRequest)
			return
		}
		if input.TTLSeconds < 60 || input.TTLSeconds > 600 {
			http.Error(w, "invalid challenge lifetime", http.StatusBadRequest)
			return
		}

		challenge, err := store.IssueEnrollmentChallenge(r.Context(),
			id.TenantID, id.AgentID, actorID, input.TTLSeconds)
		if err != nil {
			http.Error(w, "challenge issuance unavailable", http.StatusServiceUnavailable)
			return
		}
		if challenge == nil {
			// Does not reveal whether a device is already enrolled, revoked,
			// a pending challenge exists, or the tenant is disabled.
			http.Error(w, "challenge issuance rejected", http.StatusConflict)
			return
		}
		defer clear(challenge.ChallengeSecret[:])
		// []byte is deliberately encoded as base64 rather than a JSON array.
		if err := json.NewEncoder(w).Encode(struct {
			ChallengeID string `json:"challenge_id"`
			ChallengeSecret []byte `json:"challenge_secret"`
			TTLSeconds int `json:"ttl_seconds"`
		}{challenge.ChallengeID, challenge.ChallengeSecret[:], challenge.TTLSeconds}); err != nil {
			// The secret is non-retrievable after a write failure. An expired
			// challenge must be invalidated before reissuance; fail closed.
			return
		}
	}), nil
}

func issuerChallengeRoute(u *url.URL) (AgentIdentity, bool) {
	if u == nil || u.RawPath != "" || u.EscapedPath() != u.Path {
		return AgentIdentity{}, false
	}
	p := strings.Split(u.Path, "/")
	if len(p) != 9 || p[0] != "" || p[1] != "issuer" || p[2] != "v1" ||
		p[3] != "tenants" || p[5] != "agents" ||
		p[7] != "enroll" || p[8] != "challenge" ||
		!validQueueIdentity(p[4], p[6]) {
		return AgentIdentity{}, false
	}
	return AgentIdentity{TenantID: p[4], AgentID: p[6]}, true
}

// NewIssuerProvisioningHandler groups the two approved issuer-only paths.
// No wildcard request is forwarded to either privileged handler.
func NewIssuerProvisioningHandler(
	enrollmentStore InitialEnrollmentStore,
	challengeStore EnrollmentChallengeIssuer,
	agentRoots, agentIntermediates *x509.CertPool,
	issuers []TrustedEnrollmentIssuer,
) (http.Handler, error) {
	enrollment, err := NewIssuerEnrollmentHandler(
		enrollmentStore, agentRoots, agentIntermediates, issuers)
	if err != nil { return nil, err }
	challenges, err := NewIssuerChallengeHandler(challengeStore, issuers)
	if err != nil { return nil, err }
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/enroll/complete"):
			enrollment.ServeHTTP(w, r)
		case strings.HasSuffix(r.URL.Path, "/enroll/challenge"):
			challenges.ServeHTTP(w, r)
		default:
			http.NotFound(w, r)
		}
	}), nil
}
