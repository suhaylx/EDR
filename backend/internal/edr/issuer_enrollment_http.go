package edr

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// TrustedEnrollmentIssuer is an explicitly provisioned operator/issuance
// identity, never a claim from request JSON, an HTTP header or a certificate CN.
// Fingerprints pin individual issuer *client* leaves in addition to mTLS CA
// verification. An issuer may have multiple tenant grants with different actors.
type TrustedEnrollmentIssuer struct {
	ClientCertificateFingerprintSHA256 [32]byte
	TenantID                            string
	ActorID                             string
}

// InitialEnrollmentStore persists an approved enrollment and consumes its
// challenge atomically. Implementations MUST fail closed on database errors.
type InitialEnrollmentStore interface {
	CompleteInitialEnrollment(context.Context, EnrollmentAuthorization) (bool, error)
}

type issuerTenantKey struct {
	fingerprint [32]byte
	tenantID    string
}

// IssuerEnrollmentHandler is a dedicated, issuer-only API boundary. It must
// NOT share the agent, operator/dashboard, or localhost dev-token listener.
// The serving listener MUST use TLS 1.3 RequireAndVerifyClientCert and an
// issuer-only CA pool. The handler checks the verified connection and pins
// the issuer leaf to a pre-provisioned tenant grant; it performs no issuance.
func NewIssuerEnrollmentHandler(store InitialEnrollmentStore, agentRoots, agentIntermediates *x509.CertPool, issuers []TrustedEnrollmentIssuer) (http.Handler, error) {
	if store == nil || agentRoots == nil || len(issuers) == 0 {
		return nil, errors.New("issuer enrollment requires storage, controlled agent roots, and issuer grants")
	}
	grants := make(map[issuerTenantKey]string, len(issuers))
	for _, i := range issuers {
		if i.ClientCertificateFingerprintSHA256 == ([32]byte{}) ||
			!validQueueIdentity(i.TenantID, "issuer") ||
			len(i.ActorID) < 1 || len(i.ActorID) > 256 || strings.TrimSpace(i.ActorID) != i.ActorID {
			return nil, errors.New("invalid pinned issuer grant")
		}
		key := issuerTenantKey{i.ClientCertificateFingerprintSHA256, i.TenantID}
		if _, exists := grants[key]; exists {
			return nil, errors.New("duplicate pinned issuer grant")
		}
		grants[key] = i.ActorID
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
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
		identity, ok := issuerEnrollmentRoute(r.URL)
		if !ok {
			http.NotFound(w, r)
			return
		}

		// Route authorization is based ONLY on the pinned, mTLS-verified leaf.
		// A verified CA chain alone does not grant access to any tenant.
		issuerFP, verified := verifiedIssuerLeafFingerprint(r.TLS, time.Now().UTC())
		if !verified {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		actorID, allowed := grants[issuerTenantKey{issuerFP, identity.TenantID}]
		if !allowed {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || media != "application/json" {
			http.Error(w, "application/json required", http.StatusUnsupportedMediaType)
			return
		}

		// Payloads contain enrollment secrets and signed artifacts. Never log
		// body contents, certificates, challenge bytes or response artifacts.
		r.Body = http.MaxBytesReader(w, r.Body, 192*1024)
		var input struct {
			ChallengeID     string `json:"challenge_id"`
			ChallengeSecret []byte `json:"challenge_secret"` // standard JSON base64
			Platform        string `json:"platform"`
			CSRDER          []byte `json:"csr_der"`
			CertificateDER  []byte `json:"certificate_der"`
		}
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&input); err != nil {
			http.Error(w, "invalid enrollment payload", http.StatusBadRequest)
			return
		}
		defer clear(input.ChallengeSecret)
		var extra json.RawMessage
		if err := decoder.Decode(&extra); err != io.EOF {
			http.Error(w, "invalid enrollment payload", http.StatusBadRequest)
			return
		}
		if !validUUID(input.ChallengeID) || len(input.ChallengeSecret) != 32 ||
			len(input.CSRDER) == 0 || len(input.CSRDER) > 64*1024 ||
			len(input.CertificateDER) == 0 || len(input.CertificateDER) > 64*1024 ||
			(input.Platform != "windows" && input.Platform != "linux") {
			http.Error(w, "invalid enrollment payload", http.StatusBadRequest)
			return
		}
		if err := ValidateChallengeBoundAgentCSR(input.CSRDER, identity, input.ChallengeID, input.ChallengeSecret); err != nil {
			http.Error(w, "invalid certificate request", http.StatusBadRequest)
			return
		}
		now := time.Now().UTC()
		fingerprint, err := ValidateTrustedIssuedCertificateForCSR(
			input.CSRDER, input.CertificateDER, identity,
			agentRoots, agentIntermediates, now,
		)
		if err != nil {
			http.Error(w, "untrusted or mismatched issued certificate", http.StatusBadRequest)
			return
		}
		leaf, err := x509.ParseCertificate(input.CertificateDER)
		if err != nil {
			http.Error(w, "invalid issued certificate", http.StatusBadRequest)
			return
		}
		authorized := EnrollmentAuthorization{
			ChallengeID:             input.ChallengeID,
			TenantID:                identity.TenantID,
			AgentID:                 identity.AgentID,
			Platform:                input.Platform,
			ChallengeDigest:         sha256.Sum256(input.ChallengeSecret),
			CertificateFingerprint:  fingerprint,
			CertificateNotBefore:    leaf.NotBefore,
			CertificateNotAfter:     leaf.NotAfter,
			ActorID:                 actorID,
		}
		enrolled, err := store.CompleteInitialEnrollment(r.Context(), authorized)
		if err != nil {
			http.Error(w, "enrollment unavailable", http.StatusServiceUnavailable)
			return
		}
		if !enrolled {
			// Never disclose whether an agent exists, a challenge was consumed,
			// or a tenant was disabled. The authorized issuer can investigate
			// through the out-of-band enrollment audit.
			http.Error(w, "enrollment rejected", http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}), nil
}

// EnrollmentCSRChallengeSerial returns the challenge-specific signed subject
// serialNumber the endpoint must put in the CSR it generates using its own
// private key. The server checks the signature and this exact binding, so an
// old signed CSR cannot be reused for a new challenge or tenant/device.
// A short-lived 32-byte secret MUST be generated by a privileged challenge
// issuer with crypto/rand and stored only as a digest in PostgreSQL.
func EnrollmentCSRChallengeSerial(challengeID string, identity AgentIdentity, secret []byte) (string, error) {
	if !validUUID(challengeID) || !validQueueIdentity(identity.TenantID, identity.AgentID) || len(secret) != 32 {
		return "", errors.New("invalid enrollment challenge binding")
	}
	h := sha256.New()
	_, _ = io.WriteString(h, "turansec-agent-enrollment-csr-v1\x00")
	_, _ = io.WriteString(h, challengeID)
	_, _ = io.WriteString(h, "\x00")
	_, _ = io.WriteString(h, identity.TenantID)
	_, _ = io.WriteString(h, "\x00")
	_, _ = io.WriteString(h, identity.AgentID)
	_, _ = io.WriteString(h, "\x00")
	_, _ = h.Write(secret)
	return "ts-enroll-v1-" + hex.EncodeToString(h.Sum(nil)), nil
}

func ValidateChallengeBoundAgentCSR(csrDER []byte, identity AgentIdentity, challengeID string, secret []byte) error {
	if _, err := ValidateAgentCSR(csrDER, identity); err != nil {
		return err
	}
	serial, err := EnrollmentCSRChallengeSerial(challengeID, identity, secret)
	if err != nil {
		return err
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil || subtle.ConstantTimeCompare([]byte(csr.Subject.SerialNumber), []byte(serial)) != 1 {
		return errors.New("agent CSR not bound to issued enrollment challenge")
	}
	return nil
}

func issuerEnrollmentRoute(u *url.URL) (AgentIdentity, bool) {
	if u == nil || u.RawPath != "" || u.EscapedPath() != u.Path {
		return AgentIdentity{}, false
	}
	p := strings.Split(u.Path, "/")
	if len(p) != 9 || p[0] != "" || p[1] != "issuer" || p[2] != "v1" ||
		p[3] != "tenants" || p[5] != "agents" ||
		p[7] != "enroll" || p[8] != "complete" ||
		!validQueueIdentity(p[4], p[6]) {
		return AgentIdentity{}, false
	}
	return AgentIdentity{TenantID: p[4], AgentID: p[6]}, true
}

func verifiedIssuerLeafFingerprint(state *tls.ConnectionState, now time.Time) ([32]byte, bool) {
	var zero [32]byte
	if state == nil || !state.HandshakeComplete || state.Version < tls.VersionTLS13 ||
		len(state.PeerCertificates) == 0 || len(state.VerifiedChains) == 0 ||
		len(state.VerifiedChains[0]) == 0 {
		return zero, false
	}
	leaf := state.PeerCertificates[0]
	verifiedLeaf := state.VerifiedChains[0][0]
	if leaf == nil || verifiedLeaf == nil || len(leaf.Raw) == 0 ||
		subtle.ConstantTimeCompare(leaf.Raw, verifiedLeaf.Raw) != 1 ||
		leaf.IsCA || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) ||
		leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 || !hasClientAuthenticationEKU(leaf) {
		return zero, false
	}
	return sha256.Sum256(leaf.Raw), true
}
