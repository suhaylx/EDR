package edr

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"
)

type captureInitialEnrollmentStore struct {
	mu      sync.Mutex
	calls   []EnrollmentAuthorization
	allowed bool
	err     error
}

func (s *captureInitialEnrollmentStore) CompleteInitialEnrollment(_ context.Context, a EnrollmentAuthorization) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, a)
	return s.allowed, s.err
}

func (s *captureInitialEnrollmentStore) records() []EnrollmentAuthorization {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]EnrollmentAuthorization(nil), s.calls...)
}

type issuerTestSetup struct {
	handler         http.Handler
	store           *captureInitialEnrollmentStore
	issuerTLS       tls.Certificate
	issuerRoots     *x509.CertPool
	agentLeaf       *x509.Certificate
	agentTLS        tls.Certificate
	agentRoots      *x509.CertPool
	identity        AgentIdentity
	challengeSecret []byte
	challengeID     string
	csrDER          []byte
}

func newIssuerTestSetup(t *testing.T) issuerTestSetup {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	issuerLeaf, issuerTLS, issuerRoots := createTestAgentCertificate(t, now,
		[]string{"spiffe://turansec.local/tenants/security/agents/issuer01"},
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	agentLeaf, agentTLS, agentRoots := createTestAgentCertificate(t, now,
		[]string{"spiffe://turansec.local/tenants/tenantA/agents/win01"},
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	id := AgentIdentity{TenantID: "tenantA", AgentID: "win01"}
	challenge := []byte("0123456789abcdef0123456789abcdef")
	challengeID := "11111111-1111-4111-8111-111111111111"
	serial, err := EnrollmentCSRChallengeSerial(challengeID, id, challenge)
	if err != nil {
		t.Fatal(err)
	}
	uri, _ := url.Parse("spiffe://turansec.local/tenants/tenantA/agents/win01")
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{SerialNumber: serial}, URIs: []*url.URL{uri},
	}, agentTLS.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	store := &captureInitialEnrollmentStore{allowed: true}
	handler, err := NewIssuerEnrollmentHandler(store, agentRoots, nil, []TrustedEnrollmentIssuer{{
		ClientCertificateFingerprintSHA256: sha256.Sum256(issuerLeaf.Raw),
		TenantID: "tenantA", ActorID: "pinned-issuer-01",
	}})
	if err != nil {
		t.Fatal(err)
	}
	return issuerTestSetup{
		handler: handler, store: store, issuerTLS: issuerTLS,
		issuerRoots: issuerRoots, agentLeaf: agentLeaf, agentTLS: agentTLS,
		agentRoots: agentRoots, identity: id, challengeSecret: challenge,
		challengeID: challengeID, csrDER: csr,
	}
}

func (s issuerTestSetup) payload(t *testing.T) []byte {
	t.Helper()
	body, err := json.Marshal(struct {
		ChallengeID string `json:"challenge_id"`
		ChallengeSecret []byte `json:"challenge_secret"`
		Platform string `json:"platform"`
		CSRDER []byte `json:"csr_der"`
		CertificateDER []byte `json:"certificate_der"`
	}{s.challengeID, s.challengeSecret, "windows", s.csrDER, s.agentLeaf.Raw})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestIssuerEnrollmentRealMutualTLSAndChallengeBinding(t *testing.T) {
	s := newIssuerTestSetup(t)
	server := httptest.NewUnstartedServer(s.handler)
	server.TLS = &tls.Config{
		MinVersion: tls.VersionTLS13,
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs: s.issuerRoots,
	}
	server.StartTLS()
	defer server.Close()
	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.Certificates = []tls.Certificate{s.issuerTLS}
	client := &http.Client{Transport: transport}
	defer transport.CloseIdleConnections()

	const path = "/issuer/v1/tenants/tenantA/agents/win01/enroll/complete"
	post := func(path string, body []byte) int {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, server.URL+path, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		// Spoofed headers are never used to determine issuer grants or actor.
		req.Header.Set("X-Actor-ID", "attacker")
		req.Header.Set("X-Tenant-ID", "tenantB")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}
	body := s.payload(t)
	if status := post(path, body); status != http.StatusNoContent {
		t.Fatalf("authorized issuer enrollment status %d", status)
	}
	got := s.store.records()
	if len(got) != 1 {
		t.Fatalf("expected one atomic enrollment call, got %d", len(got))
	}
	a := got[0]
	if a.TenantID != s.identity.TenantID || a.AgentID != s.identity.AgentID ||
		a.ActorID != "pinned-issuer-01" || a.Platform != "windows" ||
		a.ChallengeDigest != sha256.Sum256(s.challengeSecret) ||
		a.CertificateFingerprint != sha256.Sum256(s.agentLeaf.Raw) ||
		!a.CertificateNotBefore.Equal(s.agentLeaf.NotBefore) ||
		!a.CertificateNotAfter.Equal(s.agentLeaf.NotAfter) {
		t.Fatalf("enrollment trust boundaries not preserved: %+v", a)
	}

	if status := post("/issuer/v1/tenants/tenantB/agents/win01/enroll/complete", body); status != http.StatusForbidden {
		t.Fatalf("issuer authorized for wrong tenant: %d", status)
	}
	if status := post("/issuer/v1/tenants/tenantA/agents/other/enroll/complete", body); status != http.StatusBadRequest {
		t.Fatalf("CSR/issued cert accepted for different agent: %d", status)
	}
	if len(s.store.records()) != 1 {
		t.Fatal("unauthorized or mismatched requests reached enrollment database")
	}

	// A second attempt is always subject to the database's single-use
	// challenge check; the handler must never assume that a valid CSR alone
	// makes the request idempotently successful.
	s.store.mu.Lock()
	s.store.allowed = false
	s.store.mu.Unlock()
	if status := post(path, body); status != http.StatusConflict {
		t.Fatalf("replayed or already-enrolled request status %d", status)
	}
	if len(s.store.records()) != 2 {
		t.Fatal("replay did not reach atomic challenge/replay rejection")
	}

	// A non-mTLS client cannot even establish a connection to the listener.
	req, err := http.NewRequest(http.MethodPost, server.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := server.Client().Do(req)
	if err == nil {
		resp.Body.Close()
		t.Fatalf("missing issuer certificate reached endpoint: status %d", resp.StatusCode)
	}
}

func TestIssuerEnrollmentRejectsCrossChallengeCSRAndUntrustedLeaf(t *testing.T) {
	s := newIssuerTestSetup(t)
	good := s.csrDER
	if err := ValidateChallengeBoundAgentCSR(good, s.identity, s.challengeID, s.challengeSecret); err != nil {
		t.Fatalf("challenge-bound CSR rejected: %v", err)
	}
	if err := ValidateChallengeBoundAgentCSR(good, s.identity,
		"22222222-2222-4222-8222-222222222222", s.challengeSecret); err == nil {
		t.Fatal("old CSR accepted for a different challenge ID")
	}
	otherSecret := append([]byte(nil), s.challengeSecret...)
	otherSecret[0] ^= 0xff
	if err := ValidateChallengeBoundAgentCSR(good, s.identity, s.challengeID, otherSecret); err == nil {
		t.Fatal("CSR accepted for a different secret")
	}
	if err := ValidateChallengeBoundAgentCSR(good,
		AgentIdentity{TenantID: "tenantB", AgentID: "win01"}, s.challengeID, s.challengeSecret); err == nil {
		t.Fatal("CSR accepted for a different tenant")
	}
	tampered := append([]byte(nil), good...)
	tampered[len(tampered)-1] ^= 0xff
	if err := ValidateChallengeBoundAgentCSR(tampered, s.identity, s.challengeID, s.challengeSecret); err == nil {
		t.Fatal("tampered signed CSR accepted")
	}
	if _, err := ValidateTrustedIssuedCertificateForCSR(
		s.csrDER, s.agentLeaf.Raw, s.identity, s.issuerRoots, nil, time.Now()); err == nil {
		t.Fatal("untrusted agent CA accepted")
	}
}

func TestIssuerEnrollmentFailClosedPayloadAndIssuerConfiguration(t *testing.T) {
	s := newIssuerTestSetup(t)
	if _, err := NewIssuerEnrollmentHandler(nil, s.agentRoots, nil, []TrustedEnrollmentIssuer{{
		TenantID: "tenantA", ActorID: "ops",
	}}); err == nil {
		t.Fatal("missing enrollment store accepted")
	}
	if _, err := NewIssuerEnrollmentHandler(s.store, nil, nil, []TrustedEnrollmentIssuer{{
		TenantID: "tenantA", ActorID: "ops",
	}}); err == nil {
		t.Fatal("missing agent roots accepted")
	}
	if _, err := NewIssuerEnrollmentHandler(s.store, s.agentRoots, nil, nil); err == nil {
		t.Fatal("empty issuer allowlist accepted")
	}
	if _, err := NewIssuerEnrollmentHandler(s.store, s.agentRoots, nil, []TrustedEnrollmentIssuer{{
		TenantID: "tenantA", ActorID: "ops",
	}}); err == nil {
		t.Fatal("zero issuer fingerprint accepted")
	}
	leaf, _, _ := createTestAgentCertificate(t, time.Now(),
		[]string{"spiffe://turansec.local/tenants/security/agents/issuer01"},
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	grant := TrustedEnrollmentIssuer{ClientCertificateFingerprintSHA256: sha256.Sum256(leaf.Raw),
		TenantID: "tenantA", ActorID: "ops"}
	if _, err := NewIssuerEnrollmentHandler(s.store, s.agentRoots, nil,
		[]TrustedEnrollmentIssuer{grant, grant}); err == nil {
		t.Fatal("duplicate issuer grant accepted")
	}

	const path = "/issuer/v1/tenants/tenantA/agents/win01/enroll/complete"
	// No fabricated TLS headers can substitute for a verified TLS connection.
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(s.payload(t)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Client-Cert", "trusted")
	w := httptest.NewRecorder()
	s.handler.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated direct request status %d", w.Code)
	}

	// This test state models a *verified* issuer TLS connection; malformed
	// payloads must be rejected before any database write.
	issuerLeaf := s.issuerTLS.Leaf
	verified := &tls.ConnectionState{
		HandshakeComplete: true, Version: tls.VersionTLS13,
		PeerCertificates: []*x509.Certificate{issuerLeaf},
		VerifiedChains: [][]*x509.Certificate{{issuerLeaf}},
	}
	cases := []struct {
		name string
		body string
		status int
	}{
		{"bad json", "{", http.StatusBadRequest},
		{"unknown actor", `{"actor_id":"attacker"}`, http.StatusBadRequest},
		{"trailing JSON", string(s.payload(t)) + `{}`, http.StatusBadRequest},
		{"missing fields", `{}`, http.StatusBadRequest},
		{"bad base64", `{"challenge_secret":"**"}`, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(tc.body))
			req.TLS = verified
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			s.handler.ServeHTTP(w, req)
			if w.Code != tc.status {
				t.Fatalf("got %d expected %d", w.Code, tc.status)
			}
		})
	}
	if len(s.store.records()) != 0 {
		t.Fatal("invalid issuer requests reached storage")
	}

	// Storage outages must not produce a registration success response.
	s.store.err = errors.New("secret PostgreSQL outage")
	req = httptest.NewRequest(http.MethodPost, path, bytes.NewReader(s.payload(t)))
	req.TLS = verified
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	s.handler.ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("storage failure status %d", w.Code)
	}
	if bytes.Contains(w.Body.Bytes(), []byte("secret PostgreSQL")) {
		t.Fatal("database details leaked to client")
	}
}
