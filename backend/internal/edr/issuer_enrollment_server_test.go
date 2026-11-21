package edr

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql/driver"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestIssuerListenerEnforcesDedicatedMTLSConfiguration(t *testing.T) {
	now := time.Now().UTC()
	issuerLeaf, _, issuerRoots := createTestAgentCertificate(t, now,
		[]string{"spiffe://turansec.local/tenants/security/agents/issuer01"},
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	_, serverCert, _ := createTestAgentCertificate(t, now, nil,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	_, _, agentRoots := createTestAgentCertificate(t, now,
		[]string{"spiffe://turansec.local/tenants/tenantA/agents/win01"},
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	grants := []TrustedEnrollmentIssuer{{
		ClientCertificateFingerprintSHA256: sha256.Sum256(issuerLeaf.Raw),
		TenantID: "tenantA", ActorID: "pinned-issuer-01",
	}}
	db := scanDB(t, func(string, []driver.NamedValue) (driver.Rows, error) {
		return nil, errors.New("database must not be queried at construction")
	})
	server, err := NewIssuerEnrollmentMTLSServer("127.0.0.1:9443",
		db, serverCert, issuerRoots, agentRoots, nil, grants)
	if err != nil {
		t.Fatalf("expected a server constructor, got %v", err)
	}
	if server.TLSConfig.MinVersion != tls.VersionTLS13 ||
		server.TLSConfig.ClientAuth != tls.RequireAndVerifyClientCert ||
		server.TLSConfig.ClientCAs != issuerRoots ||
		server.Handler == nil {
		t.Fatal("issuer TLS listener is not isolated or client-authenticated")
	}
	// The constructor must not accidentally enable a bypassing HTTP listener.
	w := httptest.NewRecorder()
	server.Handler.ServeHTTP(w, httptest.NewRequest(http.MethodPost,
		"/issuer/v1/tenants/tenantA/agents/win01/enroll/complete", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("plain HTTP accepted on issuer handler: %d", w.Code)
	}

	invalid := []struct {
		name       string
		addr       string
		issuerCAs  *x509.CertPool
		agentRoots *x509.CertPool
		grants     []TrustedEnrollmentIssuer
		cert       tls.Certificate
	}{
		{"wildcard ipv4", "0.0.0.0:9443", issuerRoots, agentRoots, grants, serverCert},
		{"wildcard ipv6", "[::]:9443", issuerRoots, agentRoots, grants, serverCert},
		{"missing host", ":9443", issuerRoots, agentRoots, grants, serverCert},
		{"invalid hostport", "invalid", issuerRoots, agentRoots, grants, serverCert},
		{"missing issuer CA", "127.0.0.1:9443", nil, agentRoots, grants, serverCert},
		{"missing agent root", "127.0.0.1:9443", issuerRoots, nil, grants, serverCert},
		{"missing grants", "127.0.0.1:9443", issuerRoots, agentRoots, nil, serverCert},
		{"missing server keypair", "127.0.0.1:9443", issuerRoots, agentRoots, grants, tls.Certificate{}},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewIssuerEnrollmentMTLSServer(tc.addr,
				db, tc.cert, tc.issuerCAs, tc.agentRoots, nil, tc.grants); err == nil {
				t.Fatal("insecure issuer listener configuration was accepted")
			}
		})
	}
	if _, err := NewIssuerEnrollmentMTLSServer("127.0.0.1:9443",
		nil, serverCert, issuerRoots, agentRoots, nil, grants); err == nil {
		t.Fatal("missing database accepted")
	}
}
