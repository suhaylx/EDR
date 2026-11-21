package edr

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAgentHTTPGuardAuthenticatesTenantAndDevice(t *testing.T) {
	now := time.Now().UTC()
	cert, _, _ := createTestAgentCertificate(t, now,
		[]string{"spiffe://turansec.local/tenants/tenantA/agents/win01"},
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	id := AgentIdentity{TenantID: "tenantA", AgentID: "win01"}
	registry := testIdentityRegistry{record: EnrolledAgentCertificate{
		Identity: id, FingerprintSHA256: sha256.Sum256(cert.Raw),
	}}
	tlsState := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert},
		VerifiedChains: [][]*x509.Certificate{{cert}}}
	calls := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		got, ok := AgentIdentityFromContext(r.Context())
		if !ok || got != id {
			t.Fatalf("missing or wrong principal: %+v, %v", got, ok)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	route := "/agent/v1/tenants/tenantA/agents/win01/events"
	tests := []struct {
		name, path string
		tls *tls.ConnectionState
		registry AgentIdentityRegistry
		want int
	}{
		{"allowed", route, tlsState, registry, http.StatusNoContent},
		{"header-claims-no-tls", route, nil, registry, http.StatusUnauthorized},
		{"unverified", route, &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}, registry, http.StatusUnauthorized},
		{"wrong-tenant", "/agent/v1/tenants/other/agents/win01/events", tlsState, registry, http.StatusForbidden},
		{"wrong-agent", "/agent/v1/tenants/tenantA/agents/other/events", tlsState, registry, http.StatusForbidden},
		{"non-agent-route", "/api/agents/win01", tlsState, registry, http.StatusNotFound},
		{"no-operation", "/agent/v1/tenants/tenantA/agents/win01", tlsState, registry, http.StatusNotFound},
		{"empty-segment", "/agent/v1/tenants/tenantA/agents/win01//events", tlsState, registry, http.StatusNotFound},
		{"malformed-route", "/agent/v1/tenants/tenantA/agents/../events", tlsState, registry, http.StatusNotFound},
		{"encoded-segment", "/agent/v1/tenants/tenantA/agents/%77in01/events", tlsState, registry, http.StatusNotFound},
		{"registry-unavailable", route, tlsState, testIdentityRegistry{err: errors.New("db down")}, http.StatusServiceUnavailable},
		{"not-enrolled", route, tlsState, testIdentityRegistry{err: ErrAgentNotEnrolled}, http.StatusUnauthorized},
		{"no-registry", route, tlsState, nil, http.StatusServiceUnavailable},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", tc.path, nil)
			req.TLS = tc.tls
			req.Header.Set("X-Tenant-ID", "tenantA")
			req.Header.Set("X-Agent-ID", "win01")
			req.Header.Set("Authorization", "Bearer arbitrary")
			res := httptest.NewRecorder()
			AgentHTTPGuard(tc.registry, next).ServeHTTP(res, req)
			if res.Code != tc.want {
				t.Fatalf("status %d want %d", res.Code, tc.want)
			}
			if res.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("missing no-store")
			}
		})
	}
	if calls != 1 {
		t.Fatalf("downstream called %d times; expected 1", calls)
	}
	if _, ok := AgentIdentityFromContext(context.Background()); ok {
		t.Fatal("empty context passed")
	}
	req := httptest.NewRequest("GET", route, nil)
	req.TLS = tlsState
	rec := httptest.NewRecorder()
	AgentHTTPGuard(registry, nil).ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("nil next status %d", rec.Code)
	}
}

func TestAgentHTTPGuardWithRealMutualTLS(t *testing.T) {
	now := time.Now().UTC()
	cert, clientCert, pool := createTestAgentCertificate(t, now,
		[]string{"spiffe://turansec.local/tenants/tenantA/agents/win01"},
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	id := AgentIdentity{TenantID: "tenantA", AgentID: "win01"}
	registry := testIdentityRegistry{record: EnrolledAgentCertificate{Identity: id,
		FingerprintSHA256: sha256.Sum256(cert.Raw)}}
	downstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, ok := AgentIdentityFromContext(r.Context())
		if !ok || got != id {
			t.Errorf("wrong identity: %+v, %v", got, ok)
			http.Error(w, "bad identity", 500)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	server := httptest.NewUnstartedServer(AgentHTTPGuard(registry, downstream))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
	server.StartTLS()
	defer server.Close()
	client := server.Client()
	tr := client.Transport.(*http.Transport).Clone()
	tr.TLSClientConfig = tr.TLSClientConfig.Clone()
	tr.TLSClientConfig.Certificates = []tls.Certificate{clientCert}
	client.Transport = tr
	defer tr.CloseIdleConnections()
	resp, err := client.Get(server.URL + "/agent/v1/tenants/tenantA/agents/win01/events")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected success got %d", resp.StatusCode)
	}
	resp, err = client.Get(server.URL + "/agent/v1/tenants/tenantA/agents/other/events")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-device status %d", resp.StatusCode)
	}
}
