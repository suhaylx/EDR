package edr

import (
    "crypto/sha256"
    "crypto/tls"
    "crypto/x509"
    "errors"
    "net/http"
    "net/http/httptest"
    "strings"
    "testing"
    "time"
)

func TestAgentIdentityProbeRejectsLegacyBearerAndMissingRegistry(t *testing.T) {
    h := AgentIdentityHandler(testIdentityRegistry{})
    for _, tc := range []struct{name, method string; want int}{
        {"no-tls", http.MethodGet, http.StatusUnauthorized},
        {"post", http.MethodPost, http.StatusMethodNotAllowed},
    } {
        t.Run(tc.name, func(t *testing.T) {
            req := httptest.NewRequest(tc.method, "/api/agent/v1/identity", nil)
            req.Header.Set("Authorization", "Bearer development-only-token")
            w := httptest.NewRecorder()
            h.ServeHTTP(w, req)
            if w.Code != tc.want { t.Fatalf("status %d, want %d", w.Code, tc.want) }
            if strings.Contains(w.Body.String(), "tenant_id") { t.Fatal("identity leaked") }
            if w.Header().Get("Cache-Control") != "no-store" { t.Fatal("must prevent caching") }
        })
    }
    w := httptest.NewRecorder()
    AgentIdentityHandler(nil).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/agent/v1/identity", nil))
    if w.Code != http.StatusServiceUnavailable { t.Fatalf("registry absent: %d", w.Code) }
}

func TestAgentIdentityProbeVerifiedAndRevoked(t *testing.T) {
    now := time.Now().UTC().Truncate(time.Second)
    cert, _, _ := createTestAgentCertificate(t, now, []string{
        "spiffe://turansec.local/tenants/tenantA/agents/deviceA",
    }, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
    identity := AgentIdentity{TenantID:"tenantA", AgentID:"deviceA"}
    record := EnrolledAgentCertificate{Identity:identity, FingerprintSHA256:sha256.Sum256(cert.Raw)}
    cases := []struct{name string; registry testIdentityRegistry; want int}{
        {"registered", testIdentityRegistry{record:record}, http.StatusOK},
        {"revoked", testIdentityRegistry{record:EnrolledAgentCertificate{Identity:identity, FingerprintSHA256:record.FingerprintSHA256, Revoked:true}}, http.StatusUnauthorized},
        {"registry-down", testIdentityRegistry{err:errors.New("database unavailable")}, http.StatusServiceUnavailable},
    }
    for _,tc := range cases {
        t.Run(tc.name,func(t *testing.T){
            req:=httptest.NewRequest(http.MethodGet,"/api/agent/v1/identity",nil)
            req.TLS=&tls.ConnectionState{PeerCertificates:[]*x509.Certificate{cert}, VerifiedChains:[][]*x509.Certificate{{cert}}}
            w:=httptest.NewRecorder()
            AgentIdentityHandler(tc.registry).ServeHTTP(w,req)
            if w.Code!=tc.want { t.Fatalf("status %d want %d: %s",w.Code,tc.want,w.Body.String()) }
            if tc.want==http.StatusOK && (!strings.Contains(w.Body.String(), "tenantA") || !strings.Contains(w.Body.String(),"deviceA")) {t.Fatal("missing verified principal")}
        })
    }
}
