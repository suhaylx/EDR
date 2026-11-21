package edr

import (
    "context"
    "crypto/sha256"
    "crypto/tls"
    "crypto/x509"
    "database/sql/driver"
    "io"
    "net/http"
    "net/http/httptest"
    "strings"
    "sync"
    "sync/atomic"
    "testing"
    "time"
)

// Sprint Day 2: exercise the actual TLS handshake, certificate-derived
// tenant/agent context and heartbeat DB write in one test. The SQL driver is
// an isolated stub; this is not a live PostgreSQL or endpoint-host test.
func TestEnrolledMTLSHeartbeatUsesVerifiedPrincipal(t *testing.T) {
    now := time.Now().UTC().Truncate(time.Second)
    leaf, clientCert, trustedCA := createTestAgentCertificate(t, now,
        []string{"spiffe://turansec.local/tenants/tenantA/agents/win01"},
        []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
    principal := AgentIdentity{TenantID: "tenantA", AgentID: "win01"}
    registry := &revocableHeartbeatTestRegistry{record: EnrolledAgentCertificate{
        Identity: principal, FingerprintSHA256: sha256.Sum256(leaf.Raw),
    }}
    var writes atomic.Int32
    db := scanDB(t, func(q string, args []driver.NamedValue) (driver.Rows, error) {
        if !strings.Contains(q, "edr_record_agent_heartbeat") {
            t.Fatalf("unexpected SQL statement %q", q)
        }
        writes.Add(1)
        if len(args) != 7 || args[0].Value != "tenantA" ||
            args[1].Value != "win01" || args[2].Value != "windows" ||
            args[3].Value != "0.1.0" {
            t.Fatalf("untrusted tenant/device values reached SQL: %#v", args)
        }
        return &scanRows{columns: []string{"saved"},
            values: [][]driver.Value{{true}}}, nil
    })
    handler := AgentHTTPGuard(registry, AgentScanQueueHandler(PostgresScanJobQueue{DB: db}))
    server := httptest.NewUnstartedServer(handler)
    server.TLS = &tls.Config{
        MinVersion: tls.VersionTLS13,
        ClientAuth: tls.RequireAndVerifyClientCert,
        ClientCAs: trustedCA,
        SessionTicketsDisabled: true,
    }
    server.StartTLS()
    defer server.Close()

    transport := server.Client().Transport.(*http.Transport).Clone()
    transport.TLSClientConfig = transport.TLSClientConfig.Clone()
    transport.TLSClientConfig.Certificates = []tls.Certificate{clientCert}
    client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
    defer transport.CloseIdleConnections()
    path := "/agent/v1/tenants/tenantA/agents/win01/heartbeat"
    body := `{"platform":"windows","agent_version":"0.1.0","scan_ready":false}`
    send := func(url string) int {
        t.Helper()
        req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
        if err != nil {t.Fatal(err)}
        req.Header.Set("Content-Type", "application/json")
        req.Header.Set("Authorization", "Bearer attacker-provided")
        req.Header.Set("X-Tenant-ID", "wrong-tenant")
        req.Header.Set("X-Agent-ID", "wrong-device")
        req.Header.Set("X-Forwarded-Client-Cert", "forged")
        response, err := client.Do(req)
        if err != nil {t.Fatal(err)}
        defer response.Body.Close()
        _, _ = io.Copy(io.Discard, response.Body)
        return response.StatusCode
    }
    if code := send(server.URL + path); code != http.StatusNoContent {
        t.Fatalf("genuine client cert heartbeat status %d, want 204", code)
    }
    if writes.Load() != 1 {t.Fatalf("expected 1 SQL heartbeat write, got %d", writes.Load())}
    if code := send(server.URL + "/agent/v1/tenants/other/agents/win01/heartbeat");
        code != http.StatusForbidden {
        t.Fatalf("wrong tenant path status %d, want 403", code)
    }
    if writes.Load() != 1 {t.Fatal("cross-tenant request reached database")}

    // The TLS layer itself must refuse a client without a certificate.
    request, err := http.NewRequest(http.MethodPost, server.URL + path,
        strings.NewReader(body))
    if err != nil {t.Fatal(err)}
    response, err := server.Client().Do(request)
    if err == nil {
        response.Body.Close()
        t.Fatal("server accepted an HTTPS request with no client certificate")
    }
    if writes.Load() != 1 {t.Fatal("missing client certificate reached database")}

    // The same previously accepted mTLS connection must not continue
    // authorizing device operations after enrollment is revoked. The
    // application guard rechecks the registry on every HTTP request.
    registry.revoke()
    if code := send(server.URL + path); code != http.StatusUnauthorized {
        t.Fatalf("revoked device heartbeat status %d, want 401", code)
    }
    if writes.Load() != 1 {t.Fatal("revoked client certificate reached SQL")}
}

type revocableHeartbeatTestRegistry struct {
    mu sync.Mutex
    record EnrolledAgentCertificate
}

func (r *revocableHeartbeatTestRegistry) LookupAgentCertificate(
    _ context.Context, tenant, agent string,
) (EnrolledAgentCertificate, error) {
    r.mu.Lock()
    defer r.mu.Unlock()
    if tenant != r.record.Identity.TenantID || agent != r.record.Identity.AgentID {
        return EnrolledAgentCertificate{}, ErrAgentNotEnrolled
    }
    return r.record, nil
}

func (r *revocableHeartbeatTestRegistry) revoke() {
    r.mu.Lock()
    defer r.mu.Unlock()
    r.record.Revoked = true
}
