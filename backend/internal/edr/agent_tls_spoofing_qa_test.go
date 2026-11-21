package edr

import (
    "crypto/sha256"
    "crypto/tls"
    "crypto/x509"
    "io"
    "log"
    "net/http"
    "net/http/httptest"
    "strings"
    "testing"
    "time"
)

// Day 1, P0: exercise real ephemeral TLS sockets rather than supplying a
// fabricated request.TLS identity. This does NOT configure a production listener.
func TestQAMutualTLSSpoofedHeadersAndUntrustedClients(t *testing.T) {
    now := time.Now().UTC()
    uri := "spiffe://turansec.local/tenants/tenantA/agents/win01"
    leaf, approvedCert, approvedCA := createTestAgentCertificate(t, now,
        []string{uri}, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
    _, wrongCACert, _ := createTestAgentCertificate(t, now,
        []string{uri}, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
    _, serverOnlyCert, _ := createTestAgentCertificate(t, now,
        []string{uri}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})

    record := EnrolledAgentCertificate{
        Identity: AgentIdentity{TenantID: "tenantA", AgentID: "win01"},
        FingerprintSHA256: sha256.Sum256(leaf.Raw),
    }
    handler := AgentHTTPGuard(testIdentityRegistry{record: record},
        AgentScanQueueHandler(PostgresScanJobQueue{}))
    server := httptest.NewUnstartedServer(handler)
    server.Config.ErrorLog = log.New(io.Discard, "", 0)
    server.TLS = &tls.Config{
        MinVersion: tls.VersionTLS13,
        ClientAuth: tls.RequireAndVerifyClientCert,
        ClientCAs: approvedCA,
    }
    server.StartTLS()
    defer server.Close()

    path := "/agent/v1/tenants/tenantA/agents/win01/scan-jobs/claim"
    newClient := func(certs []tls.Certificate, maxTLS uint16) *http.Client {
        t.Helper()
        tr := server.Client().Transport.(*http.Transport).Clone()
        tr.TLSClientConfig = tr.TLSClientConfig.Clone()
        tr.TLSClientConfig.Certificates = certs
        tr.TLSClientConfig.MinVersion = tls.VersionTLS12
        tr.TLSClientConfig.MaxVersion = maxTLS
        t.Cleanup(tr.CloseIdleConnections)
        return &http.Client{Transport: tr, Timeout: 4 * time.Second}
    }
    request := func(c *http.Client, url string) (*http.Response, error) {
        t.Helper()
        req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(""))
        if err != nil { t.Fatal(err) }
        // All of these are attacker-controlled. None may substitute for an
        // authenticated certificate principal or override the SAN/registry.
        req.Header.Set("X-Tenant-ID", "tenantB")
        req.Header.Set("X-Agent-ID", "other")
        req.Header.Set("X-Forwarded-Client-Cert", "spiffe://turansec.local/tenants/tenantA/agents/win01")
        req.Header.Set("X-SSL-Client-Verify", "SUCCESS")
        req.Header.Set("X-SSL-Client-S-DN", "CN=win01")
        req.Header.Set("Authorization", "Bearer unauthorized-proxy-token")
        return c.Do(req)
    }
    tlsDenials := []struct{
        name string
        certs []tls.Certificate
        maxVersion uint16
    }{
        {"forwarded-identity-without-certificate", nil, 0},
        {"untrusted-ca-client-certificate", []tls.Certificate{wrongCACert}, 0},
        {"wrong-purpose-server-only-certificate", []tls.Certificate{serverOnlyCert}, 0},
        {"obsolete-tls12-even-with-valid-certificate", []tls.Certificate{approvedCert}, tls.VersionTLS12},
    }
    for _, tc := range tlsDenials {
        t.Run(tc.name, func(t *testing.T) {
            client := newClient(tc.certs, tc.maxVersion)
            response, err := request(client, server.URL + path)
            if err == nil {
                response.Body.Close()
                t.Fatalf("client rejected by TLS policy unexpectedly received HTTP %d", response.StatusCode)
            }
        })
    }

    client := newClient([]tls.Certificate{approvedCert}, 0)
    cases := []struct{name, path string; want int}{
        {"trusted-cert-but-spoofed-headers-have-no-authority", path, http.StatusServiceUnavailable},
        {"trusted-cert-cannot-claim-other-tenant", "/agent/v1/tenants/tenantB/agents/win01/scan-jobs/claim", http.StatusForbidden},
        {"trusted-cert-cannot-claim-other-agent", "/agent/v1/tenants/tenantA/agents/other/scan-jobs/claim", http.StatusForbidden},
        {"trusted-cert-cannot-inject-query-tenant", path + "?tenant_id=tenantB", http.StatusBadRequest},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            response, err := request(client, server.URL + tc.path)
            if err != nil { t.Fatal(err) }
            defer response.Body.Close()
            if response.StatusCode != tc.want {
                t.Fatalf("verified client status %d want %d for %s", response.StatusCode, tc.want, tc.path)
            }
            if response.Header.Get("Cache-Control") != "no-store" {
                t.Fatal("private agent response is cacheable")
            }
        })
    }
}
