package edr

import (
    "crypto/tls"
    "crypto/x509"
    "database/sql"
    "database/sql/driver"
    "net/http"
    "net/http/httptest"
    "testing"
    "time"
)

// Regression: previous test supplied nil DB for every case, so it never
// reached address or TLS configuration validation.
func TestNewAgentMTLSServerRejectsIncompleteConfiguration(t *testing.T) {
    db := scanDB(t, func(string, []driver.NamedValue) (driver.Rows, error) {
        t.Fatal("constructing a TLS server must not access the database")
        return nil, nil
    })
    pool := x509.NewCertPool()
    cert := tls.Certificate{Certificate: [][]byte{{1}}} // constructor-only sentinel
    cases := []struct {
        name, addr string
        db *sql.DB
        cert tls.Certificate
        ca *x509.CertPool
    }{
        {"missing db", "127.0.0.1:9443", nil, cert, pool},
        {"missing cert", "127.0.0.1:9443", db, tls.Certificate{}, pool},
        {"missing CA", "127.0.0.1:9443", db, cert, nil},
        {"wildcard ipv4", "0.0.0.0:9443", db, cert, pool},
        {"wildcard ipv6", "[::]:9443", db, cert, pool},
        {"no host", ":9443", db, cert, pool},
        {"malformed", "not-a-listener", db, cert, pool},
        {"missing port", "127.0.0.1", db, cert, pool},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            if server, err := NewAgentMTLSServer(tc.addr, tc.db, tc.cert, tc.ca); err == nil {
                t.Fatalf("unsafe TLS configuration accepted: %#v", server)
            }
        })
    }
}

func TestNewAgentMTLSServerEnforcesClientCertificates(t *testing.T) {
    db := scanDB(t, func(string, []driver.NamedValue) (driver.Rows, error) {
        t.Fatal("server constructor accessed database")
        return nil, nil
    })
    ca := x509.NewCertPool()
    cert := tls.Certificate{Certificate: [][]byte{{1}}} // constructor-only sentinel
    server, err := NewAgentMTLSServer("127.0.0.1:9443", db, cert, ca)
    if err != nil { t.Fatal(err) }
    if server.Addr != "127.0.0.1:9443" || server.Handler == nil || server.TLSConfig == nil {
        t.Fatal("agent listener missing address, guard, or TLS config")
    }
    if server.TLSConfig.MinVersion != tls.VersionTLS13 ||
        server.TLSConfig.ClientAuth != tls.RequireAndVerifyClientCert ||
        server.TLSConfig.ClientCAs != ca ||
        len(server.TLSConfig.Certificates) != 1 {
        t.Fatal("agent listener does not enforce approved TLS 1.3 mutual authentication")
    }
    if server.ReadHeaderTimeout != 5*time.Second ||
        server.ReadTimeout != 15*time.Second ||
        server.WriteTimeout != 15*time.Second ||
        server.IdleTimeout != 45*time.Second ||
        server.MaxHeaderBytes != 16<<10 {
        t.Fatal("agent listener resource limits were weakened")
    }
}

func TestAgentScanQueueRequiresGuard(t *testing.T) {
    // No TLS identity and no context principal: handler denies before SQL.
    h := AgentHTTPGuard(PostgresAgentIdentityRegistry{}, AgentScanQueueHandler(PostgresScanJobQueue{}))
    w := httptest.NewRecorder()
    h.ServeHTTP(w, httptest.NewRequest(http.MethodPost,
        "/agent/v1/tenants/tenantA/agents/win01/scan-jobs/claim", nil))
    if w.Code != http.StatusUnauthorized {
        t.Fatalf("unauthenticated request status %d", w.Code)
    }
}
