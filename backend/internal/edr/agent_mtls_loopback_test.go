package edr

import (
    "crypto/tls"
    "crypto/x509"
    "database/sql"
    "strings"
    "testing"
    "time"
)

// The development listener must never become an externally reachable
// certificate/scan API merely because an environment variable was changed.
func TestAgentMTLSListenerRequiresLoopbackTCPAddress(t *testing.T) {
    now := time.Now().UTC()
    _, serverCert, clientCA := createTestAgentCertificate(t, now,
        []string{"spiffe://turansec.local/tenants/lab/agents/device"},
        []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
    db := &sql.DB{}
    for _, addr := range []string{
        "127.0.0.1:9443",
        "127.0.0.2:9443",
        "[::1]:9443",
    } {
        t.Run("accept_"+strings.ReplaceAll(addr, ":", "_"), func(t *testing.T) {
            srv, err := NewAgentMTLSServer(addr, db, serverCert, clientCA)
            if err != nil || srv == nil {
                t.Fatalf("valid loopback %q failed: server=%v err=%v", addr, srv, err)
            }
            if srv.Addr != addr || srv.TLSConfig.MinVersion != tls.VersionTLS13 ||
                srv.TLSConfig.ClientAuth != tls.RequireAndVerifyClientCert {
                t.Fatal("listener lost TLS/client-certificate invariant")
            }
        })
    }
    for _, addr := range []string{
        "", ":9443", "127.0.0.1:", "127.0.0.1:0",
        "127.0.0.1:-1", "127.0.0.1:65536", "127.0.0.1:bad",
        "0.0.0.0:9443", "[::]:9443", "192.168.1.10:9443",
        "10.0.0.7:9443", "8.8.8.8:9443", "[2001:db8::1]:9443",
        "localhost:9443", "turansec.example:9443", "not-an-address",
    } {
        t.Run("reject_"+strings.ReplaceAll(addr, ":", "_"), func(t *testing.T) {
            srv, err := NewAgentMTLSServer(addr, db, serverCert, clientCA)
            if err == nil || srv != nil {
                t.Fatalf("unsafe listener address %q accepted: server=%v err=%v", addr, srv, err)
            }
        })
    }
}
