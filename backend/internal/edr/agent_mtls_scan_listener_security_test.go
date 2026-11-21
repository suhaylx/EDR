package edr

import (
    "crypto/tls"
    "crypto/x509"
    "database/sql"
    "strings"
    "testing"
    "time"
)

// TestIntegratedAgentListenerFailClosed verifies the actual PostgreSQL scan
// listener constructor, not a separate auth-probe or development bearer API.
func TestIntegratedAgentListenerFailClosed(t *testing.T) {
    now := time.Now().UTC()
    _, serverCert, trusted := createTestAgentCertificate(t, now,
        []string{"spiffe://turansec.local/tenants/lab/agents/worker"},
        []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
    db := &sql.DB{}
    for _, addr := range []string{"127.0.0.1:9443", "127.0.0.2:9443", "[::1]:9443"} {
        t.Run("allow_"+strings.ReplaceAll(addr, ":", "_"),func(t *testing.T) {
            s,err:=NewAgentMTLSServer(addr,db,serverCert,trusted)
            if err!=nil || s==nil {t.Fatalf("valid lab listener rejected: %v",err)}
            if s.Addr!=addr || s.TLSConfig.MinVersion!=tls.VersionTLS13 ||
                s.TLSConfig.ClientAuth!=tls.RequireAndVerifyClientCert ||
                !s.TLSConfig.SessionTicketsDisabled {
                t.Fatal("agent listener lost strict TLS and client identity policy")
            }
        })
    }
    for _,addr:=range []string{
        "",":9443","localhost:9443","agent.example:9443",
        "0.0.0.0:9443","[::]:9443","192.168.1.10:9443",
        "10.12.1.1:9443","8.8.8.8:9443","[2001:db8::1234]:9443",
        "127.0.0.1:", "127.0.0.1:0","127.0.0.1:-1",
        "127.0.0.1:65536","127.0.0.1:bad","not-a-listener",
    }{
        t.Run("deny_"+strings.ReplaceAll(addr,":","_"),func(t *testing.T){
            server,err:=NewAgentMTLSServer(addr,db,serverCert,trusted)
            if err==nil||server!=nil {t.Fatalf("unsafe listener %q accepted",addr)}
        })
    }
    noKey:=serverCert
    noKey.PrivateKey=nil
    incomplete:=[]struct{
        name string
        db *sql.DB
        pair tls.Certificate
        ca *x509.CertPool
    }{
        {"no-db",nil,serverCert,trusted},
        {"nil-ca",db,serverCert,nil},
        {"empty-ca",db,serverCert,x509.NewCertPool()},
        {"no-key",db,noKey,trusted},
        {"no-cert",db,tls.Certificate{},trusted},
    }
    for _,tc:=range incomplete{
        t.Run(tc.name,func(t *testing.T){
            server,err:=NewAgentMTLSServer("127.0.0.1:9443",tc.db,tc.pair,tc.ca)
            if err==nil||server!=nil {t.Fatalf("%s should fail closed",tc.name)}
        })
    }
}
