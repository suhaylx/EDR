package edr

import (
    "crypto/tls"
    "crypto/x509"
    "database/sql"
    "net/http"
    "strings"
    "testing"
    "time"
)

func TestAgentMTLSServerRejectsUnconfiguredTrust(t *testing.T) {
    db := &sql.DB{}
    pool := x509.NewCertPool()
    cert := tls.Certificate{Certificate: [][]byte{{1}}, PrivateKey: "test-key"}
    tests := []struct {
        name string
        db *sql.DB
        cert tls.Certificate
        pool *x509.CertPool
    }{
        {"nil-db", nil, cert, pool},
        {"missing-client-ca", db, cert, nil},
        {"empty-client-ca", db, cert, pool},
        {"missing-server-key", db, tls.Certificate{Certificate: [][]byte{{1}}}, pool},
        {"missing-server-certificate", db, tls.Certificate{PrivateKey: "test-key"}, pool},
    }
    for _, tc := range tests {
        t.Run(tc.name, func(t *testing.T) {
            srv, err := NewAgentMTLSServer("127.0.0.1:9443",tc.db,tc.cert,tc.pool)
            if err == nil || srv != nil { t.Fatalf("expected fail-closed setup; server=%v, err=%v",srv,err) }
        })
    }
}

func TestAgentMTLSServerTLSConfiguration(t *testing.T) {
    db := &sql.DB{}
    now := time.Now().UTC().Truncate(time.Second)
    _, serverCert, _ := createTestAgentCertificate(t, now,
        []string{"spiffe://turansec.local/tenants/lab/agents/endpoint"}, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
    _,_,trusted := createTestAgentCertificate(t, now,
        []string{"spiffe://turansec.local/tenants/lab/agents/worker"}, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
    srv,err:=NewAgentMTLSServer("127.0.0.1:9443",db,serverCert,trusted)
    if err!=nil {t.Fatal(err)}
    if srv.TLSConfig.MinVersion!=tls.VersionTLS13 ||
        srv.TLSConfig.ClientAuth!=tls.RequireAndVerifyClientCert ||
        !srv.TLSConfig.SessionTicketsDisabled {
        t.Fatal("agent listener must mandate TLS 1.3, verified client certificates and no session tickets")
    }
    req,err:=http.NewRequest(http.MethodGet,"https://localhost/agent/v1/tenants/lab/agents/worker/scan-jobs/claim",strings.NewReader(""))
    if err!=nil {t.Fatal(err)}
    recorder:=newRecordingResponseWriter()
    srv.Handler.ServeHTTP(recorder,req)
    if recorder.statusCode != http.StatusUnauthorized {t.Fatalf("unauthenticated request status %d",recorder.statusCode)}
}

type recordingResponseWriter struct {
    header http.Header
    statusCode int
}
func newRecordingResponseWriter() *recordingResponseWriter { return &recordingResponseWriter{header:make(http.Header)} }
func (w *recordingResponseWriter) Header() http.Header { return w.header }
func (w *recordingResponseWriter) Write(p []byte)(int,error){if w.statusCode==0{w.statusCode=200};return len(p),nil}
func (w *recordingResponseWriter) WriteHeader(status int){w.statusCode=status}
