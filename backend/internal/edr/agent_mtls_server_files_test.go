package edr

import (
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewAgentMTLSServerFromFilesRequiresValidCAAndDatabase(t *testing.T) {
	now := time.Now().UTC()
	certPEM, keyPEM := makeTestTLSCert(t, now.Add(-time.Hour), now.Add(time.Hour), false, x509.ExtKeyUsageServerAuth)
	caPEM, _ := makeTestTLSCert(t, now.Add(-time.Hour), now.Add(time.Hour), true, x509.ExtKeyUsageClientAuth)
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	certFile, keyFile, caFile := write("server.pem", certPEM), write("server.key", keyPEM), write("agents-ca.pem", caPEM)
	srv, err := NewAgentMTLSServerFromFiles("127.0.0.1:9443", &sql.DB{}, certFile, keyFile, caFile, now)
	if err != nil {
		t.Fatal(err)
	}
	if srv == nil || srv.TLSConfig.MinVersion != tls.VersionTLS13 ||
		srv.TLSConfig.ClientAuth != tls.RequireAndVerifyClientCert ||
		srv.TLSConfig.ClientCAs == nil {
		t.Fatal("listener must use strictly verified agent mTLS")
	}
	if srv.Addr != "127.0.0.1:9443" {
		t.Fatal("unexpected listener address")
	}
	if got, err := NewAgentMTLSServerFromFiles("127.0.0.1:9443", nil, certFile, keyFile, caFile, now); got != nil || err == nil {
		t.Fatal("must not start without a database")
	}
	if got, err := NewAgentMTLSServerFromFiles("127.0.0.1:9443", &sql.DB{}, certFile, keyFile, write("invalid-ca.pem", certPEM), now); got != nil || err == nil {
		t.Fatal("must not start with untrusted non-CA client roots")
	}
}
