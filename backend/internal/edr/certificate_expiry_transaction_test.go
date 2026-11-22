package edr

import (
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCertificateTransactionRechecksActualLeafAfterSQLAuthorization(t *testing.T) {
	p := &transactionProbe{allowed: true}
	db := sql.OpenDB(probeConnector{p})
	defer db.Close()
	req := httptest.NewRequest("POST", "https://127.0.0.1/", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Raw: []byte("expired-peer"), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(-time.Second)}}}
	w := httptest.NewRecorder()
	certificateTransaction(w, req, db, "authorization", []any{"tenant", "operator", "viewer"}, func(*sql.Tx) http.Handler {
		t.Fatal("expired TLS leaf reached mutation after database authorization")
		return nil
	})
	if w.Code != 401 || !p.began || !p.rolledBack || p.committed {
		t.Fatal("expired certificate did not fail closed in authorization transaction")
	}
}
