package edr

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"database/sql/driver"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type transactionProbe struct {
	allowed, commitFail, authFail, began, committed, rolledBack bool
	args                                                        []driver.NamedValue
}
type probeConnector struct{ p *transactionProbe }
type probeDriver struct{ p *transactionProbe }
type probeConn struct{ p *transactionProbe }
type probeTx struct{ p *transactionProbe }

func (d probeDriver) Open(string) (driver.Conn, error)                            { return &probeConn{d.p}, nil }
func (c probeConnector) Connect(context.Context) (driver.Conn, error)             { return &probeConn{c.p}, nil }
func (c probeConnector) Driver() driver.Driver                                    { return probeDriver{c.p} }
func (c *probeConn) Prepare(string) (driver.Stmt, error)                          { return nil, errors.New("unsupported") }
func (c *probeConn) Close() error                                                 { return nil }
func (c *probeConn) Begin() (driver.Tx, error)                                    { c.p.began = true; return &probeTx{c.p}, nil }
func (c *probeConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) { return c.Begin() }
func (c *probeConn) QueryContext(_ context.Context, _ string, args []driver.NamedValue) (driver.Rows, error) {
	c.p.args = args
	if c.p.authFail {
		return nil, errors.New("private SQL detail")
	}
	return &scanRows{columns: []string{"allowed"}, values: [][]driver.Value{{c.p.allowed}}}, nil
}
func (t *probeTx) Commit() error {
	if t.p.commitFail {
		return errors.New("private commit failure")
	}
	t.p.committed = true
	return nil
}
func (t *probeTx) Rollback() error { t.p.rolledBack = true; return nil }

func TestCertificateTransactionHoldsResponseUntilCommit(t *testing.T) {
	for _, tc := range []struct {
		name                        string
		allow, commitFail, authFail bool
		handlerCode                 int
		body                        string
		want                        int
		handler                     bool
	}{
		{"success", true, false, false, 201, "lease-fixture", 201, true},
		{"commit failure", true, true, false, 201, "lease-fixture", 503, true},
		{"auth deny", false, false, false, 201, "lease-fixture", 401, false},
		{"auth failure", true, false, true, 201, "lease-fixture", 503, false},
		{"handler denial", true, false, false, 409, "conflict", 409, true},
		{"overflow", true, false, false, 201, strings.Repeat("x", 65537), 503, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &transactionProbe{allowed: tc.allow, commitFail: tc.commitFail, authFail: tc.authFail}
			db := sql.OpenDB(probeConnector{p})
			defer db.Close()
			req := httptest.NewRequest("POST", "https://127.0.0.1/", strings.NewReader(`{}`))
			leaf := &x509.Certificate{Raw: []byte("verified-test-leaf"), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
			req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
			writer := httptest.NewRecorder()
			called := false
			certificateTransaction(writer, req, db, "authorization", []any{"tenant", "operator", "scanner"}, func(tx *sql.Tx) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					called = true
					if writer.Body.Len() != 0 || p.committed {
						t.Error("response/commit escaped before handler result")
					}
					w.WriteHeader(tc.handlerCode)
					_, _ = w.Write([]byte(tc.body))
				})
			})
			if writer.Code != tc.want || called != tc.handler {
				t.Fatalf("status=%d handler=%v", writer.Code, called)
			}
			digest := sha256.Sum256(leaf.Raw)
			if len(p.args) != 4 || p.args[0].Value != "tenant" || p.args[1].Value != "operator" || p.args[3].Value != "scanner" || string(p.args[2].Value.([]byte)) != string(digest[:]) {
				t.Fatal("certificate authorization binding/order incorrect")
			}
			if tc.want == 503 && (strings.Contains(writer.Body.String(), "lease-fixture") || strings.Contains(writer.Body.String(), "private")) {
				t.Fatal("failed transaction disclosed private result")
			}
			if (tc.want == 201) != p.committed {
				t.Fatal("success not coupled to commit")
			}
			if tc.want != 201 && !tc.commitFail && !p.rolledBack {
				t.Fatal("failed transaction was not rolled back")
			}
		})
	}
}

func TestCertificateTransactionRejectsLargeBodyBeforeLocks(t *testing.T) {
	p := &transactionProbe{allowed: true}
	db := sql.OpenDB(probeConnector{p})
	defer db.Close()
	req := httptest.NewRequest("POST", "https://127.0.0.1/", strings.NewReader(strings.Repeat("x", 8193)))
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Raw: []byte("leaf"), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}}}
	w := httptest.NewRecorder()
	certificateTransaction(w, req, db, "authorization", []any{"tenant", "agent"}, func(*sql.Tx) http.Handler { t.Fatal("large body reached transaction"); return nil })
	if w.Code != 413 || p.began {
		t.Fatal("body read acquired authorization locks")
	}
}

func TestCertificateTransactionPanicRollsBackWithoutResponse(t *testing.T) {
	p := &transactionProbe{allowed: true}
	db := sql.OpenDB(probeConnector{p})
	defer db.Close()
	req := httptest.NewRequest("POST", "https://127.0.0.1/", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Raw: []byte("leaf"), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}}}
	w := httptest.NewRecorder()
	defer func() {
		if recover() == nil || !p.rolledBack || p.committed || w.Body.Len() != 0 {
			t.Error("panic did not rollback an undisclosed response")
		}
	}()
	certificateTransaction(w, req, db, "authorization", []any{"tenant", "agent"}, func(*sql.Tx) http.Handler {
		return http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("fixture") })
	})
}
