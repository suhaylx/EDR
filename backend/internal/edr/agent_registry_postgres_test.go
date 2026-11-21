package edr

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"strings"
	"testing"
)

type fakeEnrollmentDriver struct{}
func (fakeEnrollmentDriver) Open(string) (driver.Conn, error) { return nil, errors.New("use connector") }

type fakeEnrollmentConnector struct{ conn *fakeEnrollmentConn }
func (c fakeEnrollmentConnector) Connect(context.Context) (driver.Conn, error) { return c.conn, nil }
func (fakeEnrollmentConnector) Driver() driver.Driver { return fakeEnrollmentDriver{} }

type fakeEnrollmentConn struct {
	tenant, agent string
	fingerprint []byte
	missing bool
	queryError error
	calls int
}
func (*fakeEnrollmentConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("unexpected prepare") }
func (*fakeEnrollmentConn) Close() error { return nil }
func (*fakeEnrollmentConn) Begin() (driver.Tx, error) { return nil, errors.New("unexpected transaction") }
func (c *fakeEnrollmentConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	c.calls++
	if query != lookupAgentCertificateSQL || len(args) != 2 || args[0].Value != c.tenant || args[1].Value != c.agent {
		return nil, errors.New("wrong or unparameterized tenant/device query")
	}
	if c.queryError != nil { return nil, c.queryError }
	if c.missing { return &fakeEnrollmentRows{empty:true}, nil }
	return &fakeEnrollmentRows{fingerprint:c.fingerprint}, nil
}

type fakeEnrollmentRows struct { fingerprint []byte; empty, returned bool }
func (*fakeEnrollmentRows) Columns() []string { return []string{"fingerprint_sha256"} }
func (*fakeEnrollmentRows) Close() error { return nil }
func (r *fakeEnrollmentRows) Next(dest []driver.Value) error {
	if r.empty || r.returned { return io.EOF }
	r.returned=true
	dest[0]=append([]byte(nil),r.fingerprint...)
	return nil
}

func TestPostgresAgentIdentityRegistry(t *testing.T) {
	fingerprint:=make([]byte,32)
	for i:=range fingerprint {fingerprint[i]=byte(i+1)}
	cases:=[]struct{
		name string
		fingerprint []byte
		missing bool
		queryError error
		tenant,agent string
		want error
		expectQueries int
	}{
		{name:"active-certificate",tenant:"tenantA",agent:"win01",fingerprint:fingerprint,expectQueries:1},
		{name:"not-enrolled",tenant:"tenantA",agent:"win01",missing:true,want:ErrAgentNotEnrolled,expectQueries:1},
		{name:"db-unavailable",tenant:"tenantA",agent:"win01",queryError:errors.New("network error"),want:ErrAgentRegistryUnavailable,expectQueries:1},
		{name:"corrupt-fingerprint",tenant:"tenantA",agent:"win01",fingerprint:[]byte{1,2,3},want:ErrAgentRegistryUnavailable,expectQueries:1},
		{name:"empty-fingerprint",tenant:"tenantA",agent:"win01",fingerprint:nil,want:ErrAgentRegistryUnavailable,expectQueries:1},
		{name:"invalid-tenant",tenant:"../tenantA",agent:"win01",want:ErrAgentNotEnrolled},
		{name:"invalid-agent",tenant:"tenantA",agent:"..",want:ErrAgentNotEnrolled},
		{name:"empty-id",tenant:"",agent:"win01",want:ErrAgentNotEnrolled},
	}
	for _,tc:=range cases {
		t.Run(tc.name,func(t *testing.T){
			conn:=&fakeEnrollmentConn{tenant:tc.tenant,agent:tc.agent,fingerprint:tc.fingerprint,missing:tc.missing,queryError:tc.queryError}
			db:=sql.OpenDB(fakeEnrollmentConnector{conn:conn})
			defer db.Close()
			record,err:=(PostgresAgentIdentityRegistry{DB:db}).LookupAgentCertificate(context.Background(),tc.tenant,tc.agent)
			if !errors.Is(err,tc.want){t.Fatalf("error %v want %v",err,tc.want)}
			if conn.calls!=tc.expectQueries{t.Fatalf("query calls %d want %d",conn.calls,tc.expectQueries)}
			if err==nil {
				if record.Identity!=(AgentIdentity{TenantID:tc.tenant,AgentID:tc.agent}){t.Fatalf("wrong identity %+v",record.Identity)}
				if string(record.FingerprintSHA256[:])!=string(fingerprint){t.Fatal("wrong fingerprint")}
				if record.Revoked{t.Fatal("active certificate marked revoked")}
			}
		})
	}
	if _,err:=(PostgresAgentIdentityRegistry{}).LookupAgentCertificate(context.Background(),"tenantA","win01");!errors.Is(err,ErrAgentRegistryUnavailable){t.Fatalf("nil DB: %v",err)}
}

func TestPostgresAgentIdentityRegistrySQLSafetyContract(t *testing.T) {
	query:=strings.ToLower(lookupAgentCertificateSQL)
	for _,part:=range []string{"where c.tenant_id = $1 and c.agent_id = $2","c.revoked_at is null","a.revoked_at is null","t.disabled_at is null","join edr_agents","join edr_tenants"} {
		if !strings.Contains(query,part){t.Errorf("missing predicate %q",part)}
	}
}
