package edr

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

type testIdentityRegistry struct {
	record EnrolledAgentCertificate
	err    error
}

func (r testIdentityRegistry) LookupAgentCertificate(_ context.Context, tenant, agent string) (EnrolledAgentCertificate, error) {
	if r.err != nil {
		return EnrolledAgentCertificate{}, r.err
	}
	if tenant != r.record.Identity.TenantID || agent != r.record.Identity.AgentID {
		return EnrolledAgentCertificate{}, ErrAgentNotEnrolled
	}
	return r.record, nil
}

func createTestAgentCertificate(t *testing.T, now time.Time, sans []string, eku []x509.ExtKeyUsage) (*x509.Certificate, tls.Certificate, *x509.CertPool) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil { t.Fatal(err) }
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "TuranSec Test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil { t.Fatal(err) }
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil { t.Fatal(err) }
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil { t.Fatal(err) }
	uris := make([]*url.URL, 0, len(sans))
	for _, value := range sans {
		u, err := url.Parse(value)
		if err != nil { t.Fatal(err) }
		uris = append(uris, u)
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "untrusted-cn"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Minute),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: eku, URIs: uris,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, caCert, &key.PublicKey, caKey)
	if err != nil { t.Fatal(err) }
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil { t.Fatal(err) }
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return leafCert, tls.Certificate{Certificate: [][]byte{leafDER, caDER}, PrivateKey: key, Leaf: leafCert}, pool
}

func TestAgentIdentityFromVerifiedCertificate(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	san := "spiffe://turansec.local/tenants/customer-1/agents/device-1"
	cert, _, _ := createTestAgentCertificate(t, now, []string{san}, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	identity := AgentIdentity{TenantID: "customer-1", AgentID: "device-1"}
	record := EnrolledAgentCertificate{Identity: identity, FingerprintSHA256: sha256.Sum256(cert.Raw)}
	verified := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}
	got, err := VerifyAgentCertificate(context.Background(), verified, testIdentityRegistry{record: record}, now)
	if err != nil || got != identity { t.Fatalf("valid registered client got %+v err=%v", got, err) }

	cases := []struct{
		name string
		state *tls.ConnectionState
		record EnrolledAgentCertificate
		err error
		when time.Time
		wantErr error
	}{
		{name: "no-tls", state: nil, record: record, when: now, wantErr: ErrAgentUnauthenticated},
		{name: "unverified-chain", state: &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}, record: record, when: now, wantErr: ErrAgentUnauthenticated},
		{name: "empty-verified-chain", state: &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{}}}, record: record, when: now, wantErr: ErrAgentUnauthenticated},
		{name: "wrong-tenant", state: verified, record: EnrolledAgentCertificate{Identity: AgentIdentity{TenantID: "other", AgentID: "device-1"}, FingerprintSHA256: record.FingerprintSHA256}, when: now, wantErr: ErrAgentUnauthenticated},
		{name: "wrong-fingerprint", state: verified, record: EnrolledAgentCertificate{Identity: identity}, when: now, wantErr: ErrAgentUnauthenticated},
		{name: "revoked", state: verified, record: EnrolledAgentCertificate{Identity: identity, FingerprintSHA256: record.FingerprintSHA256, Revoked: true}, when: now, wantErr: ErrAgentUnauthenticated},
		{name: "not-yet-valid", state: verified, record: record, when: now.Add(-2*time.Hour), wantErr: ErrAgentUnauthenticated},
		{name: "expired", state: verified, record: record, when: now.Add(2*time.Hour), wantErr: ErrAgentUnauthenticated},
		{name: "registry-down", state: verified, record: record, err: errors.New("database unavailable"), when: now, wantErr: ErrAgentRegistryUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T){
			_, err := VerifyAgentCertificate(context.Background(), tc.state, testIdentityRegistry{record: tc.record, err: tc.err}, tc.when)
			if !errors.Is(err,tc.wantErr) { t.Fatalf("got err=%v want=%v",err,tc.wantErr) }
		})
	}
}

func TestAgentIdentityRejectsAmbiguousOrWrongPurposeCertificates(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	valid := "spiffe://turansec.local/tenants/alpha/agents/win01"
	cases := []struct{name string; sans []string; eku []x509.ExtKeyUsage}{
		{"no-san", nil, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}},
		{"duplicate-san", []string{valid,"spiffe://turansec.local/tenants/beta/agents/win01"}, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}},
		{"wrong-trust-domain", []string{"spiffe://other.local/tenants/alpha/agents/win01"}, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}},
		{"encoded-agent", []string{"spiffe://turansec.local/tenants/alpha/agents/%77in01"}, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}},
		{"dot-agent", []string{"spiffe://turansec.local/tenants/alpha/agents/.."}, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}},
		{"unexpected-segment", []string{"spiffe://turansec.local/tenants/alpha/groups/one"}, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}},
		{"server-cert", []string{valid}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}},
	}
	for _, tc := range cases {
		t.Run(tc.name,func(t *testing.T){
			cert,_,_ := createTestAgentCertificate(t,now,tc.sans,tc.eku)
			state := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}
			record := EnrolledAgentCertificate{Identity: AgentIdentity{TenantID:"alpha",AgentID:"win01"}, FingerprintSHA256:sha256.Sum256(cert.Raw)}
			if _,err:=VerifyAgentCertificate(context.Background(),state,testIdentityRegistry{record:record},now);!errors.Is(err,ErrAgentUnauthenticated){t.Fatalf("should reject %s: %v",tc.name,err)}
		})
	}
}

func TestRealMutualTLSHandshakeBindsRegisteredAgent(t *testing.T){
	now := time.Now().UTC().Truncate(time.Second)
	cert,clientCert,pool := createTestAgentCertificate(t,now,[]string{"spiffe://turansec.local/tenants/tenantA/agents/linuxA"},[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	identity := AgentIdentity{TenantID:"tenantA",AgentID:"linuxA"}
	registry := testIdentityRegistry{record:EnrolledAgentCertificate{Identity:identity,FingerprintSHA256:sha256.Sum256(cert.Raw)}}
	h := http.HandlerFunc(func(w http.ResponseWriter,req *http.Request){
		got,err:=VerifyAgentCertificate(req.Context(),req.TLS,registry,time.Now())
		if err!=nil||got!=identity {http.Error(w,"unverified",http.StatusUnauthorized);return}
		w.WriteHeader(http.StatusNoContent)
	})
	server:=httptest.NewUnstartedServer(h)
	server.TLS=&tls.Config{MinVersion:tls.VersionTLS13,ClientAuth:tls.RequireAndVerifyClientCert,ClientCAs:pool}
	server.StartTLS()
	defer server.Close()
	transport:=server.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig=transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.Certificates=[]tls.Certificate{clientCert}
	client:=&http.Client{Transport:transport}
	defer transport.CloseIdleConnections()
	resp,err:=client.Get(server.URL)
	if err!=nil {t.Fatal(err)}
	defer resp.Body.Close()
	if resp.StatusCode!=http.StatusNoContent {t.Fatalf("mTLS client got %d",resp.StatusCode)}
	resp2,err:=server.Client().Get(server.URL)
	if err==nil {resp2.Body.Close();t.Fatal("connection without client certificate should be rejected")}
}
