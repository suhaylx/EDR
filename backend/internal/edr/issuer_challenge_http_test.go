package edr

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

type captureChallengeIssuer struct {
	mu     sync.Mutex
	calls  int
	tenant string
	agent  string
	actor  string
	ttl    int
	deny   bool
	err    error
	challenge *IssuedEnrollmentChallenge
}

func (s *captureChallengeIssuer) IssueEnrollmentChallenge(
	_ context.Context, tenant, agent, actor string, ttl int,
) (*IssuedEnrollmentChallenge, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	s.tenant,s.agent,s.actor,s.ttl=tenant,agent,actor,ttl
	if s.err!=nil {return nil,s.err}
	if s.deny {return nil,nil}
	return s.challenge,nil
}

func TestIssuerChallengeRealTLSAndTenantGrant(t *testing.T) {
	fixture:=newIssuerTestSetup(t)
	var secret [32]byte
	copy(secret[:],fixture.challengeSecret)
	issuer:=&captureChallengeIssuer{challenge:&IssuedEnrollmentChallenge{
		ChallengeID:fixture.challengeID,ChallengeSecret:secret,TTLSeconds:300,
	}}
	handler,err:=NewIssuerProvisioningHandler(fixture.store,issuer,
		fixture.agentRoots,nil,[]TrustedEnrollmentIssuer{{
			ClientCertificateFingerprintSHA256:sha256.Sum256(fixture.issuerTLS.Leaf.Raw),
			TenantID:"tenantA",ActorID:"trusted-issuer",
		}})
	if err!=nil {t.Fatal(err)}
	server:=httptest.NewUnstartedServer(handler)
	server.TLS=&tls.Config{
		MinVersion:tls.VersionTLS13,
		ClientAuth:tls.RequireAndVerifyClientCert,
		ClientCAs:fixture.issuerRoots,
	}
	server.StartTLS()
	defer server.Close()
	transport:=server.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig=transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.Certificates=[]tls.Certificate{fixture.issuerTLS}
	client:=&http.Client{Transport:transport}
	defer transport.CloseIdleConnections()

	post:=func(client *http.Client,path,body string)(int,string){
		t.Helper()
		req,err:=http.NewRequest(http.MethodPost,server.URL+path,strings.NewReader(body))
		if err!=nil {t.Fatal(err)}
		req.Header.Set("Content-Type","application/json")
		req.Header.Set("X-Actor-ID","spoofed-actor")
		req.Header.Set("X-Tenant-ID","tenantB")
		resp,err:=client.Do(req)
		if err!=nil {t.Fatal(err)}
		defer resp.Body.Close()
		var buffer bytes.Buffer
		_,_=buffer.ReadFrom(resp.Body)
		return resp.StatusCode,buffer.String()
	}
	path:="/issuer/v1/tenants/tenantA/agents/win01/enroll/challenge"
	status,response:=post(client,path,`{"ttl_seconds":300}`)
	if status!=http.StatusOK {
		t.Fatalf("issue challenge: status %d response %s",status,response)
	}
	var received struct{
		ChallengeID string `json:"challenge_id"`
		ChallengeSecret string `json:"challenge_secret"`
		TTLSeconds int `json:"ttl_seconds"`
	}
	if err:=json.Unmarshal([]byte(response),&received);err!=nil {t.Fatal(err)}
	decoded,err:=base64.StdEncoding.DecodeString(received.ChallengeSecret)
	if err!=nil || !bytes.Equal(decoded,fixture.challengeSecret) ||
		received.ChallengeID!=fixture.challengeID || received.TTLSeconds!=300 {
		t.Fatal("challenge was not delivered as authenticated base64 secret")
	}
	issuer.mu.Lock()
	if issuer.calls!=1||issuer.tenant!="tenantA"||issuer.agent!="win01"||
		issuer.actor!="trusted-issuer"||issuer.ttl!=300 {
		t.Fatalf("issuer identity parameters not pinned: %+v",issuer)
	}
	issuer.mu.Unlock()
	if status,_:=post(client,
		"/issuer/v1/tenants/tenantB/agents/win01/enroll/challenge",
		`{"ttl_seconds":300}`);status!=http.StatusForbidden {
		t.Fatalf("cross-tenant issuer grant accepted: %d",status)
	}
	if status,_:=post(client,
		"/issuer/v1/tenants/tenantA/agents/win01/enroll/challenge",
		`{"ttl_seconds":601}`);status!=http.StatusBadRequest {
		t.Fatalf("unbounded TTL accepted: %d",status)
	}
	if status,_:=post(client,path,`{"ttl_seconds":300,"actor_id":"attacker"}`);
		status!=http.StatusBadRequest{
		t.Fatalf("client-defined actor accepted: %d",status)
	}
	if status,_:=post(client,path,`{"ttl_seconds":300}{}`);
		status!=http.StatusBadRequest{
		t.Fatalf("trailing JSON accepted: %d",status)
	}
	if status,_:=post(client,path,`{"ttl_seconds":300,"pad":"`+strings.Repeat("x",2000)+`"}`);
		status!=http.StatusBadRequest{
		t.Fatalf("oversized request accepted: %d",status)
	}
	if status,_:=post(client,"/issuer/v1/tenants/tenantA/agents/win01/secret",
		`{"ttl_seconds":300}`);status!=http.StatusNotFound{
		t.Fatalf("unexpected issuer operation accepted: %d",status)
	}
	if status,_:=post(client,path,`{"ttl_seconds":300}`);status!=http.StatusOK {
		t.Fatalf("second allowed request failed for mocked store: %d",status)
	}
	// Real PostgreSQL single-outstanding index denies the second issuance.
	// The mock explicitly simulates its false result here.
	issuer.mu.Lock()
	issuer.deny=true
	issuer.mu.Unlock()
	if status,_:=post(client,path,`{"ttl_seconds":300}`);status!=http.StatusConflict{
		t.Fatalf("existing challenge not denied: %d",status)
	}
	issuer.mu.Lock()
	issuer.deny=false
	issuer.err=errors.New("secret db connection string")
	issuer.mu.Unlock()
	if status,body:=post(client,path,`{"ttl_seconds":300}`);status!=http.StatusServiceUnavailable||
		strings.Contains(body,"connection string") {
		t.Fatalf("DB outage leaked or authorized: %d %s",status,body)
	}

	// No issuer certificate: TLS handshake failure, not an HTTP fallback.
	req,err:=http.NewRequest(http.MethodPost,server.URL+path,
		strings.NewReader(`{"ttl_seconds":300}`))
	if err!=nil {t.Fatal(err)}
	req.Header.Set("Content-Type","application/json")
	resp,err:=server.Client().Do(req)
	if err==nil {
		resp.Body.Close()
		t.Fatalf("mTLS challenge endpoint accepted no cert: %d",resp.StatusCode)
	}
}

func TestIssuerChallengeRejectsMissingTrustConfiguration(t *testing.T){
	fixture:=newIssuerTestSetup(t)
	issuer:=&captureChallengeIssuer{}
	valid:=TrustedEnrollmentIssuer{
		ClientCertificateFingerprintSHA256:sha256.Sum256(fixture.issuerTLS.Leaf.Raw),
		TenantID:"tenantA",ActorID:"trusted-issuer",
	}
	if _,err:=NewIssuerChallengeHandler(nil,[]TrustedEnrollmentIssuer{valid});err==nil{
		t.Fatal("missing DB store accepted")
	}
	if _,err:=NewIssuerChallengeHandler(issuer,nil);err==nil{
		t.Fatal("empty issuer allowlist accepted")
	}
	duplicate:=[]TrustedEnrollmentIssuer{valid,valid}
	if _,err:=NewIssuerChallengeHandler(issuer,duplicate);err==nil{
		t.Fatal("duplicate authorization accepted")
	}
	bad:=valid
	bad.ClientCertificateFingerprintSHA256=[32]byte{}
	if _,err:=NewIssuerChallengeHandler(issuer,[]TrustedEnrollmentIssuer{bad});err==nil{
		t.Fatal("empty issuer fingerprint accepted")
	}
}
