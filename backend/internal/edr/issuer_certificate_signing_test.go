package edr

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"testing"
	"time"
)

func testAgentCASigningPolicy(t *testing.T, now time.Time) AgentCASigningPolicy {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil { t.Fatal(err) }
	caTemplate := &x509.Certificate{
		SerialNumber:big.NewInt(912),
		Subject:pkix.Name{CommonName:"TuranSec isolated test agent CA"},
		NotBefore:now.Add(-time.Hour),
		NotAfter:now.Add(48*time.Hour),
		IsCA:true, BasicConstraintsValid:true,
		KeyUsage:x509.KeyUsageCertSign|x509.KeyUsageCRLSign,
	}
	der,err:=x509.CreateCertificate(rand.Reader,caTemplate,caTemplate,&key.PublicKey,key)
	if err!=nil { t.Fatal(err) }
	ca,err:=x509.ParseCertificate(der)
	if err!=nil { t.Fatal(err) }
	pool:=x509.NewCertPool()
	pool.AddCert(ca)
	return AgentCASigningPolicy{
		CACertificate:ca,Signer:key,TrustRoots:pool,Validity:time.Hour,
	}
}

func testChallengeCSR(t *testing.T,identity AgentIdentity,challengeID string,secret []byte) []byte{
	t.Helper()
	key,err:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader)
	if err!=nil {t.Fatal(err)}
	serial,err:=EnrollmentCSRChallengeSerial(challengeID,identity,secret)
	if err!=nil {t.Fatal(err)}
	uri,_:=url.Parse("spiffe://turansec.local/tenants/"+identity.TenantID+"/agents/"+identity.AgentID)
	der,err:=x509.CreateCertificateRequest(rand.Reader,&x509.CertificateRequest{
		Subject:pkix.Name{SerialNumber:serial},URIs:[]*url.URL{uri},
	},key)
	if err!=nil {t.Fatal(err)}
	return der
}

func TestSignChallengeBoundAgentCertificateWithApprovedCA(t *testing.T){
	now:=time.Now().UTC().Truncate(time.Second)
	policy:=testAgentCASigningPolicy(t,now)
	id:=AgentIdentity{TenantID:"tenantA",AgentID:"win01"}
	challengeID:="11111111-1111-4111-8111-111111111111"
	secret:=[]byte("0123456789abcdef0123456789abcdef")
	csr:=testChallengeCSR(t,id,challengeID,secret)
	der,err:=SignChallengeBoundAgentCertificate(csr,id,challengeID,secret,policy,now)
	if err!=nil {t.Fatalf("valid CSR denied: %v",err)}
	leaf,err:=x509.ParseCertificate(der)
	if err!=nil {t.Fatal(err)}
	if leaf.IsCA||len(leaf.URIs)!=1||len(leaf.DNSNames)!=0||
		len(leaf.IPAddresses)!=0||len(leaf.EmailAddresses)!=0||
		len(leaf.ExtKeyUsage)!=1||leaf.ExtKeyUsage[0]!=x509.ExtKeyUsageClientAuth||
		leaf.KeyUsage!=x509.KeyUsageDigitalSignature ||
		leaf.NotAfter.Sub(leaf.NotBefore)!=time.Hour ||
		leaf.Subject.CommonName!="" {
		t.Fatalf("issued certificate has overbroad privileges: %+v",leaf)
	}
	if _,err:=ValidateTrustedIssuedCertificateForCSR(
		csr,der,id,policy.TrustRoots,nil,now);err!=nil{
		t.Fatalf("issued CA chain or subject key invalid: %v",err)
	}
	otherDER,err:=SignChallengeBoundAgentCertificate(csr,id,challengeID,secret,policy,now)
	if err!=nil {t.Fatal(err)}
	other,err:=x509.ParseCertificate(otherDER)
	if err!=nil {t.Fatal(err)}
	if leaf.SerialNumber.Cmp(other.SerialNumber)==0 {
		t.Fatal("certificate serial number reused")
	}
}

func TestAgentCASignerRejectsUntrustedChallengeOrSigner(t *testing.T){
	now:=time.Now().UTC().Truncate(time.Second)
	id:=AgentIdentity{TenantID:"tenantA",AgentID:"linux01"}
	challengeID:="22222222-2222-4222-8222-222222222222"
	secret:=[]byte("abcdef0123456789abcdef0123456789")
	csr:=testChallengeCSR(t,id,challengeID,secret)
	policy:=testAgentCASigningPolicy(t,now)
	testCases:=[]struct{
		name string
		id AgentIdentity
		challengeID string
		secret []byte
		policy AgentCASigningPolicy
		when time.Time
	}{
		{"wrong-tenant",AgentIdentity{TenantID:"tenantB",AgentID:"linux01"},challengeID,secret,policy,now},
		{"wrong-challenge-id",id,"33333333-3333-4333-8333-333333333333",secret,policy,now},
		{"wrong-challenge-secret",id,challengeID,[]byte("00000000000000000000000000000000"),policy,now},
		{"missing-signer",id,challengeID,secret,AgentCASigningPolicy{CACertificate:policy.CACertificate,TrustRoots:policy.TrustRoots,Validity:time.Hour},now},
		{"missing-roots",id,challengeID,secret,AgentCASigningPolicy{CACertificate:policy.CACertificate,Signer:policy.Signer,Validity:time.Hour},now},
		{"ttl-too-long",id,challengeID,secret,AgentCASigningPolicy{CACertificate:policy.CACertificate,Signer:policy.Signer,TrustRoots:policy.TrustRoots,Validity:25*time.Hour},now},
		{"ttl-too-short",id,challengeID,secret,AgentCASigningPolicy{CACertificate:policy.CACertificate,Signer:policy.Signer,TrustRoots:policy.TrustRoots,Validity:time.Second},now},
		{"expired-ca",id,challengeID,secret,policy,now.Add(72*time.Hour)},
		{"issuer-expiry-exceeded",id,challengeID,secret,AgentCASigningPolicy{CACertificate:policy.CACertificate,Signer:policy.Signer,TrustRoots:policy.TrustRoots,Validity:24*time.Hour},now.Add(36*time.Hour)},
	}
	otherCA:=testAgentCASigningPolicy(t,now)
	mismatched:=policy
	mismatched.Signer=otherCA.Signer
	testCases=append(testCases,struct{
		name string
		id AgentIdentity
		challengeID string
		secret []byte
		policy AgentCASigningPolicy
		when time.Time
	}{"mismatched-ca-key",id,challengeID,secret,mismatched,now})
	for _,tc:=range testCases{
		t.Run(tc.name,func(t *testing.T){
			issued,err:=SignChallengeBoundAgentCertificate(
				csr,tc.id,tc.challengeID,tc.secret,tc.policy,tc.when)
			if err==nil || len(issued)!=0 {
				t.Fatalf("unapproved certificate issued: %d bytes %v",len(issued),err)
			}
		})
	}
	_ = crypto.SHA256
}
