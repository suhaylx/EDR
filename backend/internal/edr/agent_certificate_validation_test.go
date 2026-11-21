package edr

import (
    "crypto/rand"
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/x509"
    "crypto/x509/pkix"
    "net/url"
    "testing"
    "time"
)

func TestValidateAgentCSRProofOfPossessionAndIdentity(t *testing.T){
    key,err:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader)
    if err!=nil{t.Fatal(err)}
    identity:=AgentIdentity{TenantID:"tenantA",AgentID:"win01"}
    uri,_:=url.Parse("spiffe://turansec.local/tenants/tenantA/agents/win01")
    csrDER,err:=x509.CreateCertificateRequest(rand.Reader,&x509.CertificateRequest{
        Subject:pkix.Name{CommonName:"untrusted-cn"},URIs:[]*url.URL{uri},
    },key)
    if err!=nil{t.Fatal(err)}
    fp,err:=ValidateAgentCSR(csrDER,identity)
    if err!=nil||fp==([32]byte{}){t.Fatalf("valid signed CSR rejected: %v",err)}
    if _,err:=ValidateAgentCSR(csrDER,AgentIdentity{TenantID:"tenantB",AgentID:"win01"});err==nil{
        t.Fatal("cross-tenant CSR accepted")
    }
    tampered:=append([]byte(nil),csrDER...)
    tampered[len(tampered)-1]^=0xff
    if _,err:=ValidateAgentCSR(tampered,identity);err==nil{
        t.Fatal("tampered CSR signature accepted")
    }
    dnsCSR,err:=x509.CreateCertificateRequest(rand.Reader,&x509.CertificateRequest{
        URIs:[]*url.URL{uri},DNSNames:[]string{"example.com"},
    },key)
    if err!=nil{t.Fatal(err)}
    if _,err:=ValidateAgentCSR(dnsCSR,identity);err==nil{
        t.Fatal("CSR with extra DNS SAN accepted")
    }
}

func TestValidateIssuedAgentCertificate(t *testing.T){
    now:=time.Now().UTC()
    leaf,_,_:=createTestAgentCertificate(t,now,
        []string{"spiffe://turansec.local/tenants/tenantA/agents/win01"},
        []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
    identity:=AgentIdentity{TenantID:"tenantA",AgentID:"win01"}
    fp,err:=ValidateIssuedAgentCertificate(leaf.Raw,identity,now)
    if err!=nil||fp==([32]byte{}){t.Fatalf("valid issued leaf rejected: %v",err)}
    if _,err:=ValidateIssuedAgentCertificate(leaf.Raw,AgentIdentity{TenantID:"tenantB",AgentID:"win01"},now);err==nil{
        t.Fatal("issued certificate accepted for wrong tenant")
    }
    if _,err:=ValidateIssuedAgentCertificate(leaf.Raw,identity,now.Add(48*time.Hour));err==nil{
        t.Fatal("expired issued certificate accepted")
    }
}
