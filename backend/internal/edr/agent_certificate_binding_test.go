package edr

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/x509"
    "net/url"
    "testing"
    "time"
)

// An issued certificate must contain the same key as the CSR that passed
// proof-of-possession; merely matching the URI SAN is insufficient.
func TestValidateIssuedCertificateForCSRRejectsKeySubstitution(t *testing.T){
    now:=time.Now().UTC()
    leaf,_,_:=createTestAgentCertificate(t,now,
        []string{"spiffe://turansec.local/tenants/tenantA/agents/win01"},
        []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
    otherKey,err:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader)
    if err!=nil{t.Fatal(err)}
    uri,_:=url.Parse("spiffe://turansec.local/tenants/tenantA/agents/win01")
    csr,err:=x509.CreateCertificateRequest(rand.Reader,
        &x509.CertificateRequest{URIs:[]*url.URL{uri}},otherKey)
    if err!=nil{t.Fatal(err)}
    identity:=AgentIdentity{TenantID:"tenantA",AgentID:"win01"}
    if _,err:=ValidateIssuedCertificateForCSR(csr,leaf.Raw,identity,now);err==nil{
        t.Fatal("accepted certificate with key different from signed CSR")
    }
}
