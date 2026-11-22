package edr

import (
    "crypto/x509"
    "testing"
    "time"
)

func TestVerifyIssuedAgentCertificateChainRejectsUntrustedIssuer(t *testing.T){
    now:=time.Now().UTC()
    leaf,_,trustedPool:=createTestAgentCertificate(t,now,
        []string{"spiffe://turansec.local/tenants/tenantA/agents/win01"},
        []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
    if err:=VerifyIssuedAgentCertificateChain(leaf.Raw,trustedPool,nil,now);err!=nil{
        t.Fatalf("trusted client certificate rejected: %v",err)
    }
    if err:=VerifyIssuedAgentCertificateChain(leaf.Raw,x509.NewCertPool(),nil,now);err==nil{
        t.Fatal("untrusted agent issuer accepted")
    }
    if err:=VerifyIssuedAgentCertificateChain(leaf.Raw,nil,nil,now);err==nil{
        t.Fatal("missing controlled CA pool accepted")
    }
    if err:=VerifyIssuedAgentCertificateChain(leaf.Raw,trustedPool,nil,now.Add(48*time.Hour));err==nil{
        t.Fatal("expired certificate chain accepted")
    }
}
