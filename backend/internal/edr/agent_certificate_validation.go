package edr

import (
    "crypto/sha256"
    "crypto/x509"
    "errors"
    "time"
)

// ValidateAgentCSR proves possession of the private key corresponding to a
// requested public key and enforces the exact agent URI SAN. It does NOT
// authenticate the requester or authorize certificate issuance.
// An authorized issuer must bind the challenge to this CSR and validate
// the issued certificate before invoking the enrollment database adapter.
func ValidateAgentCSR(der []byte, expected AgentIdentity)([32]byte,error){
    var empty [32]byte
    if !validQueueIdentity(expected.TenantID,expected.AgentID)||len(der)==0||len(der)>64*1024{
        return empty,errors.New("invalid agent certificate request")
    }
    csr,err:=x509.ParseCertificateRequest(der)
    if err!=nil||csr.CheckSignature()!=nil||len(csr.URIs)!=1||
        len(csr.DNSNames)!=0||len(csr.EmailAddresses)!=0||len(csr.IPAddresses)!=0{
        return empty,errors.New("invalid agent certificate request")
    }
    identity,ok:=parseAgentIdentityURI(csr.URIs[0])
    if !ok||identity!=expected{
        return empty,errors.New("agent certificate request identity mismatch")
    }
    return sha256.Sum256(csr.RawSubjectPublicKeyInfo),nil
}

// ValidateIssuedAgentCertificate checks the issued leaf's identity and
// validity before a trusted issuer records its fingerprint. Certificate
// signature/chain verification is the issuer's responsibility and MUST be
// performed independently with its controlled CA trust store.
func ValidateIssuedAgentCertificate(der []byte,expected AgentIdentity,now time.Time)([32]byte,error){
    var empty [32]byte
    if !validQueueIdentity(expected.TenantID,expected.AgentID)||len(der)==0||len(der)>64*1024{
        return empty,errors.New("invalid issued certificate")
    }
    cert,err:=x509.ParseCertificate(der)
    if err!=nil||cert.IsCA||len(cert.URIs)!=1||
        len(cert.DNSNames)!=0||len(cert.EmailAddresses)!=0||len(cert.IPAddresses)!=0||
        !now.Before(cert.NotAfter)||now.Before(cert.NotBefore)||
        cert.KeyUsage&x509.KeyUsageDigitalSignature==0||!hasClientAuthenticationEKU(cert){
        return empty,errors.New("invalid issued certificate")
    }
    identity,ok:=parseAgentIdentityURI(cert.URIs[0])
    if !ok||identity!=expected{
        return empty,errors.New("issued certificate identity mismatch")
    }
    return sha256.Sum256(cert.Raw),nil
}

// ValidateIssuedCertificateForCSR ensures the certificate issued by a trusted
// CA contains the exact public key proven by the signed CSR. The caller must
// separately authenticate the enrollment issuer and verify the issued chain.
func ValidateIssuedCertificateForCSR(csrDER, certDER []byte, expected AgentIdentity, now time.Time) ([32]byte,error) {
    var empty [32]byte
    csrKey,err:=ValidateAgentCSR(csrDER,expected)
    if err!=nil{return empty,err}
    fingerprint,err:=ValidateIssuedAgentCertificate(certDER,expected,now)
    if err!=nil{return empty,err}
    cert,err:=x509.ParseCertificate(certDER)
    if err!=nil{return empty,errors.New("invalid issued certificate")}
    certKey:=sha256.Sum256(cert.RawSubjectPublicKeyInfo)
    if certKey!=csrKey{
        return empty,errors.New("issued certificate public key does not match signed CSR")
    }
    return fingerprint,nil
}
