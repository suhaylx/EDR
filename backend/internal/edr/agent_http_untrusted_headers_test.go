package edr

import (
    "crypto/sha256"
    "crypto/tls"
    "crypto/x509"
    "net/http"
    "net/http/httptest"
    "testing"
    "time"
)

// SEC-051/052: successful mTLS must deliver the certificate-derived context,
// never client-provided tenant/device/certificate/legacy bearer claims. The
// original request is cloned, preserving caller-owned headers.
func TestAgentHTTPGuardStripsSpoofedIdentityHeadersAfterMTLS(t *testing.T) {
    now:=time.Now().UTC().Truncate(time.Second)
    cert,_,_:=createTestAgentCertificate(t,now,
        []string{"spiffe://turansec.local/tenants/tenantA/agents/win01"},
        []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
    trusted:=AgentIdentity{TenantID:"tenantA",AgentID:"win01"}
    registry:=testIdentityRegistry{record:EnrolledAgentCertificate{
        Identity:trusted,FingerprintSHA256:sha256.Sum256(cert.Raw),
    }}
    var downstreamCalled bool
    guarded:=AgentHTTPGuard(registry,http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
        downstreamCalled=true
        fromContext,ok:=AgentIdentityFromContext(r.Context())
        if !ok || fromContext!=trusted {t.Fatalf("missing certificate-derived identity: %+v %v",fromContext,ok)}
        forged:=[]string{
            "Authorization","Proxy-Authorization","X-Tenant-ID","X-Agent-ID",
            "X-Device-ID","X-User-ID","X-Forwarded-Client-Cert",
            "X-SSL-Client-Cert","X-Verified-Client-Cert","X-Client-Cert",
            "X-Client-Certificate","X-SSL-Client-Verify",
            "X-Authenticated-User","X-Forwarded-User","X-Remote-User",
            "X-Forwarded-Proto", "X-SSL-Client-S-DN",
            "X-SSL-Client-Fingerprint", "X-Forwarded-Client-Cert-Chain",
            "X-Auth-Request-User", "X-Verified-Client-Subject",
            "SSL-Client-Cert", "SSL-Client-Verify",
        }
        for _,name:=range forged {
            if value:=r.Header.Get(name);value!="" {
                t.Fatalf("untrusted identity header %q leaked to agent handler",name)
            }
        }
        if r.Header.Get("X-Request-ID")!="trace-only" {
            t.Fatal("benign tracing header removed")
        }
        w.WriteHeader(http.StatusNoContent)
    }))
    path:="/agent/v1/tenants/tenantA/agents/win01/scan-jobs/claim"
    request:=httptest.NewRequest(http.MethodPost,path,nil)
    request.TLS=&tls.ConnectionState{
        PeerCertificates:[]*x509.Certificate{cert},
        VerifiedChains:[][]*x509.Certificate{{cert}},
    }
    for _,name:=range []string{
        "Authorization","Proxy-Authorization","X-Tenant-ID","X-Agent-ID",
        "X-Device-ID","X-User-ID","X-Forwarded-Client-Cert",
        "X-SSL-Client-Cert","X-Verified-Client-Cert","X-Client-Cert",
        "X-Client-Certificate","X-SSL-Client-Verify","X-Authenticated-User",
        "X-Forwarded-User","X-Remote-User","X-Forwarded-Proto",
        "X-SSL-Client-S-DN","X-SSL-Client-Fingerprint",
        "X-Forwarded-Client-Cert-Chain","X-Auth-Request-User",
        "X-Verified-Client-Subject","SSL-Client-Cert","SSL-Client-Verify",
    } {
        request.Header.Set(name,"attacker-controlled-tenant-device-or-certificate")
    }
    request.Header.Set("X-Request-ID","trace-only")
    response:=httptest.NewRecorder()
    guarded.ServeHTTP(response,request)
    if response.Code!=http.StatusNoContent || !downstreamCalled {
        t.Fatalf("verified identity denied or not processed: %d",response.Code)
    }
    if request.Header.Get("Authorization")=="" || request.Header.Get("X-Tenant-ID")=="" {
        t.Fatal("caller-owned request headers unexpectedly mutated")
    }
    // The same attacker-controlled pseudo-identity, without an actual
    // authenticated TLS certificate, must never reach downstream.
    downstreamCalled=false
    request.TLS=nil
    denied:=httptest.NewRecorder()
    guarded.ServeHTTP(denied,request)
    if denied.Code!=http.StatusUnauthorized || downstreamCalled {
        t.Fatalf("forged identity without mTLS authorized: code=%d called=%v",denied.Code,downstreamCalled)
    }
}

func TestAgentIdentityHeaderDenylistCaseNormalization(t *testing.T) {
    for _,name:=range []string{
        "authorization","proxy-authorization","x-tenant-id","x-agent-id",
        "x-device-id","x-forwarded-client-cert","x-ssl-client-cert",
        "x-client-cert","x-verified-client-cert",
        "x-ssl-client-s-dn","x-ssl-client-fingerprint",
        "x-forwarded-client-cert-chain","x-auth-request-user",
        "x-verified-client-subject","ssl-client-cert","ssl-client-verify",
    } {
        if !untrustedAgentIdentityHeader(name) {
            t.Fatalf("spoofing header not rejected: %s",name)
        }
    }
    for _,name:=range []string{"x-request-id","accept","content-type","user-agent"} {
        if untrustedAgentIdentityHeader(name) {
            t.Fatalf("non-identity header blocked: %s",name)
        }
    }
}
