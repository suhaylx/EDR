package edr

import (
    "crypto/sha256"
    "bytes"
    "crypto/tls"
    "crypto/x509"
    "database/sql/driver"
    "io"
    "net/http"
    "net/http/httptest"
    "strings"
    "testing"
    "time"
)

// End-to-end transport test: real TLS 1.3 handshake, verified client
// certificate, enrolled fingerprint lookup, and tenant-scoped queue claim.
func TestAgentScanQueueRealMutualTLS(t *testing.T) {
    now:=time.Now().UTC()
    leaf,clientCert,caPool:=createTestAgentCertificate(t,now,
        []string{"spiffe://turansec.local/tenants/tenantA/agents/win01"},
        []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
    id:=AgentIdentity{TenantID:"tenantA",AgentID:"win01"}
    registry:=testIdentityRegistry{record:EnrolledAgentCertificate{
        Identity:id,FingerprintSHA256:sha256.Sum256(leaf.Raw),
    }}
    db:=scanDB(t,func(query string,args []driver.NamedValue)(driver.Rows,error){
        if strings.Contains(query,"edr_renew_scan_job_lease") {
            if len(args)!=6||args[0].Value!="tenantA"||args[1].Value!="win01"||
                args[3].Value!="win01"||args[5].Value!=int64(30) {
                t.Errorf("unscoped SQL renewal: %q %#v",query,args)
                return nil,io.ErrUnexpectedEOF
            }
            return &scanRows{columns:[]string{"ok"},values:[][]driver.Value{{true}}},nil
        }
        if !strings.Contains(query,"edr_claim_scan_job")||len(args)!=5||
            args[0].Value!="tenantA"||args[1].Value!="win01" {
            t.Errorf("unscoped SQL claim: %q %#v",query,args)
            return nil,io.ErrUnexpectedEOF
        }
        return &scanRows{columns:[]string{"job_id","scan_root","attempt_count"},
            values:[][]driver.Value{{testUUID,"C:/Lab",int64(1)}}},nil
    })
    handler:=AgentHTTPGuard(registry,AgentScanQueueHandler(PostgresScanJobQueue{DB:db}))
    server:=httptest.NewUnstartedServer(handler)
    server.TLS=&tls.Config{MinVersion:tls.VersionTLS13,
        ClientAuth:tls.RequireAndVerifyClientCert,ClientCAs:caPool}
    server.StartTLS()
    defer server.Close()

    // A verified TLS client without the enrolled private key cannot claim.
    unauth:=server.Client()
    resp,err:=unauth.Post(server.URL+
        "/agent/v1/tenants/tenantA/agents/win01/scan-jobs/claim",
        "application/json",strings.NewReader(""))
    if err==nil{
        resp.Body.Close()
        t.Fatalf("client without certificate unexpectedly got HTTP %d",resp.StatusCode)
    }

    client:=server.Client()
    transport:=client.Transport.(*http.Transport).Clone()
    transport.TLSClientConfig=transport.TLSClientConfig.Clone()
    transport.TLSClientConfig.Certificates=[]tls.Certificate{clientCert}
    client.Transport=transport
    defer transport.CloseIdleConnections()

    claim:=func(path string)int{
        t.Helper()
        req,err:=http.NewRequest(http.MethodPost,server.URL+path,nil)
        if err!=nil{t.Fatal(err)}
        req.Header.Set("X-Tenant-ID","tenantB")
        req.Header.Set("X-Agent-ID","other")
        resp,err:=client.Do(req)
        if err!=nil{t.Fatal(err)}
        defer resp.Body.Close()
        return resp.StatusCode
    }
    if status:=claim("/agent/v1/tenants/tenantA/agents/win01/scan-jobs/claim");status!=200{
        t.Fatalf("enrolled client claim status %d",status)
    }
    if status:=claim("/agent/v1/tenants/tenantB/agents/win01/scan-jobs/claim");status!=403{
        t.Fatalf("cross-tenant client status %d",status)
    }
    if status:=claim("/agent/v1/tenants/tenantA/agents/other/scan-jobs/claim");status!=403{
        t.Fatalf("cross-agent client status %d",status)
    }
    renewBody:=[]byte(`{"job_id":"`+testUUID+`","lease_token":"`+leaseUUID+`","lease_seconds":30}`)
    renew:=func(path string)int{
        t.Helper()
        resp,err:=client.Post(server.URL+path,"application/json",bytes.NewReader(renewBody))
        if err!=nil {t.Fatal(err)}
        defer resp.Body.Close()
        return resp.StatusCode
    }
    if status:=renew("/agent/v1/tenants/tenantA/agents/win01/scan-jobs/renew");status!=204{
        t.Fatalf("mTLS renewal status %d",status)
    }
    if status:=renew("/agent/v1/tenants/tenantB/agents/win01/scan-jobs/renew");status!=403{
        t.Fatalf("cross-tenant renewal status %d",status)
    }
    if status:=renew("/agent/v1/tenants/tenantA/agents/other/scan-jobs/renew");status!=403{
        t.Fatalf("cross-device renewal status %d",status)
    }
}
