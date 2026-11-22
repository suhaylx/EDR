package edr

import (
    "bytes"
    "crypto/sha256"
    "crypto/tls"
    "crypto/x509"
    "database/sql/driver"
    "io"
    "net/http"
    "net/http/httptest"
    "strings"
    "sync/atomic"
    "testing"
    "time"
)

// BE-116..120 checks the result endpoint over a REAL TLS 1.3 client certificate
// handshake and an enrolled certificate registry, with a deterministic fake DB.
// It does NOT attest a deployed issuer, endpoint host, real clamd, or PG E2E.
func TestBE116To120RealMTLSScanResultBoundary(t *testing.T) {
    now:=time.Now().UTC()
    leaf,deviceCert,trust:=createTestAgentCertificate(t,now,
        []string{"spiffe://turansec.local/tenants/tenantA/agents/win01"},
        []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
    identity:=AgentIdentity{TenantID:"tenantA",AgentID:"win01"}
    registry:=testIdentityRegistry{record:EnrolledAgentCertificate{
        Identity:identity,FingerprintSHA256:sha256.Sum256(leaf.Raw),
    }}
    var dbCalls atomic.Int32
    db:=scanDB(t,func(query string,args []driver.NamedValue)(driver.Rows,error){
        if !strings.Contains(query,"edr_complete_scan_job_with_result") || len(args)!=7 ||
            args[0].Value!="tenantA" || args[1].Value!="win01" ||
            args[2].Value!=testUUID || args[3].Value!=leaseUUID ||
            args[4].Value!="malicious" || args[5].Value!="Lab-Signature" || args[6].Value!="" {
            t.Errorf("result query escaped enrolled identity: %q %#v",query,args)
            return nil,io.ErrUnexpectedEOF
        }
        switch dbCalls.Add(1) {
        case 1:
            return &scanRows{columns:[]string{"saved"},
                values:[][]driver.Value{{true}}},nil
        case 2:
            return &scanRows{columns:[]string{"saved"},
                values:[][]driver.Value{{false}}},nil
        default:
            return nil,io.ErrUnexpectedEOF
        }
    })
    guarded:=AgentHTTPGuard(registry,AgentScanQueueHandler(PostgresScanJobQueue{DB:db}))
    server:=httptest.NewUnstartedServer(guarded)
    server.TLS=&tls.Config{MinVersion:tls.VersionTLS13,
        ClientAuth:tls.RequireAndVerifyClientCert,ClientCAs:trust}
    server.StartTLS()
    defer server.Close()
    path:="/agent/v1/tenants/tenantA/agents/win01/scan-jobs/complete-result"
    payload:=[]byte(`{"job_id":"`+testUUID+`","lease_token":"`+leaseUUID+`","verdict":"malicious","threat_name":"Lab-Signature","detail":""}`)

    t.Run("BE-116 client certificate required at handshake",func(t *testing.T){
        unauth:=server.Client()
        resp,err:=unauth.Post(server.URL+path,"application/json",bytes.NewReader(payload))
        if err==nil {
            resp.Body.Close()
            t.Fatalf("result endpoint accepted no-client-cert TLS: %d",resp.StatusCode)
        }
        if dbCalls.Load()!=0 {t.Fatalf("unauthenticated TLS invoked result database")}
    })

    client:=server.Client()
    transport:=client.Transport.(*http.Transport).Clone()
    transport.TLSClientConfig=transport.TLSClientConfig.Clone()
    transport.TLSClientConfig.Certificates=[]tls.Certificate{deviceCert}
    client.Transport=transport
    defer transport.CloseIdleConnections()
    send:=func(method,route string,body []byte,spoof bool)(int,http.Header){
        t.Helper()
        req,err:=http.NewRequest(method,server.URL+route,bytes.NewReader(body))
        if err!=nil {t.Fatal(err)}
        req.Header.Set("Content-Type","application/json")
        if spoof {
            req.Header.Set("X-Tenant-ID","tenantB")
            req.Header.Set("X-Agent-ID","other")
        }
        res,err:=client.Do(req)
        if err!=nil {t.Fatal(err)}
        defer res.Body.Close()
        _,_=io.Copy(io.Discard,res.Body)
        return res.StatusCode,res.Header
    }

    t.Run("BE-117 spoofed request headers cannot override enrolled SQL identity",func(t *testing.T){
        status,headers:=send("POST",path,payload,true)
        if status!=204 {t.Fatalf("trusted result response %d",status)}
        if headers.Get("Cache-Control")!="no-store" {
            t.Fatalf("missing no-store on result completion")
        }
        if dbCalls.Load()!=1 {t.Fatalf("expected exactly one scoped completion query")}
    })
    t.Run("BE-118 cross-tenant and device routes fail before SQL",func(t *testing.T){
        for _,route:=range []string{
            "/agent/v1/tenants/tenantB/agents/win01/scan-jobs/complete-result",
            "/agent/v1/tenants/tenantA/agents/win02/scan-jobs/complete-result",
        } {
            if status,_:=send("POST",route,payload,false);status!=403 {
                t.Fatalf("cross-identity completion returned %d",status)
            }
        }
        if dbCalls.Load()!=1 {t.Fatalf("forbidden route invoked database")}
    })
    t.Run("BE-119 stale lease conflict and database outage never return success",func(t *testing.T){
        if status,_:=send("POST",path,payload,false);status!=409 {
            t.Fatalf("stale lease completion returned %d",status)
        }
        if status,_:=send("POST",path,payload,false);status!=503 {
            t.Fatalf("database outage returned %d",status)
        }
    })
    t.Run("BE-120 wrong method, unknown JSON, oversized body denied before SQL",func(t *testing.T){
        before:=dbCalls.Load()
        if status,_:=send("GET",path,nil,false);status!=405 {
            t.Fatalf("wrong method status %d",status)
        }
        extra:=bytes.Replace(payload,[]byte(`"detail":""`),
            []byte(`"detail":"","agent_id":"other"`),1)
        if status,_:=send("POST",path,extra,false);status!=400 {
            t.Fatalf("unknown result field status %d",status)
        }
        if status,_:=send("POST",path,[]byte(strings.Repeat("{",5000)),false);status!=400 {
            t.Fatalf("oversized result body status %d",status)
        }
        if dbCalls.Load()!=before {t.Fatalf("malformed result invoked database")}
    })
}
