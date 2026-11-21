package edr

import (
    "bytes"
    "context"
    "encoding/json"
    "io"
    "database/sql/driver"
    "net/http"
    "net/http/httptest"
    "strings"
    "testing"
)

func scanRequest(method,path,body string,principal *AgentIdentity)*http.Request{
    r:=httptest.NewRequest(method,path,strings.NewReader(body))
    if principal!=nil {r=r.WithContext(context.WithValue(r.Context(),agentIdentityContextKey{},*principal))}
    return r
}
func TestAgentScanQueueHandlerRejectsUntrustedRequests(t *testing.T){
    handler:=AgentScanQueueHandler(PostgresScanJobQueue{})
    base:="/agent/v1/tenants/tenantA/agents/win01/"
    valid:=&AgentIdentity{TenantID:"tenantA",AgentID:"win01"}
    cases:=[]struct{name,method,path,body string;principal *AgentIdentity;status int}{
        {"no principal","POST",base+"scan-jobs/claim","",nil,401},
        {"wrong tenant","POST","/agent/v1/tenants/tenantB/agents/win01/scan-jobs/claim","",valid,403},
        {"wrong device","POST","/agent/v1/tenants/tenantA/agents/other/scan-jobs/claim","",valid,403},
        {"wrong method","GET",base+"scan-jobs/claim","",valid,405},
        {"unknown operation","POST",base+"unknown","",valid,404},
        {"query","POST",base+"scan-jobs/claim?override=true","",valid,400},
        {"invalid json","POST",base+"scan-jobs/complete","not json",valid,400},
        {"unknown fields","POST",base+"scan-jobs/complete",`{"job_id":"`+testUUID+`","lease_token":"`+leaseUUID+`","success":true,"tenant_id":"tenantB"}`,valid,400},
        {"missing success","POST",base+"scan-jobs/complete",`{"job_id":"`+testUUID+`","lease_token":"`+leaseUUID+`"}`,valid,400},
        {"trailing json","POST",base+"scan-jobs/complete",`{"job_id":"`+testUUID+`","lease_token":"`+leaseUUID+`","success":true}{}`,valid,400},
        {"invalid lease","POST",base+"scan-jobs/complete",`{"job_id":"`+testUUID+`","lease_token":"invalid","success":true}`,valid,400},
        {"claim unexpected JSON","POST",base+"scan-jobs/claim",`{"tenant_id":"tenantB"}`,valid,400},
        {"claim unexpected byte","POST",base+"scan-jobs/claim","x",valid,400},
        {"no db claim","POST",base+"scan-jobs/claim","",valid,503},
        {"renew no principal","POST",base+"scan-jobs/renew","{}",nil,401},
        {"renew cross tenant","POST","/agent/v1/tenants/tenantB/agents/win01/scan-jobs/renew","{}",valid,403},
        {"renew wrong method","GET",base+"scan-jobs/renew","",valid,405},
        {"renew query rejected","POST",base+"scan-jobs/renew?tenant=other","",valid,400},
        {"renew other device","POST","/agent/v1/tenants/tenantA/agents/other/scan-jobs/renew","",valid,403},
        {"renew empty body","POST",base+"scan-jobs/renew","",valid,400},
        {"renew missing duration","POST",base+"scan-jobs/renew",`{"job_id":"`+testUUID+`","lease_token":"`+leaseUUID+`"}`,valid,400},
        {"renew invalid duration","POST",base+"scan-jobs/renew",`{"job_id":"`+testUUID+`","lease_token":"`+leaseUUID+`","lease_seconds":301}`,valid,400},
        {"renew invalid token","POST",base+"scan-jobs/renew",`{"job_id":"`+testUUID+`","lease_token":"bad","lease_seconds":30}`,valid,400},
        {"renew unknown field","POST",base+"scan-jobs/renew",`{"job_id":"`+testUUID+`","lease_token":"`+leaseUUID+`","lease_seconds":30,"tenant_id":"tenantB"}`,valid,400},
        {"renew trailing json","POST",base+"scan-jobs/renew",`{"job_id":"`+testUUID+`","lease_token":"`+leaseUUID+`","lease_seconds":30}{}`,valid,400},
        {"renew no db","POST",base+"scan-jobs/renew",`{"job_id":"`+testUUID+`","lease_token":"`+leaseUUID+`","lease_seconds":30}`,valid,503},
        {"no db complete","POST",base+"scan-jobs/complete",`{"job_id":"`+testUUID+`","lease_token":"`+leaseUUID+`","success":true}`,valid,503},
    }
    for _,tc:=range cases{
        t.Run(tc.name,func(t *testing.T){
            w:=httptest.NewRecorder()
            handler.ServeHTTP(w,scanRequest(tc.method,tc.path,tc.body,tc.principal))
            if w.Code!=tc.status {t.Fatalf("status %d, want %d; body %s",w.Code,tc.status,w.Body.String())}
        })
    }
}
func TestNewScanLeaseTokenUniqueAndUUIDv4(t *testing.T){
    seen:=map[string]bool{}
    for i:=0;i<128;i++{
        token,err:=NewScanLeaseToken()
        if err!=nil||!validUUID(token)||token[14]!='4'||!strings.ContainsAny(token[19:20],"89ab"){
            t.Fatalf("bad token: %s %v",token,err)
        }
        if seen[token]{t.Fatal("duplicate token")}
        seen[token]=true
    }
}
func TestAgentScanQueueClaimResponse(t *testing.T){
    db:=scanDB(t,func(q string,args []driver.NamedValue)(driver.Rows,error){
        return &scanRows{columns:[]string{"job_id","scan_root","attempt_count"},
            values:[][]driver.Value{{testUUID,"C:/Lab",int64(1)}}},nil
    })
    handler:=AgentScanQueueHandler(PostgresScanJobQueue{DB:db})
    principal:=&AgentIdentity{TenantID:"tenantA",AgentID:"win01"}
    w:=httptest.NewRecorder()
    handler.ServeHTTP(w,scanRequest("POST","/agent/v1/tenants/tenantA/agents/win01/scan-jobs/claim","",principal))
    if w.Code!=200{t.Fatalf("status %d: %s",w.Code,w.Body.String())}
    var response struct{JobID string `json:"job_id"`;LeaseToken string `json:"lease_token"`}
    if err:=json.NewDecoder(bytes.NewReader(w.Body.Bytes())).Decode(&response);err!=nil||response.JobID!=testUUID||!validUUID(response.LeaseToken){
        t.Fatalf("invalid response: %#v %v",response,err)
    }
}

func TestAgentScanQueueRenewalUsesAuthenticatedDevice(t *testing.T){
    db:=scanDB(t,func(q string,args []driver.NamedValue)(driver.Rows,error){
        if !strings.Contains(q,"edr_renew_scan_job_lease")||len(args)!=6||
            args[0].Value!="tenantA"||args[1].Value!="win01"||
            args[2].Value!=testUUID||args[3].Value!="win01"||
            args[4].Value!=leaseUUID||args[5].Value!=int64(30) {
            t.Fatalf("renewal scope/args: %q %#v",q,args)
        }
        return &scanRows{columns:[]string{"renewed"},values:[][]driver.Value{{true}}},nil
    })
    handler:=AgentScanQueueHandler(PostgresScanJobQueue{DB:db})
    principal:=&AgentIdentity{TenantID:"tenantA",AgentID:"win01"}
    body:=`{"job_id":"`+testUUID+`","lease_token":"`+leaseUUID+`","lease_seconds":30}`
    w:=httptest.NewRecorder()
    handler.ServeHTTP(w,scanRequest("POST","/agent/v1/tenants/tenantA/agents/win01/scan-jobs/renew",body,principal))
    if w.Code!=204 {t.Fatalf("renew status %d: %s",w.Code,w.Body.String())}
}

func TestAgentScanQueueRenewalConflictAndDatabaseFailure(t *testing.T){
    principal:=&AgentIdentity{TenantID:"tenantA",AgentID:"win01"}
    body:=`{"job_id":"`+testUUID+`","lease_token":"`+leaseUUID+`","lease_seconds":30}`
    for _,tc:=range []struct{name string; rows driver.Rows; err error; status int}{
        {"expired lease",&scanRows{columns:[]string{"ok"},values:[][]driver.Value{{false}}},nil,409},
        {"db outage",nil,io.ErrUnexpectedEOF,503},
    }{
        t.Run(tc.name,func(t *testing.T){
            db:=scanDB(t,func(string,[]driver.NamedValue)(driver.Rows,error){return tc.rows,tc.err})
            w:=httptest.NewRecorder()
            AgentScanQueueHandler(PostgresScanJobQueue{DB:db}).ServeHTTP(w,
                scanRequest("POST","/agent/v1/tenants/tenantA/agents/win01/scan-jobs/renew",body,principal))
            if w.Code!=tc.status {t.Fatalf("status %d, expected %d",w.Code,tc.status)}
        })
    }
}
