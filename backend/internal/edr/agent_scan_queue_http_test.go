package edr

import (
    "bytes"
    "context"
    "encoding/json"
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
        {"no db claim","POST",base+"scan-jobs/claim","",valid,503},
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
