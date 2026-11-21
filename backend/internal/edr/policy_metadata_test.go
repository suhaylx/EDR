package edr

import (
 "encoding/json"
 "net/http"
 "net/http/httptest"
 "strings"
 "testing"
)

func TestPolicyMetadataEndpointOmitsSysmonXML(t *testing.T) {
 store:=NewStore()
 raw:=`<Sysmon schemaversion="4.90"><EventFiltering><ImageLoad onmatch="include"><Image condition="contains">SECRET_TEST_RULE</Image></ImageLoad></EventFiltering></Sysmon>`
 created,err:=store.CreatePolicy("Lab Policy", "windows",raw)
 if err!=nil { t.Fatal(err) }
 server:=(&Server{Store:store,Token:"test-only-development-token",WebDir:"."}).Handler()
 req:=httptest.NewRequest(http.MethodGet,"/api/policy-metadata",nil)
 req.Header.Set("Authorization","Bearer test-only-development-token")
 w:=httptest.NewRecorder()
 server.ServeHTTP(w,req)
 if w.Code!=http.StatusOK {t.Fatalf("status=%d body=%s",w.Code,w.Body.String())}
 if w.Header().Get("Cache-Control")!="no-store" {t.Fatal("missing no-store cache header")}
 if strings.Contains(w.Body.String(),"SECRET_TEST_RULE")||
    strings.Contains(w.Body.String(),`"xml"`) {
  t.Fatal("policy metadata route leaked Sysmon XML")
 }
 var items []map[string]any
 if err:=json.Unmarshal(w.Body.Bytes(),&items);err!=nil{t.Fatal(err)}
 if len(items)!=1 {t.Fatalf("count=%d",len(items))}
 if items[0]["id"]!=created.ID || items[0]["sha256"]!=created.SHA256 ||
   items[0]["name"]!=created.Name || items[0]["platform"]!="windows" ||
   items[0]["revision"]!=float64(1) {t.Fatalf("metadata contract mismatch: %#v",items[0])}
 for _,field:=range []string{"id","name","platform","revision","sha256","created_at"} {
  if _,ok:=items[0][field];!ok{t.Fatalf("missing %s",field)}
 }
}

func TestPolicyMetadataRequiresLabBearerAndIsReadOnly(t *testing.T){
 store:=NewStore()
 server:=(&Server{Store:store,Token:"test-only-development-token",WebDir:"."}).Handler()
 for _,auth:=range []string{"","Bearer invalid"} {
  r:=httptest.NewRequest(http.MethodGet,"/api/policy-metadata",nil)
  if auth!="" {r.Header.Set("Authorization",auth)}
  w:=httptest.NewRecorder();server.ServeHTTP(w,r)
  if w.Code!=http.StatusUnauthorized{t.Fatalf("unauthorized status=%d",w.Code)}
 }
 r:=httptest.NewRequest(http.MethodPost,"/api/policy-metadata",strings.NewReader("{}"))
 r.Header.Set("Authorization","Bearer test-only-development-token")
 r.Header.Set("Content-Type","application/json")
 w:=httptest.NewRecorder();server.ServeHTTP(w,r)
 if w.Code!=http.StatusNotFound{t.Fatalf("unexpected write route status=%d",w.Code)}
 if len(store.Snapshot().Policies)!=0{t.Fatal("read-only policy route changed catalog")}
}
