package edr

import (
 "context"
 "net/http"
 "net/http/httptest"
 "strings"
 "testing"
)

func TestQASOCAssignDoesNotInterpretAbsentFieldAsUnassign(t *testing.T) {
 principal:=SOCOperatorPrincipal{TenantID:"tenantA",OperatorID:"analyst",Role:"scanner"}
 h:=SOCScanHandler(PostgresScanJobQueue{})
 url:="/soc/v1/tenants/tenantA/alerts/"+testUUID+"/assign"
 for _,payload:=range []string{"{}",`{"operator_id":null}`,`{"operatorId":""}`} {
  request:=httptest.NewRequest(http.MethodPost,url,strings.NewReader(payload))
  request=request.WithContext(context.WithValue(request.Context(),socOperatorContextKey{},principal))
  recorder:=httptest.NewRecorder()
  h.ServeHTTP(recorder,request)
  if recorder.Code!=http.StatusBadRequest{
   t.Errorf("omitted/null/unrecognized assignment field %q returned %d, want 400",payload,recorder.Code)
  }
 }
 // Explicit empty operator_id is an intentional unassign request; without
 // a DB it must fail closed as 503, not be mistaken for an omitted field.
 request:=httptest.NewRequest(http.MethodPost,url,
  strings.NewReader(`{"operator_id":""}`))
 request=request.WithContext(context.WithValue(request.Context(),socOperatorContextKey{},principal))
 recorder:=httptest.NewRecorder()
 h.ServeHTTP(recorder,request)
 if recorder.Code!=http.StatusServiceUnavailable {
  t.Fatalf("explicit unassign status %d want 503 without DB",recorder.Code)
 }
}
