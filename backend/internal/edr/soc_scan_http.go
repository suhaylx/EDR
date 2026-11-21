package edr

import (
 "encoding/json"
 "errors"
 "io"
 "net/http"
 "strings"
)

func socRespondError(w http.ResponseWriter,err error){
 status:=http.StatusServiceUnavailable
 switch {
 case errors.Is(err,ErrInvalidScanQueueRequest):
  status=http.StatusBadRequest
 case errors.Is(err,ErrSOCForbidden):
  status=http.StatusForbidden
 case errors.Is(err,ErrSOCConflict):
  status=http.StatusConflict
 }
 http.Error(w,http.StatusText(status),status)
}
func socDecode(w http.ResponseWriter,r *http.Request,payload any)bool{
 r.Body=http.MaxBytesReader(w,r.Body,8192)
 dec:=json.NewDecoder(r.Body)
 dec.DisallowUnknownFields()
 if dec.Decode(payload)!=nil {http.Error(w,"invalid JSON",400);return false}
 var extra json.RawMessage
 if dec.Decode(&extra)!=io.EOF {http.Error(w,"multiple JSON values",400);return false}
 return true
}

// SOCScanHandler is *not* an independently authenticated HTTP endpoint.
// Call only under SOCOperatorHTTPGuard on a separate trusted operator mTLS
// listener. Never mount on the shared development-token or agent listener.
func SOCScanHandler(q PostgresScanJobQueue)http.Handler{
 return http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  w.Header().Set("Cache-Control","no-store")
  p,ok:=socPrincipal(r.Context())
  if !ok {http.Error(w,"unauthorized",401);return}
  tenant,valid:=socTenantRoute(r.URL)
  if !valid||tenant!=p.TenantID {http.Error(w,"forbidden",403);return}
  // Derive the operation before routing: this handler also owns the
  // operator-only alert and read-only investigation subrouters.
  prefix:="/soc/v1/tenants/"+p.TenantID+"/"
  operation:=strings.TrimPrefix(r.URL.Path,prefix)
  if operation=="endpoints"||operation=="endpoint-stats"||
    strings.HasPrefix(operation,"endpoints/") {
   SOCEndpointHandler(q).ServeHTTP(w,r)
   return
  }
  if operation=="alerts"||strings.HasPrefix(operation,"alerts/")||operation=="alert-stats"||operation=="my-alerts" {
   SOCAlertHandler(q).ServeHTTP(w,r)
   return
  }
  if r.Method==http.MethodGet {
   SOCScanReadHandler(q).ServeHTTP(w,r)
   return
  }
  if r.URL.RawQuery!="" {http.Error(w,"invalid query",400);return}
  if operation=="scan-jobs"&&r.Method==http.MethodPost{
   if p.Role!="scanner"{http.Error(w,"forbidden",403);return}
   var payload struct{
    AgentID string `json:"agent_id"`
    RequestID string `json:"request_id"`
    ScanRoot string `json:"scan_root"`
   }
   if !socDecode(w,r,&payload){return}
   job,err:=q.ScheduleSOCScan(r.Context(),p,payload.AgentID,payload.RequestID,payload.ScanRoot)
   if err!=nil{socRespondError(w,err);return}
   status:=http.StatusOK
   if job.Created{status=http.StatusCreated}
   w.Header().Set("Content-Type","application/json")
   w.WriteHeader(status)
   _=json.NewEncoder(w).Encode(job)
   return
  }
  if strings.HasPrefix(operation,"scan-jobs/")&&
   strings.HasSuffix(operation,"/cancel")&&r.Method==http.MethodPost{
   if p.Role!="scanner"{http.Error(w,"forbidden",403);return}
   id:=strings.TrimSuffix(strings.TrimPrefix(operation,"scan-jobs/"),"/cancel")
   if !validUUID(id){http.Error(w,"invalid job",400);return}
   // Cancellation is bodyless; no second request source may override target.
   r.Body=http.MaxBytesReader(w,r.Body,1)
   var probe [1]byte
   n,err:=r.Body.Read(probe[:])
   if n!=0||(err!=nil&&err!=io.EOF){http.Error(w,"invalid payload",400);return}
   done,e:=q.CancelSOCScan(r.Context(),p,id)
   if e!=nil{socRespondError(w,e);return}
   if !done{http.Error(w,"job is not pending or not owned",409);return}
   w.WriteHeader(http.StatusNoContent);return
  }
  http.NotFound(w,r)
 })
}
