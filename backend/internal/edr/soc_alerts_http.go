package edr

import (
 "encoding/json"
 "io"
 "net/http"
 "strings"
)

// SOCAlertHandler always requires a verified operator principal; this
// handler is mounted only on the separate SOC operator mTLS listener.
func SOCAlertHandler(q PostgresScanJobQueue)http.Handler{
 return http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  w.Header().Set("Cache-Control","no-store")
  p,ok:=socPrincipal(r.Context())
  if !ok{http.Error(w,"unauthorized",401);return}
  tenant,valid:=socTenantRoute(r.URL)
  if !valid||tenant!=p.TenantID{http.Error(w,"forbidden",403);return}
  prefix:="/soc/v1/tenants/"+p.TenantID+"/"
  op:=strings.TrimPrefix(r.URL.Path,prefix)
  if op=="alert-stats"&&r.Method==http.MethodGet {
   if r.URL.RawQuery!=""{http.Error(w,"invalid query",400);return}
   counts,err:=q.SOCAlertStats(r.Context(),p)
   if err!=nil{socRespondError(w,err);return}
   socReplyJSON(w,200,counts);return
  }
  if op=="alerts"&&r.Method==http.MethodGet {
   limit,offset,ok:=socReadQuery(r.URL.Query(),"state")
   if !ok{http.Error(w,"invalid pagination",400);return}
   items,err:=q.ListSOCAlerts(r.Context(),p,r.URL.Query().Get("state"),limit,offset)
   if err!=nil{socRespondError(w,err);return}
   socReplyJSON(w,200,map[string]any{"items":items,"limit":limit,"offset":offset})
   return
  }
  if !strings.HasPrefix(op,"alerts/"){http.NotFound(w,r);return}
  if r.URL.RawQuery!=""{http.Error(w,"invalid query",400);return}
  segments:=strings.Split(strings.TrimPrefix(op,"alerts/"),"/")
  if len(segments)<1||!validUUID(segments[0]){
   http.Error(w,"invalid alert ID",400);return
  }
  id:=segments[0]
  if len(segments)==1&&r.Method==http.MethodGet {
   item,err:=q.GetSOCAlert(r.Context(),p,id)
   if err!=nil{socRespondError(w,err);return}
   if item==nil{http.NotFound(w,r);return}
   socReplyJSON(w,200,item);return
  }
  if len(segments)!=2||r.Method!=http.MethodPost {
   http.Error(w,"not found or method not allowed",405);return
  }
  if p.Role!="scanner"{http.Error(w,"forbidden",403);return}
  action:=segments[1]
  if action!="ack"&&action!="resolve"&&action!="reopen"{
   http.NotFound(w,r);return
  }
  note:=""
  if action=="resolve"{
   var payload struct{Note string `json:"note"`}
   if !socDecode(w,r,&payload){return}
   note=payload.Note
  }else{
   r.Body=http.MaxBytesReader(w,r.Body,1)
   var buffer [1]byte
   n,e:=r.Body.Read(buffer[:])
   if n!=0||(e!=nil&&e!=io.EOF){http.Error(w,"invalid payload",400);return}
  }
  saved,err:=q.ChangeSOCAlert(r.Context(),p,id,action,note)
  if err!=nil{socRespondError(w,err);return}
  if !saved{http.Error(w,"alert state does not allow transition",409);return}
  w.WriteHeader(http.StatusNoContent)
 })
}
