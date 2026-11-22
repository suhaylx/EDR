package edr

import (
 "encoding/json"
 "net/http"
 "net/url"
 "strconv"
 "strings"
)

func socReadQuery(q url.Values,allowed ...string)(int,int,bool){
 permitted:=map[string]bool{"limit":true,"offset":true}
 for _,key:=range allowed{permitted[key]=true}
 for k,values:=range q{
  if !permitted[k]||len(values)!=1{return 0,0,false}
 }
 limit,offset:=25,0
 if n:=q.Get("limit");n!="" {
  v,e:=strconv.Atoi(n);if e!=nil{return 0,0,false};limit=v
 }
 if n:=q.Get("offset");n!="" {
  v,e:=strconv.Atoi(n);if e!=nil{return 0,0,false};offset=v
 }
 return limit,offset,validSOCPage(limit,offset)
}
func socReplyJSON(w http.ResponseWriter,status int,value any){
 w.Header().Set("Content-Type","application/json")
 w.WriteHeader(status)
 _=json.NewEncoder(w).Encode(value)
}

// SOCScanReadHandler requires the same operator-authenticated context and
// tenant check as SOCScanHandler, not any agent or bearer-token principal.
func SOCScanReadHandler(q PostgresScanJobQueue)http.Handler{
 return http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  w.Header().Set("Cache-Control","no-store")
  p,ok:=socPrincipal(r.Context())
  if !ok {http.Error(w,"unauthorized",401);return}
  tenant,valid:=socTenantRoute(r.URL)
  if !valid||tenant!=p.TenantID {http.Error(w,"forbidden",403);return}
  if r.Method!=http.MethodGet {w.Header().Set("Allow","GET");http.Error(w,"method not allowed",405);return}
  prefix:="/soc/v1/tenants/"+p.TenantID+"/"
  op:=strings.TrimPrefix(r.URL.Path,prefix)
  params:=r.URL.Query()
  switch {
  case op=="scan-jobs":
   limit,offset,ok:=socReadQuery(params,"state")
   if !ok {http.Error(w,"invalid pagination",400);return}
   jobs,err:=q.ListSOCJobs(r.Context(),p,params.Get("state"),limit,offset)
   if err!=nil{socRespondError(w,err);return}
   socReplyJSON(w,200,map[string]any{"items":jobs,"limit":limit,"offset":offset})
  case strings.HasPrefix(op,"scan-jobs/"):
   if len(params)!=0{http.Error(w,"query not allowed",400);return}
   id:=strings.TrimPrefix(op,"scan-jobs/")
   job,err:=q.GetSOCJob(r.Context(),p,id)
   if err!=nil{socRespondError(w,err);return}
   if job==nil{http.NotFound(w,r);return}
   socReplyJSON(w,200,job)
  case op=="scan-results":
   limit,offset,ok:=socReadQuery(params,"agent_id","verdict")
   if !ok{http.Error(w,"invalid pagination",400);return}
   items,err:=q.ListSOCResults(r.Context(),p,
    params.Get("agent_id"),params.Get("verdict"),limit,offset)
   if err!=nil{socRespondError(w,err);return}
   socReplyJSON(w,200,map[string]any{"items":items,"limit":limit,"offset":offset})
  case strings.HasPrefix(op,"scan-results/"):
   if len(params)!=0{http.Error(w,"query not allowed",400);return}
   id:=strings.TrimPrefix(op,"scan-results/")
   item,err:=q.GetSOCResult(r.Context(),p,id)
   if err!=nil{socRespondError(w,err);return}
   if item==nil{http.NotFound(w,r);return}
   socReplyJSON(w,200,item)
  case op=="scan-stats":
   if len(params)!=0{http.Error(w,"query not allowed",400);return}
   stats,err:=q.SOCStats(r.Context(),p)
   if err!=nil{socRespondError(w,err);return}
   socReplyJSON(w,200,stats)
  default:
   http.NotFound(w,r)
  }
 })
}
