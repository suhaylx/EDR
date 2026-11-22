package edr

import (
 "net/http"
 "strconv"
 "strings"
)

// SOCEndpointHandler is read-only and must be mounted only beneath the
// SOCOperatorHTTPGuard mTLS certificate-and-role authorization boundary.
func SOCEndpointHandler(q PostgresScanJobQueue)http.Handler{
 return http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  w.Header().Set("Cache-Control","no-store")
  principal,ok:=socPrincipal(r.Context())
  if !ok{http.Error(w,"unauthorized",http.StatusUnauthorized);return}
  tenant,valid:=socTenantRoute(r.URL)
  if !valid||tenant!=principal.TenantID{
   http.Error(w,"forbidden",http.StatusForbidden);return
  }
  if r.Method!=http.MethodGet{
   w.Header().Set("Allow","GET")
   http.Error(w,"method not allowed",http.StatusMethodNotAllowed);return
  }
  prefix:="/soc/v1/tenants/"+principal.TenantID+"/"
  operation:=strings.TrimPrefix(r.URL.Path,prefix)
  params:=r.URL.Query()
  switch {
  case operation=="endpoints":
   limit,offset,ok:=socReadQuery(params,"platform","health")
   if !ok{http.Error(w,"invalid pagination or filter",http.StatusBadRequest);return}
   items,err:=q.ListEndpoints(r.Context(),principal,
    params.Get("platform"),params.Get("health"),limit,offset)
   if err!=nil{socRespondError(w,err);return}
   socReplyJSON(w,http.StatusOK,map[string]any{
    "items":items,"limit":limit,"offset":offset,
   })
  case operation=="endpoint-stats":
   if len(params)!=0{http.Error(w,"invalid query",http.StatusBadRequest);return}
   result,err:=q.EndpointFleetStats(r.Context(),principal)
   if err!=nil{socRespondError(w,err);return}
   socReplyJSON(w,http.StatusOK,result)
  case strings.HasPrefix(operation,"endpoints/"):
   parts:=strings.Split(strings.TrimPrefix(operation,"endpoints/"),"/")
   if len(parts)==1{
    if len(params)!=0{http.Error(w,"invalid query",http.StatusBadRequest);return}
    item,err:=q.GetEndpoint(r.Context(),principal,parts[0])
    if err!=nil{socRespondError(w,err);return}
    if item==nil{http.NotFound(w,r);return}
    socReplyJSON(w,http.StatusOK,item)
    return
   }
   if len(parts)!=2||parts[1]!="timeline"{
    http.NotFound(w,r);return
   }
   if len(params)>1||len(params["limit"])>1||
    (len(params)==1&&params["limit"]==nil){
    http.Error(w,"invalid query",http.StatusBadRequest);return
   }
   limit:=25
   if values,exists:=params["limit"];exists{
    if len(values)!=1 {http.Error(w,"invalid limit",http.StatusBadRequest);return}
    n,e:=strconv.Atoi(values[0])
    if e!=nil{http.Error(w,"invalid limit",http.StatusBadRequest);return}
    limit=n
   }
   items,err:=q.EndpointTimeline(r.Context(),principal,parts[0],limit)
   if err!=nil{socRespondError(w,err);return}
   socReplyJSON(w,http.StatusOK,map[string]any{"items":items,"limit":limit})
  default:
   http.NotFound(w,r)
  }
 })
}
