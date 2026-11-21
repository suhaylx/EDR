package edr

import (
 "context"
 "database/sql"
 "errors"
 "fmt"
 "time"
)

// SOC reads are tenant-bound at SQL level; no lease owner/token is selected.
type SOCJobView struct {
 JobID string `json:"job_id"`
 AgentID string `json:"agent_id"`
 ScanRoot string `json:"scan_root"`
 State string `json:"state"`
 Attempts int `json:"attempt_count"`
 CreatedAt time.Time `json:"created_at"`
 UpdatedAt time.Time `json:"updated_at"`
}
type SOCResultView struct {
 JobID string `json:"job_id"`
 AgentID string `json:"agent_id"`
 Engine string `json:"engine"`
 Verdict string `json:"verdict"`
 ThreatName string `json:"threat_name"`
 Detail string `json:"detail"`
 ObservedAt time.Time `json:"observed_at"`
}
type SOCScanStats struct{
 Total int64 `json:"total"`
 Pending int64 `json:"pending"`
 Leased int64 `json:"leased"`
 Succeeded int64 `json:"succeeded"`
 Failed int64 `json:"failed"`
 Cancelled int64 `json:"cancelled"`
 Malicious int64 `json:"malicious"`
}
const listSOCJobsSQL=`SELECT job_id::text,agent_id,scan_root,state,attempt_count,created_at,updated_at
FROM edr_scan_jobs WHERE tenant_id=$1 AND ($2='' OR state=$2)
ORDER BY created_at DESC,job_id DESC LIMIT $3 OFFSET $4`
const getSOCJobSQL=`SELECT job_id::text,agent_id,scan_root,state,attempt_count,created_at,updated_at
FROM edr_scan_jobs WHERE tenant_id=$1 AND job_id=$2::uuid`
const listSOCResultsSQL=`SELECT job_id::text,agent_id,engine,verdict,threat_name,detail,observed_at
FROM edr_scan_job_results WHERE tenant_id=$1
AND ($2='' OR agent_id=$2) AND ($3='' OR verdict=$3)
ORDER BY observed_at DESC,job_id DESC LIMIT $4 OFFSET $5`
const getSOCResultSQL=`SELECT job_id::text,agent_id,engine,verdict,threat_name,detail,observed_at
FROM edr_scan_job_results WHERE tenant_id=$1 AND job_id=$2::uuid`
const getSOCStatsSQL=`SELECT count(*),
 count(*) FILTER(WHERE state='pending'),
 count(*) FILTER(WHERE state='leased'),
 count(*) FILTER(WHERE state='succeeded'),
 count(*) FILTER(WHERE state='failed'),
 count(*) FILTER(WHERE state='cancelled')
 FROM edr_scan_jobs WHERE tenant_id=$1`
const getSOCMaliciousCountSQL=`SELECT count(*) FROM edr_scan_job_results
 WHERE tenant_id=$1 AND verdict='malicious'`

func validSOCReader(p SOCOperatorPrincipal)bool{
 return validQueueIdentity(p.TenantID,p.OperatorID)&&
  (p.Role=="viewer"||p.Role=="scanner")
}
func validSOCPage(limit,offset int)bool{return limit>=1&&limit<=100&&offset>=0&&offset<=10000}
func validSOCJobState(state string)bool{
 switch state {
 case "","pending","leased","succeeded","failed","cancelled":return true
 }
 return false
}
func validSOCVerdict(v string)bool{
 switch v {
 case "","malicious","clean_by_signature","error","unscanned":return true
 }
 return false
}
func(q PostgresScanJobQueue) ListSOCJobs(ctx context.Context,p SOCOperatorPrincipal,
 state string,limit,offset int)([]SOCJobView,error){
 if !validSOCReader(p){return nil,ErrSOCForbidden}
 if !validSOCPage(limit,offset)||!validSOCJobState(state){return nil,ErrInvalidScanQueueRequest}
 if q.DB==nil{return nil,ErrScanQueueUnavailable}
 rows,err:=q.DB.QueryContext(ctx,listSOCJobsSQL,p.TenantID,state,limit,offset)
 if err!=nil{return nil,fmt.Errorf("%w: list jobs",ErrScanQueueUnavailable)}
 defer rows.Close()
 items:=make([]SOCJobView,0)
 for rows.Next(){
  var j SOCJobView
  if rows.Scan(&j.JobID,&j.AgentID,&j.ScanRoot,&j.State,&j.Attempts,
   &j.CreatedAt,&j.UpdatedAt)!=nil{return nil,ErrScanQueueUnavailable}
  items=append(items,j)
 }
 if rows.Err()!=nil{return nil,ErrScanQueueUnavailable}
 return items,nil
}
func(q PostgresScanJobQueue) GetSOCJob(ctx context.Context,p SOCOperatorPrincipal,
 id string)(*SOCJobView,error){
 if !validSOCReader(p){return nil,ErrSOCForbidden}
 if !validUUID(id){return nil,ErrInvalidScanQueueRequest}
 if q.DB==nil{return nil,ErrScanQueueUnavailable}
 var j SOCJobView
 err:=q.DB.QueryRowContext(ctx,getSOCJobSQL,p.TenantID,id).Scan(
  &j.JobID,&j.AgentID,&j.ScanRoot,&j.State,&j.Attempts,&j.CreatedAt,&j.UpdatedAt)
 if errors.Is(err,sql.ErrNoRows){return nil,nil}
 if err!=nil{return nil,ErrScanQueueUnavailable}
 return &j,nil
}
func(q PostgresScanJobQueue) ListSOCResults(ctx context.Context,p SOCOperatorPrincipal,
 agent,verdict string,limit,offset int)([]SOCResultView,error){
 if !validSOCReader(p){return nil,ErrSOCForbidden}
 if !validSOCPage(limit,offset)||!validSOCVerdict(verdict)||
  (agent!=""&&!validQueueIdentity(p.TenantID,agent)){
  return nil,ErrInvalidScanQueueRequest
 }
 if q.DB==nil{return nil,ErrScanQueueUnavailable}
 rows,err:=q.DB.QueryContext(ctx,listSOCResultsSQL,p.TenantID,agent,verdict,limit,offset)
 if err!=nil{return nil,ErrScanQueueUnavailable}
 defer rows.Close()
 items:=make([]SOCResultView,0)
 for rows.Next(){
  var item SOCResultView
  if rows.Scan(&item.JobID,&item.AgentID,&item.Engine,&item.Verdict,
    &item.ThreatName,&item.Detail,&item.ObservedAt)!=nil{
   return nil,ErrScanQueueUnavailable
  }
  items=append(items,item)
 }
 if rows.Err()!=nil{return nil,ErrScanQueueUnavailable}
 return items,nil
}
func(q PostgresScanJobQueue) GetSOCResult(ctx context.Context,p SOCOperatorPrincipal,
 id string)(*SOCResultView,error){
 if !validSOCReader(p){return nil,ErrSOCForbidden}
 if !validUUID(id){return nil,ErrInvalidScanQueueRequest}
 if q.DB==nil{return nil,ErrScanQueueUnavailable}
 var item SOCResultView
 err:=q.DB.QueryRowContext(ctx,getSOCResultSQL,p.TenantID,id).Scan(
  &item.JobID,&item.AgentID,&item.Engine,&item.Verdict,&item.ThreatName,
  &item.Detail,&item.ObservedAt)
 if errors.Is(err,sql.ErrNoRows){return nil,nil}
 if err!=nil{return nil,ErrScanQueueUnavailable}
 return &item,nil
}
func(q PostgresScanJobQueue) SOCStats(ctx context.Context,p SOCOperatorPrincipal)(*SOCScanStats,error){
 if !validSOCReader(p){return nil,ErrSOCForbidden}
 if q.DB==nil{return nil,ErrScanQueueUnavailable}
 var stats SOCScanStats
 err:=q.DB.QueryRowContext(ctx,getSOCStatsSQL,p.TenantID).Scan(
  &stats.Total,&stats.Pending,&stats.Leased,&stats.Succeeded,
  &stats.Failed,&stats.Cancelled)
 if err!=nil{return nil,ErrScanQueueUnavailable}
 err=q.DB.QueryRowContext(ctx,getSOCMaliciousCountSQL,p.TenantID).Scan(&stats.Malicious)
 if err!=nil{return nil,ErrScanQueueUnavailable}
 return &stats,nil
}
