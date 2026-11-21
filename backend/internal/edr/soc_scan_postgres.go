package edr

import (
 "context"
 "database/sql"
 "errors"
 "fmt"
)

var ErrSOCForbidden=errors.New("SOC operation forbidden")
var ErrSOCConflict=errors.New("SOC request conflicts with existing state")

const operatorScheduleSQL=`SELECT job_id::text,created
FROM edr_enqueue_operator_scan_job($1,$2,$3,$4::uuid,$5,$6)`
const operatorCancelSQL=`SELECT edr_cancel_operator_scan_job($1,$2,$3::uuid)`
const operatorAgentPlatformSQL=`SELECT a.platform FROM edr_agents AS a
JOIN edr_tenants AS t ON t.tenant_id=a.tenant_id
WHERE a.tenant_id=$1 AND a.agent_id=$2 AND a.revoked_at IS NULL
 AND t.disabled_at IS NULL`

type ScheduledSOCJob struct{
 JobID string `json:"job_id"`
 Created bool `json:"created"`
}
func(q PostgresScanJobQueue) ScheduleSOCScan(ctx context.Context,p SOCOperatorPrincipal,
 agentID,requestKey,scanRoot string)(*ScheduledSOCJob,error){
 if p.Role!="scanner"||!validQueueIdentity(p.TenantID,p.OperatorID){
  return nil,ErrSOCForbidden
 }
 if !validID(agentID)||!validID(requestKey)||agentID=="."||agentID==".."||
   requestKey=="."||requestKey==".."||len(scanRoot)==0||len(scanRoot)>4096||
   containsUnsafeSOCText(scanRoot){
  return nil,ErrInvalidScanQueueRequest
 }
 if q.DB==nil {return nil,ErrScanQueueUnavailable}
 var platform string
 if err:=q.DB.QueryRowContext(ctx,operatorAgentPlatformSQL,p.TenantID,agentID).
  Scan(&platform);err!=nil{
  if errors.Is(err,sql.ErrNoRows){return nil,ErrSOCForbidden}
  return nil,fmt.Errorf("%w: target lookup failed",ErrScanQueueUnavailable)
 }
 // Only path scans are currently supported by the Rust agent. Quick/full
 // are never synthesized or represented as successfully completed.
 if !scanPathAllowed(platform,scanRoot){return nil,ErrInvalidScanQueueRequest}
 jobToken,err:=NewScanLeaseToken()
 if err!=nil{return nil,ErrScanQueueUnavailable}
 var result ScheduledSOCJob
 err=q.DB.QueryRowContext(ctx,operatorScheduleSQL,p.TenantID,p.OperatorID,
  agentID,jobToken,requestKey,scanRoot).Scan(&result.JobID,&result.Created)
 if errors.Is(err,sql.ErrNoRows){return nil,ErrSOCConflict}
 if err!=nil{return nil,fmt.Errorf("%w: schedule failed",ErrScanQueueUnavailable)}
 if !validUUID(result.JobID){return nil,ErrScanQueueUnavailable}
 return &result,nil
}
func(q PostgresScanJobQueue) CancelSOCScan(ctx context.Context,p SOCOperatorPrincipal,
 jobID string)(bool,error){
 if p.Role!="scanner"||!validQueueIdentity(p.TenantID,p.OperatorID){
  return false,ErrSOCForbidden
 }
 if !validUUID(jobID){return false,ErrInvalidScanQueueRequest}
 if q.DB==nil{return false,ErrScanQueueUnavailable}
 var cancelled bool
 err:=q.DB.QueryRowContext(ctx,operatorCancelSQL,
  p.TenantID,p.OperatorID,jobID).Scan(&cancelled)
 if err!=nil{return false,fmt.Errorf("%w: cancellation failed",ErrScanQueueUnavailable)}
 return cancelled,nil
}
