package edr

import(
 "context"
 "database/sql"
 "errors"
 "fmt"
 "strings"
 "time"
)

type SOCAlertView struct{
 AlertID string `json:"alert_id"`
 JobID string `json:"job_id"`
 AgentID string `json:"agent_id"`
 Category string `json:"category"`
 Severity string `json:"severity"`
 SignatureName string `json:"signature_name"`
 State string `json:"state"`
 CreatedAt time.Time `json:"created_at"`
 UpdatedAt time.Time `json:"updated_at"`
 AcknowledgedBy string `json:"acknowledged_by,omitempty"`
 ResolvedBy string `json:"resolved_by,omitempty"`
 ResolutionNote string `json:"resolution_note,omitempty"`
 AssignedTo string `json:"assigned_to,omitempty"`
}
type SOCAlertCounts struct{
 Open int64 `json:"open"`
 Acknowledged int64 `json:"acknowledged"`
 Resolved int64 `json:"resolved"`
}
const listSOCAlertsSQL=`SELECT alert_id::text,job_id::text,agent_id,category,
 severity,signature_name,state,created_at,updated_at,
 COALESCE(acknowledged_by,''),COALESCE(resolved_by,''),resolution_note,COALESCE(assigned_to,'')
 FROM edr_soc_alerts WHERE tenant_id=$1 AND ($2='' OR state=$2)
 ORDER BY created_at DESC,alert_id DESC LIMIT $3 OFFSET $4`
const getSOCAlertSQL=`SELECT alert_id::text,job_id::text,agent_id,category,
 severity,signature_name,state,created_at,updated_at,
 COALESCE(acknowledged_by,''),COALESCE(resolved_by,''),resolution_note,COALESCE(assigned_to,'')
 FROM edr_soc_alerts WHERE tenant_id=$1 AND alert_id=$2::uuid`
const socAlertCountsSQL=`SELECT
 count(*) FILTER(WHERE state='open'),
 count(*) FILTER(WHERE state='acknowledged'),
 count(*) FILTER(WHERE state='resolved')
 FROM edr_soc_alerts WHERE tenant_id=$1`
const socChangeAlertSQL=`SELECT edr_soc_change_alert_state($1,$2,$3::uuid,$4,$5)`

func validSOCAlertState(v string)bool {
 return v==""||v=="open"||v=="acknowledged"||v=="resolved"
}
func socScanAlertRow(row interface{Scan(...any)error})(*SOCAlertView,error){
 var item SOCAlertView
 err:=row.Scan(&item.AlertID,&item.JobID,&item.AgentID,&item.Category,
  &item.Severity,&item.SignatureName,&item.State,&item.CreatedAt,
  &item.UpdatedAt,&item.AcknowledgedBy,&item.ResolvedBy,&item.ResolutionNote,&item.AssignedTo)
 if err!=nil{return nil,err}
 return &item,nil
}
func(q PostgresScanJobQueue) ListSOCAlerts(ctx context.Context,p SOCOperatorPrincipal,
 state string,limit,offset int)([]SOCAlertView,error){
 if !validSOCReader(p){return nil,ErrSOCForbidden}
 if !validSOCPage(limit,offset)||!validSOCAlertState(state){return nil,ErrInvalidScanQueueRequest}
 if q.DB==nil{return nil,ErrScanQueueUnavailable}
 rows,err:=q.DB.QueryContext(ctx,listSOCAlertsSQL,p.TenantID,state,limit,offset)
 if err!=nil{return nil,ErrScanQueueUnavailable}
 defer rows.Close()
 items:=make([]SOCAlertView,0)
 for rows.Next(){
  item,err:=socScanAlertRow(rows)
  if err!=nil{return nil,ErrScanQueueUnavailable}
  items=append(items,*item)
 }
 if rows.Err()!=nil{return nil,ErrScanQueueUnavailable}
 return items,nil
}
func(q PostgresScanJobQueue) GetSOCAlert(ctx context.Context,p SOCOperatorPrincipal,
 alertID string)(*SOCAlertView,error){
 if !validSOCReader(p){return nil,ErrSOCForbidden}
 if !validUUID(alertID){return nil,ErrInvalidScanQueueRequest}
 if q.DB==nil{return nil,ErrScanQueueUnavailable}
 item,err:=socScanAlertRow(q.DB.QueryRowContext(ctx,getSOCAlertSQL,p.TenantID,alertID))
 if errors.Is(err,sql.ErrNoRows){return nil,nil}
 if err!=nil{return nil,ErrScanQueueUnavailable}
 return item,nil
}
func(q PostgresScanJobQueue) ChangeSOCAlert(ctx context.Context,p SOCOperatorPrincipal,
 alertID,action,note string)(bool,error){
 if p.Role!="scanner"||!validQueueIdentity(p.TenantID,p.OperatorID){
  return false,ErrSOCForbidden
 }
 if !validUUID(alertID)||!strings.Contains("|ack|resolve|reopen|","|"+action+"|")||
  len(note)>1024||strings.ContainsAny(note,"\x00\r\n\t")||
  (action=="resolve"&&strings.TrimSpace(note)=="")||
  (action!="resolve"&&note!=""){
  return false,ErrInvalidScanQueueRequest
 }
 if q.DB==nil{return false,ErrScanQueueUnavailable}
 var ok bool
 err:=q.DB.QueryRowContext(ctx,socChangeAlertSQL,p.TenantID,p.OperatorID,
  alertID,action,note).Scan(&ok)
 if err!=nil{return false,fmt.Errorf("%w: alert transition failed",ErrScanQueueUnavailable)}
 return ok,nil
}
func(q PostgresScanJobQueue) SOCAlertStats(ctx context.Context,p SOCOperatorPrincipal)(*SOCAlertCounts,error){
 if !validSOCReader(p){return nil,ErrSOCForbidden}
 if q.DB==nil{return nil,ErrScanQueueUnavailable}
 var counts SOCAlertCounts
 err:=q.DB.QueryRowContext(ctx,socAlertCountsSQL,p.TenantID).Scan(
  &counts.Open,&counts.Acknowledged,&counts.Resolved)
 if err!=nil{return nil,ErrScanQueueUnavailable}
 return &counts,nil
}
