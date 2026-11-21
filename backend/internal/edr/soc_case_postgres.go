package edr

import (
 "context"
 "database/sql"
 "errors"
 "fmt"
 "strings"
 "time"
)

// Alert activity is appended by database functions/triggers and never
// edited through HTTP. It is not a cryptographic audit log: a database
// superuser can bypass triggers, so DB privileges/backup remain essential.
type SOCAlertActivity struct {
 ActivityID string `json:"activity_id"`
 ActorID string `json:"actor_id"`
 Action string `json:"action"`
 Note string `json:"note,omitempty"`
 OccurredAt time.Time `json:"occurred_at"`
}

const assignSOCAlertSQL=`SELECT edr_soc_assign_alert($1,$2,$3::uuid,$4)`
const addSOCAlertNoteSQL=`SELECT edr_soc_add_alert_note($1,$2,$3::uuid,$4)::text`
const listSOCAlertActivitySQL=`SELECT activity_id::text,actor_id,action,note,occurred_at
FROM edr_soc_alert_activity
WHERE tenant_id=$1 AND alert_id=$2::uuid
ORDER BY occurred_at DESC,activity_id DESC LIMIT $3 OFFSET $4`
const listMySOCAlertsSQL=`SELECT alert_id::text,job_id::text,agent_id,category,
 severity,signature_name,state,created_at,updated_at,
 COALESCE(acknowledged_by,''),COALESCE(resolved_by,''),resolution_note,
 COALESCE(assigned_to,'')
 FROM edr_soc_alerts
 WHERE tenant_id=$1 AND assigned_to=$2 AND state<>'resolved'
 ORDER BY created_at DESC,alert_id DESC LIMIT $3 OFFSET $4`

func validSOCWriter(p SOCOperatorPrincipal)bool{
 return validQueueIdentity(p.TenantID,p.OperatorID)&&p.Role=="scanner"
}

func(q PostgresScanJobQueue) AssignSOCAlert(ctx context.Context,p SOCOperatorPrincipal,
 alertID,assignee string)(bool,error){
 if !validSOCWriter(p){return false,ErrSOCForbidden}
 if !validUUID(alertID)||len(assignee)>96||
  (assignee!=""&&(!validID(assignee)||assignee=="."||assignee=="..")){
  return false,ErrInvalidScanQueueRequest
 }
 if q.DB==nil{return false,ErrScanQueueUnavailable}
 var success bool
 err:=q.DB.QueryRowContext(ctx,assignSOCAlertSQL,p.TenantID,
  p.OperatorID,alertID,assignee).Scan(&success)
 if err!=nil{return false,fmt.Errorf("%w: assignment failed",ErrScanQueueUnavailable)}
 return success,nil
}

func(q PostgresScanJobQueue) AddSOCAlertNote(ctx context.Context,p SOCOperatorPrincipal,
 alertID,note string)(string,error){
 if !validSOCWriter(p){return "",ErrSOCForbidden}
 if !validUUID(alertID)||len(note)>2048||strings.TrimSpace(note)==""||
  strings.ContainsAny(note,"\x00\r\n\t"){
  return "",ErrInvalidScanQueueRequest
 }
 if q.DB==nil{return "",ErrScanQueueUnavailable}
 var id sql.NullString
 err:=q.DB.QueryRowContext(ctx,addSOCAlertNoteSQL,p.TenantID,
  p.OperatorID,alertID,note).Scan(&id)
 if err!=nil{return "",fmt.Errorf("%w: note insertion failed",ErrScanQueueUnavailable)}
 if !id.Valid{return "",ErrSOCConflict}
 if !validUUID(id.String){return "",ErrScanQueueUnavailable}
 return id.String,nil
}

func(q PostgresScanJobQueue) ListSOCAlertActivity(ctx context.Context,p SOCOperatorPrincipal,
 alertID string,limit,offset int)([]SOCAlertActivity,error){
 if !validSOCReader(p){return nil,ErrSOCForbidden}
 if !validUUID(alertID)||!validSOCPage(limit,offset){
  return nil,ErrInvalidScanQueueRequest
 }
 if q.DB==nil{return nil,ErrScanQueueUnavailable}
 rows,err:=q.DB.QueryContext(ctx,listSOCAlertActivitySQL,p.TenantID,alertID,limit,offset)
 if err!=nil{return nil,ErrScanQueueUnavailable}
 defer rows.Close()
 items:=make([]SOCAlertActivity,0)
 for rows.Next(){
  var item SOCAlertActivity
  if rows.Scan(&item.ActivityID,&item.ActorID,&item.Action,
    &item.Note,&item.OccurredAt)!=nil{return nil,ErrScanQueueUnavailable}
  items=append(items,item)
 }
 if rows.Err()!=nil{return nil,ErrScanQueueUnavailable}
 return items,nil
}

// MyAlerts returns active work assigned to the authenticated operator,
// instead of accepting an operator_id from client-controlled query fields.
func(q PostgresScanJobQueue) MySOCAlerts(ctx context.Context,p SOCOperatorPrincipal,
 limit,offset int)([]SOCAlertView,error){
 if !validSOCReader(p){return nil,ErrSOCForbidden}
 if !validSOCPage(limit,offset){return nil,ErrInvalidScanQueueRequest}
 if q.DB==nil{return nil,ErrScanQueueUnavailable}
 rows,err:=q.DB.QueryContext(ctx,listMySOCAlertsSQL,p.TenantID,
  p.OperatorID,limit,offset)
 if err!=nil{return nil,ErrScanQueueUnavailable}
 defer rows.Close()
 out:=make([]SOCAlertView,0)
 for rows.Next(){
  item,err:=socScanAlertRow(rows)
  if err!=nil{return nil,ErrScanQueueUnavailable}
  out=append(out,*item)
 }
 if rows.Err()!=nil{return nil,ErrScanQueueUnavailable}
 return out,nil
}

// Active assignment is never used as a substitute for operator mTLS auth.
var _=errors.Is
