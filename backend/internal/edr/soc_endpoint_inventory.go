package edr

import (
 "context"
 "database/sql"
 "errors"
 "time"
)

// EndpointInventory describes reported endpoint health, NOT an attestation
// of endpoint integrity. Agent software and signature versions are untrusted
// device-reported telemetry. Never expose device credentials or lease tokens.
type EndpointInventory struct {
 AgentID string `json:"agent_id"`
 Platform string `json:"platform"`
 Health string `json:"health"` // online, degraded, stale, unseen, revoked
 AgentVersion string `json:"agent_version,omitempty"`
 ClamAVVersion string `json:"clamav_version,omitempty"`
 SignatureVersion string `json:"signature_version,omitempty"`
 ScanReady bool `json:"scan_ready"`
 LastSeen *time.Time `json:"last_seen,omitempty"`
 HeartbeatCount int64 `json:"heartbeat_count"`
}

type EndpointFleetSummary struct {
 Total int64 `json:"total"`
 Windows int64 `json:"windows"`
 Linux int64 `json:"linux"`
 Online int64 `json:"online"`
 Degraded int64 `json:"degraded"`
 Stale int64 `json:"stale"`
 Unseen int64 `json:"unseen"`
 Revoked int64 `json:"revoked"`
}

type EndpointActivity struct {
 ReferenceID string `json:"reference_id"`
 AgentID string `json:"agent_id"`
 Kind string `json:"kind"`
 State string `json:"state"`
 Detail string `json:"detail,omitempty"`
 OccurredAt time.Time `json:"occurred_at"`
}

// Only database now() determines freshness, so different SOC callers obtain
// consistent 5-minute classifications. A live but unready scanner is degraded.
const endpointInventoryCTE = `WITH inventory AS (
SELECT a.agent_id, a.platform,
 COALESCE(h.agent_version,'') AS agent_version,
 COALESCE(h.clamav_version,'') AS clamav_version,
 COALESCE(h.signature_version,'') AS signature_version,
 COALESCE(h.scan_ready,false) AS scan_ready,
 h.last_seen,
 COALESCE(h.received_count,0) AS received_count,
 CASE
  WHEN a.revoked_at IS NOT NULL THEN 'revoked'
  WHEN h.last_seen IS NULL THEN 'unseen'
  WHEN h.last_seen < CURRENT_TIMESTAMP-INTERVAL '5 minutes' THEN 'stale'
  WHEN h.scan_ready THEN 'online'
  ELSE 'degraded'
 END AS health
FROM edr_agents AS a
JOIN edr_tenants AS t ON t.tenant_id=a.tenant_id
LEFT JOIN edr_agent_heartbeats AS h
 ON h.tenant_id=a.tenant_id AND h.agent_id=a.agent_id
WHERE a.tenant_id=$1 AND t.disabled_at IS NULL
)`
const listEndpointsSQL=endpointInventoryCTE+`
SELECT agent_id,platform,agent_version,clamav_version,signature_version,
 scan_ready,last_seen,received_count,health
FROM inventory
WHERE ($2='' OR platform=$2) AND ($3='' OR health=$3)
ORDER BY agent_id LIMIT $4 OFFSET $5`
const getEndpointSQL=endpointInventoryCTE+`
SELECT agent_id,platform,agent_version,clamav_version,signature_version,
 scan_ready,last_seen,received_count,health
FROM inventory WHERE agent_id=$2`
const summaryEndpointsSQL=endpointInventoryCTE+`
SELECT count(*),
 count(*) FILTER(WHERE platform='windows'),
 count(*) FILTER(WHERE platform='linux'),
 count(*) FILTER(WHERE health='online'),
 count(*) FILTER(WHERE health='degraded'),
 count(*) FILTER(WHERE health='stale'),
 count(*) FILTER(WHERE health='unseen'),
 count(*) FILTER(WHERE health='revoked')
 FROM inventory`
const endpointActivitySQL=`
SELECT reference_id,agent_id,kind,state,detail,occurred_at FROM (
 SELECT j.job_id::text AS reference_id,j.agent_id,
 'scan_job'::text AS kind,j.state AS state,
 ''::text AS detail,j.created_at AS occurred_at
 FROM edr_scan_jobs AS j WHERE j.tenant_id=$1 AND j.agent_id=$2
 UNION ALL
 SELECT a.alert_id::text AS reference_id,a.agent_id,
 'malware_alert'::text AS kind,a.state AS state,
 a.signature_name AS detail,a.created_at AS occurred_at
 FROM edr_soc_alerts AS a WHERE a.tenant_id=$1 AND a.agent_id=$2
) AS activity
ORDER BY occurred_at DESC,reference_id DESC LIMIT $3`

func validEndpointHealth(v string) bool {
 switch v {
 case "","online","degraded","stale","unseen","revoked":return true
 }
 return false
}
func validEndpointPlatform(v string)bool {
 return v==""||v=="linux"||v=="windows"
}

type socScanner interface{Scan(...any)error}
func scanEndpointInventory(scanner socScanner)(*EndpointInventory,error){
 var item EndpointInventory
 var lastSeen sql.NullTime
 err:=scanner.Scan(&item.AgentID,&item.Platform,&item.AgentVersion,
  &item.ClamAVVersion,&item.SignatureVersion,&item.ScanReady,
  &lastSeen,&item.HeartbeatCount,&item.Health)
 if err!=nil{return nil,err}
 if lastSeen.Valid{
  timestamp:=lastSeen.Time.UTC()
  item.LastSeen=&timestamp
 }
 return &item,nil
}

func(q PostgresScanJobQueue) ListEndpoints(ctx context.Context,p SOCOperatorPrincipal,
 platform,health string,limit,offset int)([]EndpointInventory,error){
 if !validSOCReader(p){return nil,ErrSOCForbidden}
 if !validSOCPage(limit,offset)||!validEndpointPlatform(platform)||
  !validEndpointHealth(health){return nil,ErrInvalidScanQueueRequest}
 if q.DB==nil{return nil,ErrScanQueueUnavailable}
 rows,err:=q.DB.QueryContext(ctx,listEndpointsSQL,p.TenantID,platform,health,limit,offset)
 if err!=nil{return nil,ErrScanQueueUnavailable}
 defer rows.Close()
 out:=make([]EndpointInventory,0)
 for rows.Next(){
  item,e:=scanEndpointInventory(rows)
  if e!=nil{return nil,ErrScanQueueUnavailable}
  out=append(out,*item)
 }
 if rows.Err()!=nil{return nil,ErrScanQueueUnavailable}
 return out,nil
}

func(q PostgresScanJobQueue) GetEndpoint(ctx context.Context,p SOCOperatorPrincipal,
 agentID string)(*EndpointInventory,error){
 if !validSOCReader(p){return nil,ErrSOCForbidden}
 if !validID(agentID)||agentID=="."||agentID==".."{
  return nil,ErrInvalidScanQueueRequest
 }
 if q.DB==nil{return nil,ErrScanQueueUnavailable}
 item,err:=scanEndpointInventory(q.DB.QueryRowContext(ctx,getEndpointSQL,
  p.TenantID,agentID))
 if errors.Is(err,sql.ErrNoRows){return nil,nil}
 if err!=nil{return nil,ErrScanQueueUnavailable}
 return item,nil
}

func(q PostgresScanJobQueue) EndpointFleetStats(ctx context.Context,p SOCOperatorPrincipal)(
 *EndpointFleetSummary,error){
 if !validSOCReader(p){return nil,ErrSOCForbidden}
 if q.DB==nil{return nil,ErrScanQueueUnavailable}
 var s EndpointFleetSummary
 err:=q.DB.QueryRowContext(ctx,summaryEndpointsSQL,p.TenantID).Scan(
  &s.Total,&s.Windows,&s.Linux,&s.Online,&s.Degraded,&s.Stale,
  &s.Unseen,&s.Revoked)
 if err!=nil{return nil,ErrScanQueueUnavailable}
 return &s,nil
}

func(q PostgresScanJobQueue) EndpointTimeline(ctx context.Context,p SOCOperatorPrincipal,
 agentID string,limit int)([]EndpointActivity,error){
 if !validSOCReader(p){return nil,ErrSOCForbidden}
 if !validID(agentID)||agentID=="."||agentID==".."||
  limit<1||limit>100{return nil,ErrInvalidScanQueueRequest}
 if q.DB==nil{return nil,ErrScanQueueUnavailable}
 rows,err:=q.DB.QueryContext(ctx,endpointActivitySQL,p.TenantID,agentID,limit)
 if err!=nil{return nil,ErrScanQueueUnavailable}
 defer rows.Close()
 out:=make([]EndpointActivity,0)
 for rows.Next(){
  var a EndpointActivity
  if rows.Scan(&a.ReferenceID,&a.AgentID,&a.Kind,
   &a.State,&a.Detail,&a.OccurredAt)!=nil{return nil,ErrScanQueueUnavailable}
  out=append(out,a)
 }
 if rows.Err()!=nil{return nil,ErrScanQueueUnavailable}
 return out,nil
}
