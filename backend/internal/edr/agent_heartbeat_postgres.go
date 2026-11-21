package edr

import (
 "context"
 "database/sql"
 "errors"
 "fmt"
 "time"
)

// AgentHeartbeat is untrusted device telemetry bound to an authenticated
// enrolled device by AgentHTTPGuard. Version fields are NOT attestation.
type AgentHeartbeat struct {
 Platform string `json:"platform"`
 AgentVersion string `json:"agent_version"`
 ClamAVVersion string `json:"clamav_version"`
 SignatureVersion string `json:"signature_version"`
 ScanReady bool `json:"scan_ready"`
}
type AgentHeartbeatStatus struct {
 AgentHeartbeat
 LastSeen time.Time `json:"last_seen"`
 ReceivedCount int64 `json:"received_count"`
}
const recordHeartbeatSQL = `SELECT edr_record_agent_heartbeat($1,$2,$3,$4,$5,$6,$7)`
const heartbeatStatusSQL = `SELECT h.platform,h.agent_version,h.clamav_version,
h.signature_version,h.scan_ready,h.last_seen,h.received_count
FROM edr_agent_heartbeats AS h JOIN edr_tenants AS t
ON t.tenant_id=h.tenant_id JOIN edr_agents AS a
ON a.tenant_id=h.tenant_id AND a.agent_id=h.agent_id
WHERE h.tenant_id=$1 AND h.agent_id=$2
AND t.disabled_at IS NULL AND a.revoked_at IS NULL`

func validHeartbeat(h AgentHeartbeat) bool {
 if h.Platform!="linux" && h.Platform!="windows" {return false}
 for i,value:=range []string{h.AgentVersion,h.ClamAVVersion,h.SignatureVersion} {
  limit:=64; if i==2{limit=96}
  if len(value)>limit || (i==0&&len(value)==0) || containsUnsafeSOCText(value) {return false}
 }
 return true
}

// RecordHeartbeat writes one current health/capability snapshot; the database
// re-checks that tenant, enrolled device and platform are still active.
func(q PostgresScanJobQueue) RecordHeartbeat(ctx context.Context,
 tenantID,agentID string,h AgentHeartbeat)(bool,error) {
 if !validQueueIdentity(tenantID,agentID)||!validHeartbeat(h){return false,ErrInvalidScanQueueRequest}
 if q.DB==nil{return false,ErrScanQueueUnavailable}
 var saved bool
 err:=q.DB.QueryRowContext(ctx,recordHeartbeatSQL,tenantID,agentID,h.Platform,
  h.AgentVersion,h.ClamAVVersion,h.SignatureVersion,h.ScanReady).Scan(&saved)
 if err!=nil{return false,fmt.Errorf("%w: heartbeat failed",ErrScanQueueUnavailable)}
 return saved,nil
}

// HeartbeatStatus reads only the mTLS-authenticated device's current snapshot.
func(q PostgresScanJobQueue) HeartbeatStatus(ctx context.Context,
 tenantID,agentID string)(*AgentHeartbeatStatus,error){
 if !validQueueIdentity(tenantID,agentID){return nil,ErrInvalidScanQueueRequest}
 if q.DB==nil{return nil,ErrScanQueueUnavailable}
 var status AgentHeartbeatStatus
 err:=q.DB.QueryRowContext(ctx,heartbeatStatusSQL,tenantID,agentID).Scan(
  &status.Platform,&status.AgentVersion,&status.ClamAVVersion,
  &status.SignatureVersion,&status.ScanReady,&status.LastSeen,&status.ReceivedCount)
 if errors.Is(err,sql.ErrNoRows){return nil,nil}
 if err!=nil{return nil,fmt.Errorf("%w: heartbeat lookup failed",ErrScanQueueUnavailable)}
 return &status,nil
}
