package edr

import (
    "context"
    "database/sql"
    "errors"
    "fmt"
    "strings"
)

// PostgresScanJobQueue is a durable storage adapter. It does NOT authenticate
// callers. Only a handler that has verified mTLS agent identity and matched
// the tenant/agent route may invoke Claim or Complete.
// Both *sql.DB (reads) and *sql.Tx (certificate-bound mutations) implement
// this interface. A mutation must not escape its authorization transaction.
type ScanQueryer interface {
 QueryContext(context.Context,string,...any)(*sql.Rows,error)
 QueryRowContext(context.Context,string,...any)*sql.Row
}
type PostgresScanJobQueue struct { DB ScanQueryer }

type ClaimedScanJob struct {
    JobID string
    ScanRoot string
    AttemptCount int
}

var ErrScanQueueUnavailable = errors.New("scan job queue unavailable")
var ErrInvalidScanQueueRequest = errors.New("invalid scan queue request")

const claimScanJobSQL = `SELECT job_id::text,scan_root,attempt_count
FROM edr_claim_scan_job($1,$2,$3,$4::uuid,$5)`
const renewScanJobSQL = `SELECT edr_renew_scan_job_lease($1,$2,$3::uuid,$4,$5::uuid,$6)`
const completeScanJobSQL = `SELECT edr_complete_scan_job($1,$2,$3::uuid,$4::uuid,$5)`
const recoverExpiredScanJobsSQL = `SELECT edr_recover_expired_scan_jobs($1)`

// Claim obtains at most one leased job; no rows means no pending work.
// LeaseToken must be generated with crypto/rand by the authenticated caller.
func (q PostgresScanJobQueue) Claim(ctx context.Context, tenantID, agentID, owner, leaseToken string, leaseSeconds int) (*ClaimedScanJob, error) {
    if !validQueueIdentity(tenantID,agentID) || strings.TrimSpace(owner)=="" || len(owner)>256 ||
        !validUUID(leaseToken) || leaseSeconds<5 || leaseSeconds>300 {
        return nil, ErrInvalidScanQueueRequest
    }
    if q.DB==nil { return nil,ErrScanQueueUnavailable }
    var j ClaimedScanJob
    err:=q.DB.QueryRowContext(ctx,claimScanJobSQL,tenantID,agentID,owner,leaseToken,leaseSeconds).
        Scan(&j.JobID,&j.ScanRoot,&j.AttemptCount)
    if errors.Is(err,sql.ErrNoRows) { return nil,nil }
    if err!=nil { return nil,fmt.Errorf("%w: claim failed",ErrScanQueueUnavailable) }
    if !validUUID(j.JobID) || j.ScanRoot=="" || j.AttemptCount<1 {
        return nil,ErrScanQueueUnavailable
    }
    return &j,nil
}

// Renew extends a still-active lease for the authenticated device and original worker.
// Authorization is rechecked transactionally in PostgreSQL.
func (q PostgresScanJobQueue) Renew(ctx context.Context,tenantID,agentID,jobID,owner,leaseToken string,leaseSeconds int)(bool,error){
    if !validQueueIdentity(tenantID,agentID) || !validUUID(jobID) ||
        strings.TrimSpace(owner)=="" || len(owner)>256 || !validUUID(leaseToken) ||
        leaseSeconds<5 || leaseSeconds>300 {
        return false,ErrInvalidScanQueueRequest
    }
    if q.DB==nil {return false,ErrScanQueueUnavailable}
    var renewed bool
    if err:=q.DB.QueryRowContext(ctx,renewScanJobSQL,tenantID,agentID,jobID,owner,leaseToken,leaseSeconds).Scan(&renewed);err!=nil {
        return false,fmt.Errorf("%w: renewal failed",ErrScanQueueUnavailable)
    }
    return renewed,nil
}

// Complete returns false when a job is absent, its lease expired, or the
// identity/token mismatches. Never treat false as successful completion.
func (q PostgresScanJobQueue) Complete(ctx context.Context,tenantID,agentID,jobID,leaseToken string,success bool)(bool,error){
    if !validQueueIdentity(tenantID,agentID) || !validUUID(jobID) || !validUUID(leaseToken) {
        return false,ErrInvalidScanQueueRequest
    }
    if q.DB==nil { return false,ErrScanQueueUnavailable }
    var completed bool
    if err:=q.DB.QueryRowContext(ctx,completeScanJobSQL,tenantID,agentID,jobID,leaseToken,success).Scan(&completed);err!=nil{
        return false,fmt.Errorf("%w: completion failed",ErrScanQueueUnavailable)
    }
    return completed,nil
}


const completeScanResultSQL = `SELECT edr_complete_scan_job_with_result($1,$2,$3::uuid,$4::uuid,$5,$6,$7)`

func validScanResult(verdict,threat,detail string)bool{
    switch verdict {
    case "clean_by_signature","error","unscanned":
        if threat!="" {return false}
    case "malicious":
        if strings.TrimSpace(threat)=="" {return false}
    default:
        return false
    }
    return len(threat)<=256 && len(detail)<=1024 &&
        !containsUnsafeSOCText(threat) &&
        !containsUnsafeSOCText(detail)
}

// CompleteWithResult consumes the authenticated, nonexpired lease and stores
// the actual clamd outcome atomically. A malware detection is a successful
// *scan*, not a clean verdict. Never use the old boolean-only endpoint for
// EDR malware detection reporting.
func(q PostgresScanJobQueue) CompleteWithResult(ctx context.Context,
    tenantID,agentID,jobID,leaseToken,verdict,threat,detail string)(bool,error){
    if !validQueueIdentity(tenantID,agentID)||!validUUID(jobID)||
        !validUUID(leaseToken)||!validScanResult(verdict,threat,detail){
        return false,ErrInvalidScanQueueRequest
    }
    if q.DB==nil{return false,ErrScanQueueUnavailable}
    var saved bool
    err:=q.DB.QueryRowContext(ctx,completeScanResultSQL,
        tenantID,agentID,jobID,leaseToken,verdict,threat,detail).Scan(&saved)
    if err!=nil{return false,fmt.Errorf("%w: result completion failed",ErrScanQueueUnavailable)}
    return saved,nil
}

// RecoverExpired is an administrative/worker operation, never an agent route.
func (q PostgresScanJobQueue) RecoverExpired(ctx context.Context,limit int)(int,error){
    if limit<1 || limit>1000 { return 0,ErrInvalidScanQueueRequest }
    if q.DB==nil { return 0,ErrScanQueueUnavailable }
    var n int
    if err:=q.DB.QueryRowContext(ctx,recoverExpiredScanJobsSQL,limit).Scan(&n);err!=nil{
        return 0,fmt.Errorf("%w: recovery failed",ErrScanQueueUnavailable)
    }
    if n<0 || n>limit { return 0,ErrScanQueueUnavailable }
    return n,nil
}

func validQueueIdentity(tenantID,agentID string)bool{
    return validID(tenantID)&&validID(agentID)&&tenantID!="."&&tenantID!=".."&&agentID!="."&&agentID!=".."
}

func validUUID(s string)bool{
    if len(s)!=36 { return false }
    for i,c:=range s {
        if i==8||i==13||i==18||i==23 {
            if c!='-' { return false }
        } else if !((c>='0'&&c<='9')||(c>='a'&&c<='f')||(c>='A'&&c<='F')) { return false }
    }
    return true
}
