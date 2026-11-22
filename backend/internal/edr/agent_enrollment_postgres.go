package edr

import (
    "context"
    "database/sql"
    "errors"
    "fmt"
    "time"
)

// EnrollmentAuthorization is an explicit approval produced by an external,
// authenticated enrollment/issuance service. Do not construct it from raw
// unauthenticated HTTP input. Proof-of-possession and certificate SAN/chain
// validation must occur BEFORE calling CompleteInitialEnrollment.
type EnrollmentAuthorization struct {
    ChallengeID string
    TenantID string
    AgentID string
    Platform string
    ChallengeDigest [32]byte
    CertificateFingerprint [32]byte
    CertificateNotBefore time.Time
    CertificateNotAfter time.Time
    ActorID string
}

var ErrEnrollmentInvalid = errors.New("invalid enrollment authorization")
var ErrEnrollmentUnavailable = errors.New("enrollment database unavailable")

type PostgresEnrollmentStore struct { DB *sql.DB }

const completeInitialEnrollmentSQL = `SELECT edr_complete_agent_enrollment(
    $1::uuid,$2,$3,$4,$5,$6,$7,$8,$9)`

// CompleteInitialEnrollment is a storage boundary, not an enrollment endpoint.
// false means the challenge was invalid, expired, already consumed, or the
// tenant/device was ineligible. A database error is never treated as approval.
func (s PostgresEnrollmentStore) CompleteInitialEnrollment(ctx context.Context, a EnrollmentAuthorization)(bool,error){
    if !validUUID(a.ChallengeID)||!validQueueIdentity(a.TenantID,a.AgentID)||
        (a.Platform!="windows"&&a.Platform!="linux")||
        len(a.ActorID)<1||len(a.ActorID)>256||
        a.CertificateNotBefore.IsZero()||a.CertificateNotAfter.IsZero()||
        !a.CertificateNotBefore.Before(a.CertificateNotAfter)||
        a.CertificateNotAfter.Before(time.Now().UTC())||
        a.CertificateNotBefore.After(time.Now().UTC()){
        return false,ErrEnrollmentInvalid
    }
    if s.DB==nil {return false,ErrEnrollmentUnavailable}
    var enrolled bool
    err:=s.DB.QueryRowContext(ctx,completeInitialEnrollmentSQL,
        a.ChallengeID,a.TenantID,a.AgentID,a.ChallengeDigest[:],
        a.Platform,a.CertificateFingerprint[:],
        a.CertificateNotBefore,a.CertificateNotAfter,a.ActorID).Scan(&enrolled)
    if err!=nil{return false,fmt.Errorf("%w: atomic registration failed",ErrEnrollmentUnavailable)}
    return enrolled,nil
}
