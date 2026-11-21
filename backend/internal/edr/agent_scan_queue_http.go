package edr

import (
    "encoding/json"
    "io"
    "net/http"
    "strings"
)

// AgentScanQueueHandler is intended to be mounted ONLY behind AgentHTTPGuard.
// The guard verifies the mTLS certificate, tenant/device identity and route.
// This handler must never be mounted directly on a public or operator listener.
func AgentScanQueueHandler(queue PostgresScanJobQueue) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
        w.Header().Set("Cache-Control","no-store")
        w.Header().Set("Content-Type","application/json")
        principal,ok:=AgentIdentityFromContext(r.Context())
        if !ok { http.Error(w,"unauthorized",http.StatusUnauthorized);return }
        requested,valid:=agentRouteIdentity(r.URL)
        if !valid||requested!=principal { http.Error(w,"forbidden",http.StatusForbidden);return }
        if r.URL.RawQuery!="" { http.Error(w,"invalid query",http.StatusBadRequest);return }
        prefix:="/agent/v1/tenants/"+principal.TenantID+"/agents/"+principal.AgentID+"/"
        operation:=strings.TrimPrefix(r.URL.Path,prefix)
        if operation=="scan-jobs/claim" {
            if r.Method!=http.MethodPost { w.Header().Set("Allow","POST");http.Error(w,"method not allowed",http.StatusMethodNotAllowed);return }
            // Only the authenticated device can claim its own work.
            // A random lease token is created server-side; never trust client tokens for claiming.
            token,err:=NewScanLeaseToken()
            if err!=nil {http.Error(w,"service unavailable",http.StatusServiceUnavailable);return}
            job,err:=queue.Claim(r.Context(),principal.TenantID,principal.AgentID,principal.AgentID,token,60)
            if err!=nil {http.Error(w,"service unavailable",http.StatusServiceUnavailable);return}
            if job==nil {w.WriteHeader(http.StatusNoContent);return}
            _=json.NewEncoder(w).Encode(struct{
                JobID string `json:"job_id"`
                ScanRoot string `json:"scan_root"`
                AttemptCount int `json:"attempt_count"`
                LeaseToken string `json:"lease_token"`
            }{job.JobID,job.ScanRoot,job.AttemptCount,token})
            return
        }
        if operation=="scan-jobs/renew" {
            if r.Method!=http.MethodPost {w.Header().Set("Allow","POST");http.Error(w,"method not allowed",http.StatusMethodNotAllowed);return}
            r.Body=http.MaxBytesReader(w,r.Body,4096)
            var payload struct{
                JobID string `json:"job_id"`
                LeaseToken string `json:"lease_token"`
                LeaseSeconds int `json:"lease_seconds"`
            }
            decoder:=json.NewDecoder(r.Body)
            decoder.DisallowUnknownFields()
            if err:=decoder.Decode(&payload);err!=nil {
                http.Error(w,"invalid payload",http.StatusBadRequest);return
            }
            var extra json.RawMessage
            if err:=decoder.Decode(&extra);err!=io.EOF {
                http.Error(w,"multiple payloads",http.StatusBadRequest);return
            }
            if !validUUID(payload.JobID)||!validUUID(payload.LeaseToken)||
                payload.LeaseSeconds<5||payload.LeaseSeconds>300 {
                http.Error(w,"invalid payload",http.StatusBadRequest);return
            }
            // Lease owner is server-derived from the mTLS-authenticated agent.
            renewed,err:=queue.Renew(r.Context(),principal.TenantID,principal.AgentID,
                payload.JobID,principal.AgentID,payload.LeaseToken,payload.LeaseSeconds)
            if err!=nil {http.Error(w,"service unavailable",http.StatusServiceUnavailable);return}
            if !renewed {http.Error(w,"job not found or lease expired",http.StatusConflict);return}
            w.WriteHeader(http.StatusNoContent)
            return
        }
        if operation=="scan-jobs/complete" {
            if r.Method!=http.MethodPost {w.Header().Set("Allow","POST");http.Error(w,"method not allowed",http.StatusMethodNotAllowed);return}
            r.Body=http.MaxBytesReader(w,r.Body,4096)
            var payload struct{
                JobID string `json:"job_id"`
                LeaseToken string `json:"lease_token"`
                Success *bool `json:"success"`
            }
            decoder:=json.NewDecoder(r.Body)
            decoder.DisallowUnknownFields()
            if err:=decoder.Decode(&payload);err!=nil||payload.Success==nil{
                http.Error(w,"invalid payload",http.StatusBadRequest);return
            }
            var extra json.RawMessage
            if err:=decoder.Decode(&extra);err!=io.EOF{
                http.Error(w,"multiple payloads",http.StatusBadRequest);return
            }
            if !validUUID(payload.JobID)||!validUUID(payload.LeaseToken){
                http.Error(w,"invalid payload",http.StatusBadRequest);return
            }
            done,err:=queue.Complete(r.Context(),principal.TenantID,principal.AgentID,payload.JobID,payload.LeaseToken,*payload.Success)
            if err!=nil {http.Error(w,"service unavailable",http.StatusServiceUnavailable);return}
            if !done {http.Error(w,"job not found or lease expired",http.StatusConflict);return}
            w.WriteHeader(http.StatusNoContent)
            return
        }
        http.NotFound(w,r)
    })
}
