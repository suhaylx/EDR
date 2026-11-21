package edr

import (
    "bytes"
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "testing"
    "time"
)

// AV-002 regression (#33): an idempotent API response must never disclose
// the active delivery capability; only the intended scan-lease endpoint may.
func TestScanLeaseCapabilityRedactedOnIdempotentStoreResponses(t *testing.T) {
    s := NewStore()
    if _, err := s.CheckIn(Agent{ID: "qa-win", Platform: "windows"}); err != nil {
        t.Fatal(err)
    }
    now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
    req := ScanRequest{AgentID: "qa-win", RequestID: "qa-retry-1", ScanType: "path", Path: `C:\Lab\file.txt`}
    job, err := s.CreateScan(req, now)
    if err != nil { t.Fatal(err) }
    leased, ok, err := s.LeaseScan(req.AgentID, now)
    if err != nil || !ok || leased.LeaseID == "" {
        t.Fatalf("lease failed: %v, ok=%t", err, ok)
    }

    dup, err := s.CreateScan(req, now.Add(time.Second))
    if err != nil || dup.ID != job.ID || dup.Status != "leased" || dup.LeaseID != "" {
        t.Fatalf("repeated create exposed active lease: %+v, err=%v", dup, err)
    }
    if history := s.ScanJobs(); len(history) != 1 || history[0].LeaseID != "" {
        t.Fatalf("job listing exposed capability: %+v", history)
    }
    result := ScanCompletion{
        AgentID: req.AgentID, LeaseID: leased.LeaseID,
        Engine: "clamav", Verdict: "clean_by_signature",
    }
    first, err := s.CompleteScan(job.ID, result, now.Add(2*time.Second))
    if err != nil || first.Status != "completed" || first.LeaseID != "" {
        t.Fatalf("first completion exposed capability: %+v, err=%v", first, err)
    }
    repeated, err := s.CompleteScan(job.ID, result, now.Add(3*time.Second))
    if err != nil || repeated.Status != "completed" || repeated.LeaseID != "" {
        t.Fatalf("idempotent completion exposed capability: %+v, err=%v", repeated, err)
    }
    if _, err := s.CompleteScan(job.ID, ScanCompletion{
        AgentID: req.AgentID, LeaseID: "wrong-lease",
        Engine: "clamav", Verdict: "clean_by_signature",
    }, now.Add(4*time.Second)); err == nil {
        t.Fatal("completion accepted an invalid lease after completion")
    }
}

func TestScanLeaseCapabilityRedactedFromIdempotentHTTPJSON(t *testing.T) {
    s := &Server{Store: NewStore(), Token: "qa-lab-token-only", WebDir: t.TempDir()}
    h := s.Handler()
    api := func(method, path string, body any) *httptest.ResponseRecorder {
        t.Helper()
        var raw []byte
        if body != nil {
            var err error
            raw, err = json.Marshal(body)
            if err != nil { t.Fatal(err) }
        }
        req := httptest.NewRequest(method, path, bytes.NewReader(raw))
        req.Header.Set("Authorization", "Bearer qa-lab-token-only")
        if method == http.MethodPost { req.Header.Set("Content-Type", "application/json") }
        w := httptest.NewRecorder()
        h.ServeHTTP(w, req)
        return w
    }
    checkJob := func(label string, r *httptest.ResponseRecorder, want int) ScanJob {
        t.Helper()
        if r.Code != want { t.Fatalf("%s: status=%d body=%s", label, r.Code, r.Body.String()) }
        var job ScanJob
        if err := json.Unmarshal(r.Body.Bytes(), &job); err != nil {
            t.Fatalf("%s: decode: %v", label, err)
        }
        return job
    }
    enrollment := api("POST", "/api/agents", Agent{ID: "qa-win", Platform: "windows"})
    if enrollment.Code != 200 { t.Fatalf("checkin: %d %s", enrollment.Code, enrollment.Body.String()) }
    scan := ScanRequest{AgentID: "qa-win", RequestID: "qa-retry-http", ScanType: "quick"}
    created := checkJob("create", api("POST", "/api/scan-jobs", scan), 201)
    lease := checkJob("lease", api("POST", "/api/agents/qa-win/scan-lease", struct{}{}), 200)
    if lease.LeaseID == "" { t.Fatal("leased agent did not receive capability") }

    retry := checkJob("repeat create", api("POST", "/api/scan-jobs", scan), 201)
    if retry.ID != created.ID || retry.LeaseID != "" {
        t.Fatalf("repeat create exposed capability: %+v", retry)
    }
    result := ScanCompletion{AgentID: "qa-win", LeaseID: lease.LeaseID, Engine: "clamav", Verdict: "unscanned"}
    first := checkJob("first completion", api("POST", "/api/scan-jobs/"+created.ID+"/result", result), 200)
    again := checkJob("repeat completion", api("POST", "/api/scan-jobs/"+created.ID+"/result", result), 200)
    if first.LeaseID != "" || again.LeaseID != "" || first.Status != "failed" || again.Status != "failed" {
        t.Fatalf("completion emitted lease capability or wrong state: first=%+v again=%+v", first, again)
    }
    listing := api("GET", "/api/scan-jobs", nil)
    if listing.Code != 200 { t.Fatalf("history status=%d", listing.Code) }
    var jobs []ScanJob
    if err := json.Unmarshal(listing.Body.Bytes(), &jobs); err != nil || len(jobs) != 1 ||
        jobs[0].LeaseID != "" {
        t.Fatalf("history exposed capability: %v %+v", err, jobs)
    }
}
