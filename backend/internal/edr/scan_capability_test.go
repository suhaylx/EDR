package edr

import (
    "testing"
    "time"
)

// Synthetic lab contract tests: no ClamAV daemon is invoked.
func TestUnsupportedQuickFullCannotReportScanSuccess(t *testing.T) {
    for _, mode := range []string{"quick", "full"} {
        for _, verdict := range []string{"clean_by_signature", "malicious", "suspicious"} {
            t.Run(mode+"/"+verdict, func(t *testing.T) {
                store := NewStore()
                if _, err := store.CheckIn(Agent{ID: "lab-agent", Platform: "linux"}); err != nil {
                    t.Fatal(err)
                }
                now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
                job, err := store.CreateScan(ScanRequest{
                    AgentID: "lab-agent", RequestID: "request-1", ScanType: mode,
                }, now)
                if err != nil { t.Fatal(err) }
                lease, ok, err := store.LeaseScan("lab-agent", now)
                if err != nil || !ok { t.Fatalf("lease failure: %v", err) }
                completion := ScanCompletion{
                    AgentID: "lab-agent", LeaseID: lease.LeaseID,
                    Engine: "clamav", Verdict: verdict,
                }
                if verdict == "malicious" { completion.ThreatName = "Eicar-Test-Signature" }
                if _, err = store.CompleteScan(job.ID, completion, now.Add(time.Second)); err == nil {
                    t.Fatalf("unsupported %s profile accepted %s verdict", mode, verdict)
                }
                before := store.ScanJobs()[0]
                if before.Status != "leased" || before.Verdict != "" {
                    t.Fatalf("rejected result corrupted scan state: %+v", before)
                }
                // A truthful unscanned result is allowed and must be failed, never completed.
                completion.Verdict, completion.ThreatName = "unscanned", ""
                result, err := store.CompleteScan(job.ID, completion, now.Add(2*time.Second))
                if err != nil || result.Status != "failed" || result.Verdict != "unscanned" {
                    t.Fatalf("truthful unscanned verdict rejected: %+v %v", result, err)
                }
            })
        }
    }
}

func TestUnsupportedScanWorkerErrorIsNotSuccessful(t *testing.T) {
    store := NewStore()
    if _, err := store.CheckIn(Agent{ID: "lab-agent", Platform: "windows"}); err != nil { t.Fatal(err) }
    now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
    job, err := store.CreateScan(ScanRequest{AgentID: "lab-agent", RequestID: "error-case", ScanType: "full"}, now)
    if err != nil { t.Fatal(err) }
    lease, ok, err := store.LeaseScan("lab-agent", now)
    if err != nil || !ok { t.Fatalf("lease failure: %v", err) }
    result, err := store.CompleteScan(job.ID, ScanCompletion{
        AgentID: "lab-agent", LeaseID: lease.LeaseID,
        Engine: "clamav", Verdict: "error", Detail: "worker offline",
    }, now.Add(time.Second))
    if err != nil || result.Status != "failed" || result.Verdict != "error" {
        t.Fatalf("failed scanner reported successful: %+v %v", result, err)
    }
}
