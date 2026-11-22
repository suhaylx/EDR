package edr

import (
    "bytes"
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "testing"
)

// The Linux lab collector intentionally sends observed procfs snapshots,
// not kernel process creation events or confirmed detections.
func TestLinuxProcfsHeartbeatAndObservedOnlyEvidenceContract(t *testing.T) {
    store := NewStore()
    srv := (&Server{Store: store, Token: "lab-token-abcdefghijklmnop", WebDir: t.TempDir()}).Handler()
    call := func(path string, body map[string]any) *httptest.ResponseRecorder {
        t.Helper()
        raw, err := json.Marshal(body)
        if err != nil { t.Fatal(err) }
        req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
        req.Header.Set("Authorization", "Bearer lab-token-abcdefghijklmnop")
        req.Header.Set("Content-Type", "application/json")
        out := httptest.NewRecorder()
        srv.ServeHTTP(out, req)
        return out
    }
    agent := call("/api/agents", map[string]any{
        "id": "linux-lab-01", "platform": "linux", "group": "lab",
        "health": "lab_unprotected",
    })
    if agent.Code != http.StatusOK {
        t.Fatalf("Linux heartbeat failed: %d %s", agent.Code, agent.Body.String())
    }
    process := call("/api/events", map[string]any{
        "device_id": "linux-lab-01", "platform": "linux",
        "source": "procfs", "source_record_id": "procfs:42:321",
        "type": "process_observed", "image": "/usr/bin/true",
        "detail": "Observed /proc inventory pid=42 ppid=1 start_ticks=321; not a process creation event",
    })
    if process.Code != http.StatusCreated {
        t.Fatalf("Linux snapshot ingestion failed: %d %s", process.Code, process.Body.String())
    }
    var saved Event
    if err := json.Unmarshal(process.Body.Bytes(), &saved); err != nil { t.Fatal(err) }
    if saved.ID == "" || saved.ReceivedAt.IsZero() {
        t.Fatalf("missing server-created event identity or receipt time: %#v", saved)
    }
    if saved.Type != "process_observed" || saved.Source != "procfs" || saved.SourceRecordID != "procfs:42:321" {
        t.Fatalf("invented or mutated source observation: %#v", saved)
    }
    if saved.ProcessGUID != "" || saved.ParentProcessGUID != "" || saved.TimeOrigin != "server_received" {
        t.Fatalf("procfs snapshot improperly asserted lineage or source time: %#v", saved)
    }
    snap := store.Snapshot()
    if len(snap.Agents) != 1 || len(snap.Events) != 1 {
        t.Fatalf("missing Linux agent/event: agents=%d events=%d", len(snap.Agents), len(snap.Events))
    }
    if signals := DetectSuspiciousDLLLoads(snap.Events); len(signals) != 0 {
        t.Fatalf("Linux procfs snapshot must not become a DLL/infection signal: %#v", signals)
    }
}
