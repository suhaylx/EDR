package edr

import (
    "bytes"
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "testing"
)

func TestLabSysmonHeartbeatAndObservedEventContract(t *testing.T) {
    server := &Server{Store: NewStore(), Token: "this-is-a-lab-token-123", WebDir: t.TempDir()}
    handler := server.Handler()

    request := func(method, path string, data any, token string) *httptest.ResponseRecorder {
        t.Helper()
        var payload []byte
        if data != nil {
            var err error
            payload, err = json.Marshal(data)
            if err != nil { t.Fatal(err) }
        }
        req := httptest.NewRequest(method, path, bytes.NewReader(payload))
        if data != nil { req.Header.Set("Content-Type", "application/json") }
        if token != "" { req.Header.Set("Authorization", "Bearer "+token) }
        rec := httptest.NewRecorder()
        handler.ServeHTTP(rec, req)
        return rec
    }
    token := "this-is-a-lab-token-123"
    event := map[string]any{
        "device_id": "win-lab-01", "platform": "windows", "source": "sysmon",
        "type": "process_create", "process_guid": "{A}", "parent_process_guid": "{B}",
        "image": "C:\\Windows\\System32\\cmd.exe",
        "detail": "Observed Sysmon Operational Event ID 1; Windows EventRecordID=12; command line not collected",
    }

    // Enforce enrollment and bearer auth before receiving telemetry.
    if rec := request("POST", "/api/events", event, token); rec.Code != http.StatusBadRequest {
        t.Fatalf("unregistered event: %d %s", rec.Code, rec.Body.String())
    }
    if rec := request("POST", "/api/agents",
        map[string]any{"id":"win-lab-01", "platform":"windows", "group":"lab", "health":"lab_unprotected"}, "");
        rec.Code != http.StatusUnauthorized {
        t.Fatalf("unauthenticated enrollment: %d", rec.Code)
    }
    rec := request("POST", "/api/agents",
        map[string]any{"id":"win-lab-01", "platform":"windows", "group":"lab", "health":"lab_unprotected"}, token)
    if rec.Code != http.StatusOK { t.Fatalf("heartbeat: %d %s", rec.Code, rec.Body.String()) }
    var agent Agent
    if err := json.Unmarshal(rec.Body.Bytes(), &agent); err != nil { t.Fatal(err) }
    if agent.ID != "win-lab-01" || agent.Platform != "windows" || agent.LastSeen.IsZero() {
        t.Fatalf("invalid observed registration: %+v", agent)
    }
    rec = request("POST", "/api/events", event, token)
    if rec.Code != http.StatusCreated { t.Fatalf("event ingest: %d %s", rec.Code, rec.Body.String()) }
    var observed Event
    if err := json.Unmarshal(rec.Body.Bytes(), &observed); err != nil { t.Fatal(err) }
    if observed.ID == "" || observed.Source != "sysmon" || observed.Type != "process_create" ||
        observed.ProcessGUID != "{A}" || observed.ParentProcessGUID != "{B}" || observed.Time.IsZero() {
        t.Fatalf("event provenance/lineage lost: %+v", observed)
    }
    rec = request("GET", "/api/overview?days=1", nil, token)
    if rec.Code != http.StatusOK { t.Fatalf("overview: %d %s", rec.Code, rec.Body.String()) }
    var overview struct {
        Agents int `json:"agents"`
        Events int `json:"events"`
        Alerts int `json:"alerts"`
    }
    if err := json.Unmarshal(rec.Body.Bytes(), &overview); err != nil { t.Fatal(err) }
    if overview.Agents != 1 || overview.Events != 1 || overview.Alerts != 0 {
        t.Fatalf("benign Sysmon process event must be visible but not automatically an alert: %+v", overview)
    }
}
