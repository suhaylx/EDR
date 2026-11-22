package edr

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSOCOverviewHeartbeatCountsAndInactivity(t *testing.T) {
	now := time.Date(2026, 11, 21, 11, 0, 0, 0, time.UTC)
	agents := []Agent{
		{ID: "online", Platform: "windows", LastSeen: now.Add(-4 * time.Minute), Health: "offline"}, // client health must not decide online
		{ID: "boundary", Platform: "linux", LastSeen: now.Add(-5 * time.Minute)},
		{ID: "yesterday", Platform: "linux", LastSeen: now.Add(-49 * time.Hour), Health: "online", LastPolicyError: "update failed"},
		{ID: "never", Platform: "windows"},
		{ID: "future", Platform: "windows", LastSeen: now.Add(time.Second)},
	}
	report := BuildSOCOverview(Snapshot{Agents: agents}, nil, now, 7)
	if report.Agents != 5 || report.Online != 2 || report.Offline != 1 || report.Unknown != 2 || report.PolicyErrors != 1 {
		t.Fatalf("incorrect heartbeat metrics: %+v", report)
	}
	if len(report.InactiveMachines) != 3 || report.InactiveMachines[0].ID != "yesterday" || report.InactiveMachines[0].InactiveDays < 2.04 || report.InactiveMachines[0].InactiveDays > 2.05 {
		t.Fatalf("incorrect inactive sorting/days: %+v", report.InactiveMachines)
	}
	if report.Endpoints[0].Status != "online" || report.Endpoints[2].Status != "offline" {
		t.Fatalf("user-reported health improperly trusted: %+v", report.Endpoints)
	}
	if len(report.AlertTrend) != 7 || report.AlertTrend[0].Day != "2026-11-15" {
		t.Fatalf("daily trend uses wrong UTC dates: %+v", report.AlertTrend)
	}
}

func TestSOCOverviewAlertsTopRulesAndActivity(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	dll := `C:\Users\user\Temp\evil.dll`
	old := now.AddDate(0, 0, -14)
	data := Snapshot{Agents: []Agent{{ID: "workstation", Platform: "windows", LastSeen: now.Add(-time.Minute)}, {ID: "db", Platform: "linux", LastSeen: now.Add(-48 * time.Hour)}},
		Events: []Event{
			{ID: "c", DeviceID: "workstation", Platform: "windows", Time: now.Add(-time.Hour), Type: "file_create", FilePath: dll},
			{ID: "l", DeviceID: "workstation", Platform: "windows", Time: now.Add(-30 * time.Minute), Type: "module_load", FilePath: dll, ProcessGUID: "A", Image: `C:\Windows\System32\rundll32.exe`},
			{ID: "proc", DeviceID: "db", Platform: "linux", Time: now.Add(-2 * time.Hour), Type: "process_create"},
			{ID: "old", DeviceID: "workstation", Platform: "windows", Time: old, Type: "module_load", FilePath: dll, ProcessGUID: "X", Image: `C:\Windows\System32\rundll32.exe`},
			{ID: "future", DeviceID: "workstation", Platform: "windows", Time: now.Add(time.Hour), Type: "process_create"},
		},
	}
	report := BuildSOCOverview(data, nil, now, 7)
	if report.Events != 3 || report.Alerts != 1 || report.HighRiskAlerts != 0 || len(report.TopRules) != 1 || report.TopRules[0].RuleID != dllPathRuleID || report.TopRules[0].Count != 1 {
		t.Fatalf("incorrect detection totals: %+v", report)
	}
	if report.MostActive[0].ID != "workstation" || report.MostActive[0].Events != 2 || report.MostActive[0].Alerts != 1 {
		t.Fatalf("most-active ranking incorrect: %+v", report.MostActive)
	}
	if report.InactiveMachines[0].ID != "db" || report.InactiveMachines[0].Events != 1 || report.AlertTrend[6].Count != 1 {
		t.Fatalf("inactive host events or alert trend inaccurate: %+v", report)
	}
	for _, b := range report.Severity {
		if b.Severity == "medium" && b.Count != 1 {
			t.Fatalf("wrong medium severity: %+v", report.Severity)
		}
		if b.Severity == "critical" && b.Count != 0 {
			t.Fatalf("unsupported critical incidents invented: %+v", report.Severity)
		}
	}
	oneDay := BuildSOCOverview(data, nil, now, 1)
	if oneDay.Alerts != 1 || len(oneDay.AlertTrend) != 1 {
		t.Fatalf("wrong 1-day window %+v", oneDay)
	}
	none := BuildSOCOverview(Snapshot{}, nil, now, 30)
	if none.Agents != 0 || len(none.Severity) != 5 || len(none.AlertTrend) != 30 || len(none.MostActive) != 0 {
		t.Fatal("empty fleet report should contain explicit zeroes")
	}
}

func TestSOCOverviewPolicyUseAndScanErrors(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	data := Snapshot{
		Policies: []Policy{{ID: "policy-1", Name: "Test policy"}},
		Agents:   []Agent{{ID: "a", LastSeen: now, AppliedPolicyID: "policy-1"}, {ID: "b", LastSeen: now, AppliedPolicyID: "policy-1"}},
	}
	scans := []ScanJob{{CreatedAt: now, Status: "completed"}, {CreatedAt: now, Status: "failed"}, {CreatedAt: now, Status: "queued"}, {CreatedAt: now.Add(-40 * 24 * time.Hour), Status: "failed"}}
	report := BuildSOCOverview(data, scans, now, 7)
	if len(report.PolicyCoverage) != 1 || report.PolicyCoverage[0].Endpoints != 2 || report.PolicyCoverage[0].PolicyName != "Test policy" || report.Scans.Done != 1 || report.Scans.Failed != 1 || report.Scans.Queued != 1 {
		t.Fatalf("bad policy coverage/scan states: %+v", report)
	}
}

func TestSOCOverviewHTTPRequiresAuthAndValidWindow(t *testing.T) {
	srv := (&Server{Store: NewStore(), Token: "example-development-token", WebDir: t.TempDir()}).Handler()
	call := func(days, token string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest("GET", "/api/overview?days="+days, nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		return rec
	}
	if c := call("7", ""); c.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated overview status %d", c.Code)
	}
	if c := call("366", "example-development-token"); c.Code != http.StatusBadRequest {
		t.Fatalf("unbounded window accepted %d", c.Code)
	}
	if c := call("-1", "example-development-token"); c.Code != http.StatusBadRequest {
		t.Fatalf("negative window accepted %d", c.Code)
	}
	c := call("30", "example-development-token")
	if c.Code != http.StatusOK {
		t.Fatalf("overview request rejected %d", c.Code)
	}
	var result SOCOverview
	if err := json.Unmarshal(c.Body.Bytes(), &result); err != nil || result.WindowDays != 30 || len(result.AlertTrend) != 30 {
		t.Fatalf("bad overview JSON %v %s", err, c.Body.String())
	}
}
