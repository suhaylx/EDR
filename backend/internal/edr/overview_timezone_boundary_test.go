package edr

import (
    "testing"
    "time"
)

// A SOC day is a UTC calendar day, not the operator's local calendar day.
// This case guards the boundary when telemetry arrives with +05:00 timestamps.
func TestSOCOverviewUTCWindowWithTashkentTimestampOffsets(t *testing.T) {
    local := time.FixedZone("Asia/Tashkent", 5*60*60)
    now := time.Date(2026, 11, 21, 17, 0, 0, 0, local) // 12:00 UTC
    justBefore := time.Date(2026, 11, 21, 4, 59, 59, 999999999, local)
    utcMidnight := time.Date(2026, 11, 21, 5, 0, 0, 0, local)
    dll := `C:\Users\qa\Temp\fixture.dll`
    image := `C:\Windows\System32\rundll32.exe`

    snapshot := Snapshot{
        Agents: []Agent{{ID: "qa-win", Platform: "windows", LastSeen: now}},
        Events: []Event{
            {ID: "prev-utc-day", DeviceID: "qa-win", Platform: "windows", Time: justBefore,
                Type: "module_load", FilePath: dll, ProcessGUID: "previous", Image: image},
            {ID: "at-utc-midnight", DeviceID: "qa-win", Platform: "windows", Time: utcMidnight,
                Type: "module_load", FilePath: dll, ProcessGUID: "included", Image: image},
            {ID: "at-now", DeviceID: "qa-win", Platform: "windows", Time: now, Type: "process_create"},
            {ID: "after-now", DeviceID: "qa-win", Platform: "windows", Time: now.Add(time.Nanosecond),
                Type: "process_create"},
        },
    }
    scans := []ScanJob{
        {CreatedAt: justBefore, Status: "failed"},
        {CreatedAt: utcMidnight, Status: "queued"},
        {CreatedAt: now.Add(time.Nanosecond), Status: "completed"},
    }
    got := BuildSOCOverview(snapshot, scans, now, 1)

    if got.Events != 2 || got.Endpoints[0].Events != 2 {
        t.Fatalf("UTC midnight event filtering: events=%d endpoint=%+v", got.Events, got.Endpoints[0])
    }
    if got.Alerts != 1 || got.Endpoints[0].Alerts != 1 ||
        len(got.TopRules) != 1 || got.TopRules[0].Count != 1 {
        t.Fatalf("alerts/rules include wrong UTC dates: alerts=%d endpoint=%+v rules=%+v",
            got.Alerts, got.Endpoints[0], got.TopRules)
    }
    if len(got.AlertTrend) != 1 || got.AlertTrend[0].Day != "2026-11-21" ||
        got.AlertTrend[0].Count != got.Alerts {
        t.Fatalf("UTC day/chart/KPI mismatch: %+v alerts=%d", got.AlertTrend, got.Alerts)
    }
    if got.Scans.Queued != 1 || got.Scans.Failed != 0 || got.Scans.Done != 0 {
        t.Fatalf("UTC scan-window filtering: %+v", got.Scans)
    }
}
