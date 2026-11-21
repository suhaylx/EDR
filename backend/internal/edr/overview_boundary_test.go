package edr

import (
    "fmt"
    "testing"
    "time"
)

// Regression for SOC-001: the first displayed UTC date must be the same
// inclusive lower bound used by events, alerts, rule hits, and scan KPIs.
func TestSOCOverviewUTCCalendarBoundaryMatchesCounters(t *testing.T) {
    now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
    for _, days := range []int{1, 7, 30} {
        t.Run(fmt.Sprintf("%d_days", days), func(t *testing.T) {
            first := now.Truncate(24*time.Hour).AddDate(0, 0, -(days - 1))
            dll := `C:\Users\test\Temp\fixture.dll`
            host := `C:\Windows\System32\rundll32.exe`
            events := []Event{
                {ID: "prior", DeviceID: "win", Platform: "windows", Time: first.Add(-time.Second), Type: "module_load", FilePath: dll, ProcessGUID: "prior", Image: host},
                {ID: "inclusive", DeviceID: "win", Platform: "windows", Time: first, Type: "module_load", FilePath: dll, ProcessGUID: "inclusive", Image: host},
                {ID: "current", DeviceID: "win", Platform: "windows", Time: now, Type: "process_create", ProcessGUID: "current"},
                {ID: "future", DeviceID: "win", Platform: "windows", Time: now.Add(time.Second), Type: "process_create", ProcessGUID: "future"},
            }
            data := Snapshot{
                Agents: []Agent{{ID: "win", Platform: "windows", LastSeen: now}},
                Events: events,
            }
            scans := []ScanJob{
                {CreatedAt: first.Add(-time.Second), Status: "failed"},
                {CreatedAt: first, Status: "completed"},
                {CreatedAt: now.Add(time.Second), Status: "failed"},
            }
            got := BuildSOCOverview(data, scans, now, days)
            if got.Events != 2 || got.Alerts != 1 || got.Scans.Failed != 0 || got.Scans.Done != 1 {
                t.Fatalf("UTC window leaked prior/future records: days=%d events=%d alerts=%d scans=%+v", days, got.Events, got.Alerts, got.Scans)
            }
            if len(got.AlertTrend) != days || got.AlertTrend[0].Day != first.Format("2006-01-02") || got.AlertTrend[0].Count != 1 {
                t.Fatalf("UTC calendar boundary mismatch: days=%d trend=%+v", days, got.AlertTrend)
            }
            if len(got.TopRules) != 1 || got.TopRules[0].Count != 1 || got.HighRiskAlerts != 0 || got.Endpoints[0].Events != 2 || got.Endpoints[0].Alerts != 1 {
                t.Fatalf("KPI totals inconsistent with UTC chart: %+v", got)
            }
            total := 0
            for _, bucket := range got.AlertTrend { total += bucket.Count }
            if total != got.Alerts { t.Fatalf("chart/KPI mismatch: trend=%d alerts=%d", total, got.Alerts) }
        })
    }
}
