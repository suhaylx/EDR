package edr

import (
    "reflect"
    "testing"
    "time"
)

// Day 3 P1 QA: a server-received heartbeat at exactly five minutes remains
// online; even one nanosecond older must no longer be represented as online.
// A future or absent timestamp is unknown, never decades of offline time.
func TestQASOCHardUTCAndHeartbeatBoundary(t *testing.T) {
    now := time.Date(2026,11,21,0,0,10,0,time.UTC)
    start := now.Truncate(24*time.Hour)
    data := Snapshot{
        Agents: []Agent{
            {ID:"exact-five-minutes",Platform:"windows",LastSeen:now.Add(-5*time.Minute),Health:"offline"},
            {ID:"one-nanosecond-too-old",Platform:"linux",LastSeen:now.Add(-5*time.Minute-time.Nanosecond),Health:"online"},
            {ID:"future",Platform:"windows",LastSeen:now.Add(time.Nanosecond),Health:"online"},
            {ID:"never",Platform:"linux",Health:"online"},
        },
        Events: []Event{
            {ID:"before-midnight",DeviceID:"exact-five-minutes",Platform:"windows",Type:"process_create",Time:start.Add(-time.Nanosecond)},
            {ID:"at-midnight",DeviceID:"exact-five-minutes",Platform:"windows",Type:"process_create",Time:start},
            {ID:"at-now",DeviceID:"one-nanosecond-too-old",Platform:"linux",Type:"process_observed",Time:now},
            {ID:"after-now",DeviceID:"one-nanosecond-too-old",Platform:"linux",Type:"process_observed",Time:now.Add(time.Nanosecond)},
        },
    }
    report := BuildSOCOverview(data,nil,now,1)
    if report.Online!=1 || report.Offline!=1 || report.Unknown!=2 ||
        report.Events!=2 || report.Alerts!=0 || report.HighRiskAlerts!=0 ||
        report.HeartbeatTTLSeconds!=300 {
        t.Fatalf("boundary counts wrong: %+v",report)
    }
    if len(report.Endpoints)!=4 ||
        report.Endpoints[0].Status!="online" ||
        report.Endpoints[1].Status!="offline" ||
        report.Endpoints[2].Status!="unknown" ||
        report.Endpoints[3].Status!="unknown" {
        t.Fatalf("heartbeat boundary incorrectly classified: %+v",report.Endpoints)
    }
    if report.Endpoints[2].InactiveSeconds!=0 || report.Endpoints[3].InactiveSeconds!=0 {
        t.Fatalf("unknown timestamp was converted into fictitious offline duration")
    }
    if len(report.AlertTrend)!=1 || report.AlertTrend[0].Day!="2026-11-21" {
        t.Fatalf("wrong UTC calendar day at midnight: %+v",report.AlertTrend)
    }
    // Time zone of the caller cannot change UTC evidence inclusion.
    localTime:=now.In(time.FixedZone("UZT",5*3600))
    localReport:=BuildSOCOverview(data,nil,localTime,1)
    if !reflect.DeepEqual(report,localReport) {
        t.Fatalf("different result for equivalent UTC+5 instant")
    }
}

// A policy being assigned, a detection rule firing, and a policy actually
// applied on an endpoint are three different operational states.
func TestQASOCAppliedPolicyDistinctFromAssignmentsAndAlerts(t *testing.T) {
    now:=time.Date(2026,11,21,14,0,0,0,time.UTC)
    data:=Snapshot{
        Agents:[]Agent{
            {ID:"applied",Platform:"windows",LastSeen:now,AppliedPolicyID:"policy-applied",AppliedRevision:3},
            {ID:"pending",Platform:"linux",LastSeen:now,LastPolicyError:"configuration rejected"},
            {ID:"stale",Platform:"windows",LastSeen:now,AppliedPolicyID:"policy-unknown"},
        },
        Policies:[]Policy{
            {ID:"policy-applied",Name:"Applied revision"},
            {ID:"policy-pending",Name:"Awaiting configuration"},
        },
        Assignments:[]Assignment{
            {TargetType:"agent",TargetID:"pending",Platform:"linux",PolicyID:"policy-pending"},
        },
    }
    report:=BuildSOCOverview(data,nil,now,7)
    if report.Policies!=2 || report.Assignments!=1 || report.PolicyErrors!=1 ||
        report.Alerts!=0 || report.HighRiskAlerts!=0 {
        t.Fatalf("false policy success or rule firings: %+v",report)
    }
    covers:=map[string]int{}
    for _,p:=range report.PolicyCoverage {covers[p.PolicyID]=p.Endpoints}
    if len(covers)!=2 || covers["policy-applied"]!=1 || covers["policy-unknown"]!=1 {
        t.Fatalf("assignment incorrectly counted as applied: %+v",report.PolicyCoverage)
    }
    if _,present:=covers["policy-pending"];present {
        t.Fatal("an assigned but unapplied policy was marked as installed")
    }
    if len(report.Unavailable)==0 || report.DataSource!="development_in_memory_retained_telemetry" {
        t.Fatal("lab reported verified fleet/security coverage without evidence")
    }
}

// Only observed, retained event timestamps inside a UTC calendar window can
// count as alerts; a suspicious DLL path is not a critical infection finding.
func TestQASOCOneDayEvent7BoundaryAndSeverity(t *testing.T) {
    now:=time.Date(2026,11,21,1,0,0,0,time.UTC)
    first:=now.Truncate(24*time.Hour)
    base:=Event{
        ID:"load-at-midnight",DeviceID:"win-lab",Platform:"windows",
        Type:"module_load",ProcessGUID:"{q1}",Image:"C:/Windows/System32/rundll32.exe",
        FilePath:"C:/Users/QA/AppData/Local/Temp/test.dll",Time:first,
    }
    old:=base
    old.ID="load-yesterday";old.Time=first.Add(-time.Nanosecond)
    future:=base
    future.ID="load-in-future";future.Time=now.Add(time.Nanosecond)
    report:=BuildSOCOverview(Snapshot{
        Agents:[]Agent{{ID:"win-lab",Platform:"windows",LastSeen:now}},
        Events:[]Event{old,base,future},
    },nil,now,1)
    if report.Events!=1 || report.Alerts!=1 || report.HighRiskAlerts!=0 ||
        len(report.TopRules)!=1 || report.TopRules[0].RuleID!="TURAN-WIN-DLL-LOAD-001" ||
        report.TopRules[0].Severity!="medium" ||
        len(report.AlertTrend)!=1 || report.AlertTrend[0].Count!=1 {
        t.Fatalf("unsafe UTC or false critical alert: %+v",report)
    }
}
