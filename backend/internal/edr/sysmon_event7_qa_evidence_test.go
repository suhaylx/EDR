package edr

import (
    "strings"
    "testing"
    "time"
)

// Synthetic Windows Sysmon evidence only. The lab API records source IDs as
// sender-reported; these tests do NOT assert trusted endpoint provenance.
// FileCreate (Event 11) cannot prove that a module was loaded (Event 7).
func qaEvidencePair() (Event, Event) {
    at := time.Date(2026,11,21,14,0,0,0,time.UTC)
    hash := strings.Repeat("a",64)
    path := `C:\Users\QA\AppData\Local\Temp\component.dll`
    create := Event{
        ID:"create-11", Source:"sysmon", SourceEventID:11,
        SourceRecordID:"100", Platform:"windows", DeviceID:"win-lab",
        Type:"file_create", FilePath:path, Hash:hash, BootID:"boot-1",
        ProcessGUID:"{process-1}", Time:at.Add(-5*time.Minute),
    }
    load := Event{
        ID:"load-7", Source:"sysmon", SourceEventID:7,
        SourceRecordID:"101", Platform:"windows", DeviceID:"win-lab",
        Type:"module_load", FilePath:path, Hash:hash, BootID:"boot-1",
        ProcessGUID:"{process-1}", Time:at,
        Image:`C:\Windows\System32\rundll32.exe`,
    }
    return create,load
}

// Confirm each missing observation suppresses a module-load detection rather
// than turning "not captured" into an invented malicious execution claim.
func TestQASysmonEvent7MinimalEvidenceGate(t *testing.T) {
    create, base := qaEvidencePair()
    if got:=DetectSuspiciousDLLLoads([]Event{create});len(got)!=0 {
        t.Fatalf("Event 11 alone was treated as executed DLL: %#v",got)
    }
    cases:=[]struct{name string; change func(*Event)}{
        {"missing-event-identity",func(e *Event){e.ID=""}},
        {"event-id-with-whitespace",func(e *Event){e.ID=" load-7 "}},
        {"missing-device",func(e *Event){e.DeviceID=""}},
        {"missing-process-guid",func(e *Event){e.ProcessGUID=""}},
        {"missing-process-image",func(e *Event){e.Image=""}},
        {"missing-event-time",func(e *Event){e.Time=time.Time{}}},
        {"non-windows-source",func(e *Event){e.Platform="linux"}},
        {"creation-is-not-a-load",func(e *Event){e.Type="file_create"}},
        {"non-dll-extension",func(e *Event){e.FilePath=`C:\Users\QA\Temp\component.txt`}},
        {"system-directory-is-not-user-writable-heuristic",func(e *Event){e.FilePath=`C:\Windows\System32\kernel32.dll`}},
        {"unknown-event-type",func(e *Event){e.Type="unknown"}},
    }
    for _,tc:=range cases{
        t.Run(tc.name,func(t *testing.T){
            load:=base
            tc.change(&load)
            if got:=DetectSuspiciousDLLLoads([]Event{create,load});len(got)!=0{
                t.Fatalf("insufficient Event 7 evidence gave detection: %#v",got)
            }
        })
    }
    alerts:=DetectSuspiciousDLLLoads([]Event{create,base})
    if len(alerts)!=1 || alerts[0].LoadEventID!="load-7" ||
        alerts[0].FileCreateEventID!="create-11" ||
        alerts[0].Confidence!="low" || alerts[0].Severity!="medium" {
        t.Fatalf("conservative observed load provenance missing: %#v",alerts)
    }
}

// File-create evidence can enrich a later load only if host/boot/process/path,
// temporal ordering and a full matching SHA-256 are consistent.
func TestQASysmonEvent7CreateCorrelationNegativeMatrix(t *testing.T){
    originalCreate,originalLoad:=qaEvidencePair()
    cases:=[]struct{name string;mutate func(*Event,*Event)}{
        {"cross-device",func(c,l *Event){c.DeviceID="win-other"}},
        {"cross-boot",func(c,l *Event){c.BootID="boot-else"}},
        {"missing-create-boot",func(c,l *Event){c.BootID=""}},
        {"missing-load-boot",func(c,l *Event){l.BootID=""}},
        {"cross-process",func(c,l *Event){c.ProcessGUID="{unrelated}"}},
        {"creation-after-load",func(c,l *Event){c.Time=l.Time.Add(time.Minute)}},
        {"creation-more-than-24h-ago",func(c,l *Event){c.Time=l.Time.Add(-25*time.Hour)}},
        {"different-sha256",func(c,l *Event){c.Hash=strings.Repeat("b",64)}},
        {"missing-create-hash",func(c,l *Event){c.Hash=""}},
        {"missing-load-hash",func(c,l *Event){l.Hash=""}},
        {"invalid-create-hash",func(c,l *Event){c.Hash="SHA256=unknown"}},
        {"different-path",func(c,l *Event){c.FilePath=`C:\Users\QA\Temp\another.dll`}},
        {"create-source-is-wrong-platform",func(c,l *Event){c.Platform="linux"}},
        {"create-type-not-file-create",func(c,l *Event){c.Type="process_create"}},
        {"create-without-id",func(c,l *Event){c.ID=""}},
        {"create-without-time",func(c,l *Event){c.Time=time.Time{}}},
    }
    for _,tc:=range cases{
        t.Run(tc.name,func(t *testing.T){
            create,load:=originalCreate,originalLoad
            tc.mutate(&create,&load)
            alerts:=DetectSuspiciousDLLLoads([]Event{create,load})
            if len(alerts)!=1 || alerts[0].FileCreateEventID!=""{
                t.Fatalf("unsafe FileCreate-to-Event7 provenance correlation: %#v",alerts)
            }
            if alerts[0].LoadEventID!="load-7"{
                t.Fatalf("the real load event must remain primary: %#v",alerts)
            }
        })
    }
}

func TestQASysmonEvent7DedupAndExplicitNonCausality(t *testing.T){
    create,load:=qaEvidencePair()
    results:=DetectSuspiciousDLLLoads([]Event{load,create,load,create})
    if len(results)!=1{
        t.Fatalf("duplicates generated multiple Event 7 detections: %#v",results)
    }
    result:=results[0]
    if result.LoadSourceRecordID!="101"||result.LoadEventID!="load-7"||
        result.FileCreateEventID!="create-11" ||
        result.RuleID!="TURAN-WIN-DLL-LOAD-001"{
        t.Fatalf("source provenance missing: %#v",result)
    }
    if strings.Contains(strings.ToLower(result.Explanation),"confirmed infection") ||
        strings.Contains(strings.ToLower(result.Explanation),"caused by") ||
        result.Confidence!="low" || result.Severity=="critical"{
        t.Fatalf("lab evidence falsely claimed causation/infection: %#v",result)
    }
    newer:=load
    newer.BootID="boot-2"
    newer.ID="load-7-other-boot"
    if got:=DetectSuspiciousDLLLoads([]Event{load,newer});len(got)!=2{
        t.Fatalf("distinct boots were improperly merged: %#v",got)
    }
}
