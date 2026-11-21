package edr

import (
    "strings"
    "testing"
)

// SEC-076: A Windows Security 4688 record is not Sysmon EID1.
// Provider/channel are sender-reported (not authenticated), but inconsistent
// labels must never be accepted as Sysmon evidence or process lineage.
func TestSEC076SysmonProviderChannelMatching(t *testing.T) {
    store := NewStore()
    if _, err := store.CheckIn(Agent{ID:"win-sec076", Platform:"windows"}); err != nil {
        t.Fatal(err)
    }
    valid := Event{
        DeviceID:"win-sec076",Platform:"windows",Source:"sysmon",
        SourceProvider:"Microsoft-Windows-Sysmon",
        SourceChannel:"Microsoft-Windows-Sysmon/Operational",
        SourceEventID:1,SourceRecordID:"101",Type:"process_create",
        ProcessGUID:"{observed-guid}",Image:"C:\\Windows\\explorer.exe",
    }
    saved,err:=store.Ingest(valid)
    if err!=nil {t.Fatalf("real provider/channel claim rejected: %v",err)}
    if saved.SourceProvider!=valid.SourceProvider || saved.SourceChannel!=valid.SourceChannel {
        t.Fatalf("source identity lost in transport: %+v",saved)
    }
    if saved.TimeOrigin!="server_received" {
        t.Fatalf("source event time was not distinguished: %+v",saved)
    }
    cases := []struct{name string; mutate func(*Event)}{
        {"security-provider-4688-disguised-as-sysmon",func(e *Event){
            e.SourceProvider="Microsoft-Windows-Security-Auditing"
            e.SourceChannel="Security"
        }},
        {"powershell-scriptblock-channel",func(e *Event){
            e.SourceProvider="Microsoft-Windows-PowerShell"
            e.SourceChannel="Microsoft-Windows-PowerShell/Operational"
        }},
        {"system-service-install-channel",func(e *Event){
            e.SourceProvider="Service Control Manager"
            e.SourceChannel="System"
        }},
        {"wrong-sysmon-channel",func(e *Event){e.SourceChannel="Security"}},
        {"missing-channel",func(e *Event){e.SourceChannel=""}},
        {"missing-provider",func(e *Event){e.SourceProvider=""}},
        {"fake-linux-provider",func(e *Event){e.Platform="linux"}},
        {"fake-source",func(e *Event){e.Source="windows_security"}},
        {"unspecified-provider-with-channel",func(e *Event){e.SourceProvider=""}},
        {"oversized-channel",func(e *Event){e.SourceChannel=strings.Repeat("A",129)}},
        {"oversized-provider",func(e *Event){e.SourceProvider=strings.Repeat("A",97)}},
    }
    for _,tc:=range cases {
        t.Run(tc.name,func(t *testing.T){
            c:=valid
            tc.mutate(&c)
            if _,err:=store.Ingest(c);err==nil{
                t.Fatalf("untrusted provider mismatch accepted: %s",tc.name)
            }
        })
    }
    // Older lab events remain accepted, but their provider is NOT established.
    legacy:=valid
    legacy.SourceProvider=""
    legacy.SourceChannel=""
    old,err:=store.Ingest(legacy)
    if err!=nil {t.Fatalf("legacy event unexpectedly invalid: %v",err)}
    if old.SourceProvider!="" || old.SourceChannel!="" {
        t.Fatalf("legacy source provider must stay unknown: %+v",old)
    }
    // Explicitly mismatched source with no numerical event ID must fail too.
    noID:=Event{DeviceID:"win-sec076",Platform:"windows",Source:"procfs",
        Type:"process_observed",SourceProvider:"Microsoft-Windows-Sysmon",
        SourceChannel:"Microsoft-Windows-Sysmon/Operational"}
    if _,err:=store.Ingest(noID);err==nil{
        t.Fatal("non-Sysmon source claimed Sysmon identity")
    }
}

func TestSEC076ProviderDoesNotMagicallyAttestSource(t *testing.T) {
    e:=Event{
        DeviceID:"win-sec076",Platform:"windows",Source:"sysmon",
        SourceProvider:"Microsoft-Windows-Sysmon",
        SourceChannel:"Microsoft-Windows-Sysmon/Operational",
        Type:"process_create",SourceEventID:1,
        ProcessGUID:"{test-guid}",Image:"C:\\Windows\\explorer.exe",
    }
    // This API checks shape ONLY: cert/tenant-bound enrollment and signed
    // source attestation are separate gates and cannot be claimed from strings.
    if err:=validateEventProvider(e);err!=nil{t.Fatal(err)}
    e.SourceProvider="Microsoft-Windows-Security-Auditing"
    if err:=validateEventProvider(e);err==nil{t.Fatal("provider spoof accepted")}
}
