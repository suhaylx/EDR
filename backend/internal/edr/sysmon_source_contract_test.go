package edr

import (
    "strings"
    "testing"
)

func TestSysmonSourceIDTypeAndPrivacyContract(t *testing.T) {
    store:=NewStore()
    if _,err:=store.CheckIn(Agent{ID:"win-lab-01",Platform:"windows"});err!=nil{t.Fatal(err)}
    for sourceID,typ:=range expectedSysmonTypes {
        ev:=Event{
            DeviceID:"win-lab-01", Platform:"windows", Source:"sysmon",
            SourceEventID:sourceID, SourceRecordID:"99", Type:typ,
        }
        if sourceID==1 {
            ev.ProcessGUID="{valid-test-guid}"
            ev.Image="C:\\Windows\\System32\\notepad.exe"
            ev.ParentProcessGUID="{observed-parent}"
        }
        if sourceID==7 {ev.FilePath="C:\\Users\\lab\\Temp\\test.dll"}
        saved,err:=store.Ingest(ev)
        if err!=nil {t.Fatalf("Sysmon ID %d rejected valid metadata: %v",sourceID,err)}
        if saved.SourceEventID!=sourceID || saved.Type!=typ || saved.SourceRecordID!="99" {
            t.Fatalf("source provenance changed for ID %d: %+v",sourceID,saved)
        }
    }
    cases:=[]struct{name string; mut func(*Event)}{
        {"wrong type",func(e *Event){e.Type="process_create"}},
        {"wrong source",func(e *Event){e.Source="procfs"}},
        {"missing identity",func(e *Event){e.SourceRecordID="";e.SourceFields=map[string]string{"command_line":"secret"}}},
        {"forged parent",func(e *Event){e.ParentProcessGUID="{fake-parent}"}},
        {"secret field",func(e *Event){e.SourceFields=map[string]string{"command_line":"never-send"}}},
        {"control character",func(e *Event){e.SourceFields=map[string]string{"query_name":"bad\nmetadata"}}},
        {"invalid event id",func(e *Event){e.SourceEventID=30}},
    }
    for _,tc:=range cases {
        t.Run(tc.name,func(t *testing.T){
            e:=Event{DeviceID:"win-lab-01",Platform:"windows",Source:"sysmon",
                Type:"dns_query",SourceEventID:22,SourceRecordID:"103"}
            tc.mut(&e)
            if _,err:=store.Ingest(e);err==nil {
                t.Fatalf("invalid Sysmon source was accepted: %s",tc.name)
            }
        })
    }
    clip:=Event{DeviceID:"win-lab-01",Platform:"windows",Source:"sysmon",
        Type:"clipboard_change_metadata",SourceEventID:24,SourceRecordID:"200"}
    clip.Image="C:\\Users\\lab\\secret.txt"
    if _,err:=store.Ingest(clip);err==nil{t.Fatal("clipboard image payload must be rejected")}
    clip.Image="";clip.SourceFields=map[string]string{"query_name":"clipboard-secret"}
    if _,err:=store.Ingest(clip);err==nil{t.Fatal("clipboard metadata map must be rejected")}
    clip.SourceFields=nil
    if _,err:=store.Ingest(clip);err!=nil{t.Fatalf("minimal clipboard metadata should be allowed: %v",err)}
    missing:=Event{DeviceID:"win-lab-01",Platform:"windows",Source:"sysmon",
        Type:"process_create",SourceEventID:1,SourceRecordID:"201",Image:"C:\\Windows\\notepad.exe"}
    if _,err:=store.Ingest(missing);err==nil{t.Fatal("process create without actual GUID accepted")}
    if strings.Contains(strings.ToLower(store.Snapshot().Events[len(store.Snapshot().Events)-1].Detail),"secret"){
        t.Fatal("private rejected event content leaked into retained data")
    }
}
