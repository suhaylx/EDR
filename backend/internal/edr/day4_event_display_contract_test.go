package edr

import (
    "strings"
    "testing"
)

// Day 4: the Go API must not accept metadata that the React lab decoder
// rejects and treats as an error for the entire 100-record response.
// Synthetic read-only fixtures, never live endpoint or malware evidence.
func TestDay4EventDisplayLimitsMatchFrontend(t *testing.T) {
    makeEvent:=func() Event {return Event{
        DeviceID:"linux-qa-01",Platform:"linux",Source:"procfs",
        SourceRecordID:"procfs:100:200",Type:"process_observed",
        Image:"/usr/bin/true",FilePath:"/tmp/benign-observed",
        Detail:"Synthetic testing only, no execution claim",
    }}
    cases:=[]struct{
        name string
        allowed bool
        mutate func(*Event)
    }{
        {"baseline-small-process-observation",true,func(e *Event){}},
        {"image-1024-bytes",true,func(e *Event){e.Image=strings.Repeat("a",1024)}},
        {"image-1025-bytes",false,func(e *Event){e.Image=strings.Repeat("a",1025)}},
        {"file-path-1024-bytes",true,func(e *Event){e.FilePath=strings.Repeat("b",1024)}},
        {"file-path-1025-bytes",false,func(e *Event){e.FilePath=strings.Repeat("b",1025)}},
        {"detail-4096-bytes",true,func(e *Event){e.Detail=strings.Repeat("c",4096)}},
        {"detail-4097-bytes",false,func(e *Event){e.Detail=strings.Repeat("c",4097)}},
        {"detail-newline-allowed",true,func(e *Event){e.Detail="line one\nline two"}},
        {"detail-nul-denied",false,func(e *Event){e.Detail="notice\x00hidden"}},
        {"image-del-denied",false,func(e *Event){e.Image="bad\x7fimage"}},
        {"image-replacement-char-denied",false,func(e *Event){e.Image="bad\ufffdimage"}},
        {"file-control-character-denied",false,func(e *Event){e.FilePath="/var/tmp/\x01hidden"}},
        {"type-control-character-denied",false,func(e *Event){e.Type="process_observed\x1b"}},
        {"source-control-character-denied",false,func(e *Event){e.Source="procfs\x01"}},
        {"image-bidi-override-denied",false,func(e *Event){e.Image="/tmp/benign\u202eexe.txt"}},
        {"file-path-isolate-denied",false,func(e *Event){e.FilePath="/tmp/\u2066suspicious"}},
        {"detail-directional-mark-denied",false,func(e *Event){e.Detail="notice\u200fhidden"}},
        {"process-guid-bidi-denied",false,func(e *Event){e.ProcessGUID="guid\u202e"}},
        {"parent-guid-bidi-denied",false,func(e *Event){e.ParentProcessGUID="guid\u2067"}},
        {"hash-bidi-denied",false,func(e *Event){e.Hash="sha\u202e"}},
        {"source-field-bidi-denied",false,func(e *Event){e.Platform="windows";e.Source="sysmon";e.Type="network_connect";e.SourceEventID=3;e.SourceFields=map[string]string{"destination_ip":"127.0.0.1\u202e"}}},
        {"boot-id-bidi-denied",false,func(e *Event){e.BootID="boot\u2069"}},
        {"source-record-id-bidi-denied",false,func(e *Event){e.SourceRecordID="procfs\u200e"}},

    }
    for _,tc:=range cases {
        t.Run(tc.name,func(t *testing.T){
            store:=NewStore()
            if _,err:=store.CheckIn(Agent{ID:"linux-qa-01",Platform:"linux"});err!=nil{t.Fatal(err)}
            e:=makeEvent();tc.mutate(&e)
            result,err:=store.Ingest(e)
            if !tc.allowed {
                if err==nil {t.Fatalf("malformed source accepted: %+v",result)}
                if len(store.Snapshot().Events)!=0 {
                    t.Fatal("rejected source modified the event store")
                }
                return
            }
            if err!=nil {t.Fatalf("safe source unexpectedly rejected: %v",err)}
            if result.Image!=e.Image || result.FilePath!=e.FilePath || result.Detail!=e.Detail {
                t.Fatalf("accepted evidence silently truncated: %+v",result)
            }
            if len(store.Snapshot().Events)!=1 {
                t.Fatal("accepted source not retained exactly once")
            }
        })
    }
}
