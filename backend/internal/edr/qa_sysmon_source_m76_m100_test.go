package edr

import (
    "strings"
    "testing"
    "time"
)

// QA M76–M100: 25 executable, synthetic source-integrity regression cases.
// These exercise the existing Go development ingestion boundary, not a real
// Windows collector, authenticated device transport, PostgreSQL or malware.
// All supplied event IDs, images, dates and source metadata are test fixtures.
func TestQAM76ToM100SysmonSourcePrivacyMatrix(t *testing.T) {
    timestamp := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
    base := func() Event {
        return Event{
            DeviceID: "qa-win-01",
            Platform: "windows",
            Source: "sysmon",
            SourceEventID: 22,
            SourceRecordID: "900",
            Type: "dns_query",
            Time: timestamp,
            Detail: "Synthetic fixture; no real endpoint detection",
        }
    }
    cases := []struct {
        name string
        valid bool
        mutate func(*Event)
    }{
        {"M76-process-create-original-parent-only", true, func(e *Event) {
            e.SourceEventID=1;e.Type="process_create";e.ProcessGUID="{qa-process}"
            e.ParentProcessGUID="{qa-parent}";e.Image="C:\\Windows\\System32\\notepad.exe"
        }},
        {"M77-network-connection-metadata", true, func(e *Event) {
            e.SourceEventID=3;e.Type="network_connect"
            e.SourceFields=map[string]string{"destination_ip":"10.0.0.4","destination_port":"443","protocol":"tcp"}
        }},
        {"M78-real-reported-module-path", true, func(e *Event) {
            e.SourceEventID=7;e.Type="module_load"
            e.FilePath="C:\\Users\\QA\\Temp\\benign.dll"
            e.SourceFields=map[string]string{"image_loaded":"C:\\Users\\QA\\Temp\\benign.dll"}
        }},
        {"M79-sensitive-process-access-record", true, func(e *Event) {
            e.SourceEventID=10;e.Type="process_access"
            e.SourceFields=map[string]string{"source_image":"C:\\Windows\\explorer.exe","target_image":"C:\\Windows\\System32\\lsass.exe"}
        }},
        {"M80-registry-change-bounded-object", true, func(e *Event) {
            e.SourceEventID=13;e.Type="registry_value_set"
            e.SourceFields=map[string]string{"target_object":"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Test"}
        }},
        {"M81-wmi-binding-source-ID", true, func(e *Event) {
            e.SourceEventID=21;e.Type="wmi_binding"
        }},
        {"M82-dns-query-with-allowlisted-domain", true, func(e *Event) {
            e.SourceFields=map[string]string{"query_name":"example.test"}
        }},
        {"M83-clipboard-metadata-only", true, func(e *Event) {
            e.SourceEventID=24;e.Type="clipboard_change_metadata"
        }},
        {"M84-process-tampering-source-ID", true, func(e *Event) {
            e.SourceEventID=25;e.Type="process_tampering";e.ProcessGUID="{qa-process}"
        }},
        {"M85-sysmon-health-error-not-infection", true, func(e *Event) {
            e.SourceEventID=255;e.Type="sysmon_error"
        }},
        {"M86-unrecognized-Event30-denied", false, func(e *Event) {
            e.SourceEventID=30;e.Type="future_extension"
        }},
        {"M87-zero-ID-with-fields-denied", false, func(e *Event) {
            e.SourceEventID=0;e.SourceFields=map[string]string{"query_name":"example.test"}
        }},
        {"M88-non-Windows-Sysmon-source-denied", false, func(e *Event) {
            e.Platform="linux"
        }},
        {"M89-numeric-ID-and-event-type-mismatch-denied", false, func(e *Event) {
            e.Type="process_create"
        }},
        {"M90-process-create-without-GUID-denied", false, func(e *Event) {
            e.SourceEventID=1;e.Type="process_create";e.Image="C:\\Windows\\System32\\notepad.exe"
        }},
        {"M91-process-create-without-image-denied", false, func(e *Event) {
            e.SourceEventID=1;e.Type="process_create";e.ProcessGUID="{qa-process}"
        }},
        {"M92-DLL-load-with-forged-parent-denied", false, func(e *Event) {
            e.SourceEventID=7;e.Type="module_load";e.ParentProcessGUID="{forged-parent}"
        }},
        {"M93-clipboard-file-path-denied", false, func(e *Event) {
            e.SourceEventID=24;e.Type="clipboard_change_metadata";e.FilePath="C:\\Sensitive\\notes.txt"
        }},
        {"M94-clipboard-image-denied", false, func(e *Event) {
            e.SourceEventID=24;e.Type="clipboard_change_metadata";e.Image="C:\\Sensitive\\notes.txt"
        }},
        {"M95-clipboard-process-identity-denied", false, func(e *Event) {
            e.SourceEventID=24;e.Type="clipboard_change_metadata";e.ProcessGUID="{private-process}"
        }},
        {"M96-clipboard-extra-metadata-denied", false, func(e *Event) {
            e.SourceEventID=24;e.Type="clipboard_change_metadata"
            e.SourceFields=map[string]string{"query_name":"private.example"}
        }},
        {"M97-commandline-or-credential-field-denied", false, func(e *Event) {
            e.SourceFields=map[string]string{"command_line":"secret-token"}
        }},
        {"M98-control-character-in-source-field-denied", false, func(e *Event) {
            e.SourceFields=map[string]string{"query_name":"line\nbreak"}
        }},
        {"M99-oversized-source-metadata-denied", false, func(e *Event) {
            e.SourceFields=map[string]string{"query_name":strings.Repeat("x",513)}
        }},
        {"M100-control-character-in-record-ID-denied", false, func(e *Event) {
            e.SourceRecordID="900\n901"
        }},
    }
    if len(cases)!=25 {
        t.Fatalf("QA milestone count changed unexpectedly: %d",len(cases))
    }
    for _,tc := range cases {
        t.Run(tc.name,func(t *testing.T){
            store:=NewStore()
            if _,err:=store.CheckIn(Agent{ID:"qa-win-01",Platform:"windows"});err!=nil{
                t.Fatal(err)
            }
            event:=base()
            tc.mutate(&event)
            saved,err:=store.Ingest(event)
            snapshot:=store.Snapshot()
            if !tc.valid {
                if err==nil {
                    t.Fatalf("invalid sender-reported evidence was accepted: %+v",saved)
                }
                if len(snapshot.Events)!=0 {
                    t.Fatalf("rejected event mutated retained evidence: %+v",snapshot.Events)
                }
                return
            }
            if err!=nil {t.Fatalf("valid synthetic Sysmon record rejected: %v",err)}
            if len(snapshot.Events)!=1 || saved.ID=="" || saved.DeviceID!="qa-win-01" {
                t.Fatalf("accepted source not retained exactly once: %+v",snapshot)
            }
            if saved.SourceEventID!=event.SourceEventID || saved.SourceRecordID!=event.SourceRecordID ||
                saved.Type!=event.Type || !saved.Time.Equal(timestamp) ||
                saved.TimeOrigin!="sender_reported_unverified" || saved.ReceivedAt.IsZero() {
                t.Fatalf("source provenance overwritten or promoted to verified: %+v",saved)
            }
            if saved.SourceEventID==24 &&
                (saved.ProcessGUID!="" || saved.ParentProcessGUID!="" ||
                 saved.Image!="" || saved.FilePath!="" || len(saved.SourceFields)!=0) {
                t.Fatalf("clipboard metadata leaked: %+v",saved)
            }
            if saved.SourceEventID==255 &&
                len(DetectBehavioralSignals(snapshot.Events))!=0 {
                t.Fatal("Sysmon sensor-health error turned into a malware heuristic")
            }
        })
    }
}
