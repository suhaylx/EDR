package edr

import (
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "strings"
    "testing"
    "time"
)

func behaviorEvidence(id, device, typ string, sourceID uint32, at time.Time) Event {
    return Event{
        ID:id, DeviceID:device, Platform:"windows", Source:"sysmon",
        SourceEventID:sourceID, SourceRecordID:id, Type:typ,
        Time:at, ProcessGUID:"{P}", Image:"C:\\Windows\\System32\\notepad.exe",
    }
}

func TestAgentOneBehaviorRulesRequireRealSourceIDsAndBoundedEvidence(t *testing.T) {
    now:=time.Now().UTC().Add(-time.Minute)
    created:=behaviorEvidence("create","win-1","process_create",1,now)
    created.Image="C:\\Users\\lab\\Downloads\\agent.exe"
    net:=behaviorEvidence("net","win-1","network_connect",3,now.Add(time.Second))
    net.SourceFields=map[string]string{"destination_ip":"10.20.30.40"}
    thread:=behaviorEvidence("thread","win-1","create_remote_thread",8,now)
    thread.SourceFields=map[string]string{"source_image":"C:\\Windows\\explorer.exe","target_image":"C:\\Windows\\notepad.exe"}
    lsass:=behaviorEvidence("lsass","win-1","process_access",10,now)
    lsass.SourceFields=map[string]string{"source_image":"C:\\Windows\\explorer.exe","target_image":"C:\\Windows\\System32\\lsass.exe"}
    autorun:=behaviorEvidence("autorun","win-1","registry_value_set",13,now)
    autorun.SourceFields=map[string]string{"target_object":"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Example"}
    wmi:=behaviorEvidence("wmi","win-1","wmi_binding",21,now)
    tamper:=behaviorEvidence("tamper","win-1","process_tampering",25,now)
    inputs:=[]Event{created,net,thread,lsass,autorun,wmi,tamper,net}
    got:=DetectBehavioralSignals(inputs)
    if len(got)!=6 {t.Fatalf("expected six unique heuristic leads, got %d: %+v",len(got),got)}
    rules:=map[string]bool{}
    for _,det:=range got {
        if det.Confidence!="low" || det.LoadEventID!="" ||
           det.EvidenceEventID=="" || det.EvidenceSourceEventID==0 ||
           det.ID=="" || strings.Contains(strings.ToLower(det.Explanation),"confirmed malicious") {
            t.Fatalf("misleading Agent 1 evidence: %+v",det)
        }
        rules[det.RuleID]=true
    }
    for _,rule:=range []string{
        "TURAN-WIN-PROC-NET-001","TURAN-WIN-REMOTE-THREAD-001",
        "TURAN-WIN-LSASS-ACCESS-001","TURAN-WIN-AUTORUN-001",
        "TURAN-WIN-WMI-BIND-001","TURAN-WIN-PROC-TAMPER-001",
    } {if !rules[rule] {t.Fatalf("rule %s missing",rule)}}
    for _,mutate:=range []func(*Event){
        func(e *Event){e.SourceRecordID=""},
        func(e *Event){e.SourceEventID=0},
        func(e *Event){e.Source="procfs"},
        func(e *Event){e.Type="file_create"},
        func(e *Event){e.Platform="linux"},
    } {
        altered:=lsass;mutate(&altered)
        if got:=DetectBehavioralSignals([]Event{altered});len(got)!=0 {
            t.Fatalf("inconsistent source unexpectedly produced signal: %+v",got)
        }
    }
}

func TestAgentOneNoCrossDeviceOrBootOrUnverifiedNetworkCorrelation(t *testing.T) {
    now:=time.Now().UTC().Add(-5*time.Minute)
    created:=behaviorEvidence("create","win-a","process_create",1,now)
    created.Image="C:\\Users\\lab\\Temp\\launch.exe"
    created.BootID="boot-A"
    net:=behaviorEvidence("net","win-b","network_connect",3,now.Add(time.Second))
    net.SourceFields=map[string]string{"destination_ip":"10.0.0.2"}
    if got:=DetectBehavioralSignals([]Event{created,net});len(got)!=0 {
        t.Fatalf("cross-device match: %+v",got)
    }
    net.DeviceID="win-a";net.BootID="boot-B"
    if got:=DetectBehavioralSignals([]Event{created,net});len(got)!=0 {
        t.Fatalf("cross-boot match: %+v",got)
    }
    net.BootID="boot-A";net.ProcessGUID="{OTHER}"
    if got:=DetectBehavioralSignals([]Event{created,net});len(got)!=0 {
        t.Fatalf("unrelated process match: %+v",got)
    }
    net.ProcessGUID=created.ProcessGUID;net.Time=created.Time.Add(11*time.Minute)
    if got:=DetectBehavioralSignals([]Event{created,net});len(got)!=0 {
        t.Fatalf("outside ten-minute window: %+v",got)
    }
    net.Time=created.Time.Add(-time.Second)
    if got:=DetectBehavioralSignals([]Event{created,net});len(got)!=0 {
        t.Fatalf("network occurred before source create: %+v",got)
    }
    net.Time=created.Time.Add(time.Second)
    created.Image="C:\\Windows\\System32\\svchost.exe"
    if got:=DetectBehavioralSignals([]Event{created,net});len(got)!=0 {
        t.Fatalf("system executable should not be flagged by user-path rule: %+v",got)
    }
}

func TestAgentOneAPIAndOverviewShareSameEvidenceCounts(t *testing.T) {
    now:=time.Now().UTC().Add(-time.Minute)
    s:=NewStore()
    if _,err:=s.CheckIn(Agent{ID:"win-lab-01",Platform:"windows"});err!=nil{t.Fatal(err)}
    evidence:=behaviorEvidence("reported","win-lab-01","process_access",10,now)
    evidence.SourceFields=map[string]string{"source_image":"C:\\Windows\\explorer.exe","target_image":"C:\\Windows\\System32\\lsass.exe"}
    if _,err:=s.Ingest(evidence);err!=nil{t.Fatal(err)}
    snapshot:=s.Snapshot()
    expected:=allAgentOneDetections(snapshot.Events)
    if len(expected)!=1 || expected[0].RuleID!="TURAN-WIN-LSASS-ACCESS-001" {
        t.Fatalf("expected low-confidence LSASS access rule: %+v",expected)
    }
    overview:=BuildSOCOverview(snapshot,nil,time.Now().UTC(),7)
    if overview.Alerts!=1 || overview.HighRiskAlerts!=0 {
        t.Fatalf("overview missed behavioral evidence: %+v",overview)
    }
    server:=(&Server{Store:s,Token:"0123456789abcdef",WebDir:t.TempDir()}).Handler()
    req:=httptest.NewRequest(http.MethodGet,"/api/detections",nil)
    req.Header.Set("Authorization","Bearer 0123456789abcdef")
    recorder:=httptest.NewRecorder();server.ServeHTTP(recorder,req)
    if recorder.Code!=http.StatusOK {t.Fatalf("detection HTTP %d",recorder.Code)}
    var actual []Detection
    if err:=json.Unmarshal(recorder.Body.Bytes(),&actual);err!=nil{t.Fatal(err)}
    if len(actual)!=1 || actual[0].EvidenceEventID=="" || actual[0].LoadEventID!="" {
        t.Fatalf("API did not preserve actual non-DLL source evidence: %+v",actual)
    }
}
