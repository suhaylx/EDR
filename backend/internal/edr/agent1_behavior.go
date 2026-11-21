package edr

import (
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "strings"
    "time"
)

// Agent 1 rules are explicitly low-confidence analyst leads. They do not
// assert malware, exploit execution, attacker intent, or justify response.
// Every match requires a retained sender-reported Sysmon ID and RecordID.
func sysmonObservation(e Event, id uint32, typ string) bool {
    return e.Platform == "windows" && e.Source == "sysmon" &&
        e.SourceEventID == id && e.Type == typ &&
        e.ID != "" && e.DeviceID != "" && e.SourceRecordID != "" &&
        !e.Time.IsZero()
}

func userWritableExecutable(s string) bool {
    p := windowsPath(s)
    if p == "" || (!strings.HasSuffix(p, ".exe") && !strings.HasSuffix(p, ".com")) {
        return false
    }
    return strings.Contains(p, "\\users\\") || strings.Contains(p, "\\appdata\\") ||
        strings.Contains(p, "\\downloads\\") || strings.Contains(p, "\\temp\\")
}

func runKey(s string) bool {
    p := windowsPath(s)
    if !strings.Contains(p, "\\software\\microsoft\\windows\\currentversion\\") {
        return false
    }
    return strings.Contains(p, "\\run\\") || strings.HasSuffix(p, "\\run") ||
        strings.Contains(p, "\\runonce\\") || strings.HasSuffix(p, "\\runonce")
}

// All Agent 1 signals share the same API and overview counting rules.
func allAgentOneDetections(events []Event) []Detection {
    result := append([]Detection{}, DetectSuspiciousDLLLoads(events)...)
    return append(result, DetectBehavioralSignals(events)...)
}

// DetectBehavioralSignals reads retained evidence without endpoint actions.
// A matched process GUID is a sender-reported, unauthenticated lab assertion.
func DetectBehavioralSignals(events []Event) []Detection {
    processes := make(map[string][]Event)
    for _, e := range events {
        if sysmonObservation(e, 1, "process_create") &&
            e.ProcessGUID != "" && e.Image != "" {
            processes[e.DeviceID+"\x00"+e.ProcessGUID] =
                append(processes[e.DeviceID+"\x00"+e.ProcessGUID], e)
        }
    }
    out := make([]Detection, 0)
    seen := make(map[string]bool)
    emit := func(e Event, rule, category, severity, explanation, target, contextID string) {
        fingerprint := fmt.Sprintf("%d:%s%d:%s%d:%s%d:%s",
            len(rule), rule, len(e.DeviceID), e.DeviceID,
            len(e.ID), e.ID, len(contextID), contextID)
        digest := sha256.Sum256([]byte(fingerprint))
        key := hex.EncodeToString(digest[:16])
        if seen[key] { return }
        seen[key] = true
        out = append(out, Detection{
            ID: key, RuleID: rule, Category: category, Severity: severity,
            Confidence: "low", DeviceID: e.DeviceID,
            ProcessGUID: e.ProcessGUID, ProcessImage: e.Image,
            EvidenceEventID: e.ID, EvidenceSourceEventID: e.SourceEventID,
            TargetObject: target, ObservedAt: e.Time,
            Explanation: explanation,
        })
    }
    for _, e := range events {
        switch {
        case sysmonObservation(e, 3, "network_connect"):
            if e.ProcessGUID == "" || e.SourceFields["destination_ip"] == "" { continue }
            for _, p := range processes[e.DeviceID+"\x00"+e.ProcessGUID] {
                if !userWritableExecutable(p.Image) { continue }
                delta := e.Time.Sub(p.Time)
                if delta < 0 || delta > 10*time.Minute { continue }
                // Missing boot identity leaves a lab provenance gap.
                if e.BootID != "" && p.BootID != "" && e.BootID != p.BootID { continue }
                emit(e, "TURAN-WIN-PROC-NET-001", "user_path_process_network", "low",
                    "Same-device Sysmon records report a user-path executable and a network connection under the same process GUID within ten minutes. Neither relation nor endpoint identity is independently authenticated.",
                    e.SourceFields["destination_ip"], p.ID)
                break
            }
        case sysmonObservation(e, 8, "create_remote_thread"):
            if e.SourceFields["source_image"] == "" || e.SourceFields["target_image"] == "" { continue }
            emit(e, "TURAN-WIN-REMOTE-THREAD-001", "remote_thread_observed", "low",
                "Sysmon reported remote thread creation; debugging and security tools may cause legitimate events, and no injection is independently verified.",
                e.SourceFields["target_image"], "")
        case sysmonObservation(e, 10, "process_access"):
            target := windowsPath(e.SourceFields["target_image"])
            if !strings.HasSuffix(target, "\\lsass.exe") || e.SourceFields["source_image"] == "" { continue }
            emit(e, "TURAN-WIN-LSASS-ACCESS-001", "sensitive_process_access", "medium",
                "Sysmon reported process access to LSASS. Legitimate security software can cause this; inspect surrounding evidence and granted access before responding.",
                e.SourceFields["target_image"], "")
        case sysmonObservation(e, 13, "registry_value_set"):
            target := e.SourceFields["target_object"]
            if !runKey(target) { continue }
            emit(e, "TURAN-WIN-AUTORUN-001", "autorun_registry_change", "low",
                "Sysmon reported a value set at a Windows Run or RunOnce location. Legitimate installers also modify these keys; no registry value data was collected.",
                target, "")
        case sysmonObservation(e, 21, "wmi_binding"):
            emit(e, "TURAN-WIN-WMI-BIND-001", "wmi_binding_observed", "low",
                "Sysmon reported a WMI consumer/filter binding, which can support persistence but is also legitimate. Binding identity is not independently verified.",
                "", "")
        case sysmonObservation(e, 25, "process_tampering"):
            if e.ProcessGUID == "" && e.SourceFields["source_process_guid"] == "" { continue }
            emit(e, "TURAN-WIN-PROC-TAMPER-001", "process_tampering_observed", "medium",
                "Sysmon reported process tampering. This is a source-reported signal, not confirmed infection or permission to terminate any process.",
                e.Image, "")
        }
    }
    return out
}
