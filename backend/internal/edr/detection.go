package edr

import (
	"fmt"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
)

// Detection is an analytical signal, NOT a confirmed infection or an action.
// This laboratory prototype does not execute prevention or remediation.
type Detection struct {
	ID                string    `json:"id"`
	RuleID            string    `json:"rule_id"`
	Category          string    `json:"category"`
	Severity          string    `json:"severity"`
	Confidence        string    `json:"confidence"`
	DeviceID          string    `json:"device_id"`
	ProcessGUID       string    `json:"process_guid"`
	ProcessImage      string    `json:"process_image"`
	ModulePath        string    `json:"module_path"`
	LoadEventID       string    `json:"load_event_id"`
	// SourceRecordID is sender-reported and unauthenticated in the lab API.
	LoadSourceRecordID string    `json:"load_source_record_id,omitempty"`
	LoadTimeOrigin     string    `json:"load_time_origin"`
	LoadReceivedAt     time.Time `json:"load_received_at"`
	FileCreateEventID string    `json:"file_create_event_id,omitempty"`
	ObservedAt        time.Time `json:"observed_at"`
	Explanation       string    `json:"explanation"`
}

const dllPathRuleID = "TURAN-WIN-DLL-LOAD-001"

func windowsPath(s string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(s), "/", `\`))
}

// The initial rule deliberately limits scope to likely user-writable folders.
// These are heuristic signals only; legitimate installers may also match.
// validSHA256Digest accepts only a complete hexadecimal SHA-256 digest.
// Hashes are still sender-reported and unauthenticated in this prototype.
func validSHA256Digest(hash string) bool {
	if len(hash) != 64 {
		return false
	}
	for _, c := range hash {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func suspiciousDLLPath(path string) bool {
	p := windowsPath(path)
	if !strings.HasSuffix(p, ".dll") {
		return false
	}
	for _, marker := range []string{`\users\`, `\appdata\`, `\temp\`, `\downloads\`} {
		if strings.Contains(p, marker) {
			return true
		}
	}
	return false
}

// DetectSuspiciousDLLLoads is a pure, read-only prototype over already received
// events. File creation alone is NEVER treated as DLL execution; ImageLoad is
// mandatory. No response or irreversible action is performed.
func DetectSuspiciousDLLLoads(events []Event) []Detection {
	created := make(map[string][]Event)
	for _, event := range events {
		if event.Platform != "windows" || event.Type != "file_create" || event.DeviceID == "" || event.FilePath == "" ||
			event.ID == "" || strings.TrimSpace(event.ID) != event.ID || event.Time.IsZero() {
			continue
		}
		key := event.DeviceID + "|" + windowsPath(event.FilePath)
		created[key] = append(created[key], event)
	}
	alerts := make([]Detection, 0)
	seen := make(map[string]bool)
	for _, event := range events {
		if event.Platform != "windows" || event.Type != "module_load" ||
			event.DeviceID == "" || event.ProcessGUID == "" || event.Image == "" ||
			event.ID == "" || event.Time.IsZero() ||
			strings.TrimSpace(event.ID) != event.ID ||
			!suspiciousDLLPath(event.FilePath) {
			continue
		}
		// The real collector must expose source-event identity, provenance and
		// tamper resistant device authentication before production use.
		// Length-prefix each untrusted field so embedded delimiters cannot
		// make distinct event tuples share the same detection identity.
		fingerprint := fmt.Sprintf("%d:%s%d:%s%d:%s%d:%s%d:%s",
			len(event.DeviceID), event.DeviceID, len(event.BootID), event.BootID,
			len(event.ProcessGUID), event.ProcessGUID,
			len(windowsPath(event.FilePath)), windowsPath(event.FilePath),
			len(event.ID), event.ID)
		if seen[fingerprint] {
			continue
		}
		seen[fingerprint] = true
		sum := sha256.Sum256([]byte(dllPathRuleID + "|" + fingerprint))
		alert := Detection{
			ID: hex.EncodeToString(sum[:16]), RuleID: dllPathRuleID,
			Category: "suspicious_dll_load", Severity: "medium", Confidence: "low",
			DeviceID: event.DeviceID, ProcessGUID: event.ProcessGUID,
			ProcessImage: event.Image, ModulePath: event.FilePath,
			LoadEventID: event.ID, ObservedAt: event.Time,
			LoadSourceRecordID: event.SourceRecordID,
			LoadTimeOrigin: event.TimeOrigin, LoadReceivedAt: event.ReceivedAt,
			Explanation: "A DLL load was observed from a potentially user-writable path; verify signer, provenance and application context before responding.",
		}
		// A prior file-create observation can enrich the alert, but is not
		// required for detection, and is never confused with actual loading.
		key := event.DeviceID + "|" + windowsPath(event.FilePath)
		var nearest time.Time
		for _, prev := range created[key] {
			// Never correlate file evidence across missing or different boot scopes.
			// BootID is sender-reported in this lab and is not proof of origin.
			if event.BootID == "" || prev.BootID == "" || event.BootID != prev.BootID {
				continue
			}
			delta := event.Time.Sub(prev.Time)
			if delta < 0 || delta > 24*time.Hour || !prev.Time.After(nearest) {
				continue
			}
			// A missing hash cannot establish that a prior path occupant is
			// the module actually loaded. Keep the load alert unlinked.
			if !validSHA256Digest(event.Hash) || !validSHA256Digest(prev.Hash) || !strings.EqualFold(event.Hash, prev.Hash) {
				continue
			}
			nearest = prev.Time
			alert.FileCreateEventID = prev.ID
		}
		alerts = append(alerts, alert)
	}
	return alerts
}
