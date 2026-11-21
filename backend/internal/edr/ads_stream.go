package edr

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// Sysmon Event 15 FileCreateStreamHash reports an alternate stream creation.
// EID15 is NOT an execution, DLL load, or malicious-content verdict.
const adsStreamRuleID = "TURAN-WIN-ADS-STREAM-001"

// extractSuspiciousADS recognizes explicit drive-absolute alternate stream
// paths. Zone.Identifier is commonly a benign Mark-of-the-Web download marker.
// The server performs no filesystem access or verification of stream contents.
func extractSuspiciousADS(raw string) (string, bool) {
	path := windowsPath(raw)
	if len(path) < 5 || path[1] != ':' || path[2] != '\\' {
		return "", false
	}
	index := strings.Index(path[3:], ":")
	if index < 0 {
		return "", false
	}
	index += 3
	base, suffix := path[:index], path[index+1:]
	if len(suffix) == 0 || len(suffix) > 150 || !strings.Contains(base, "\\") {
		return "", false
	}
	parts := strings.Split(suffix, ":")
	if len(parts) > 2 || (len(parts) == 2 && parts[1] != "$data") {
		return "", false
	}
	name := parts[0]
	if name == "" || len(name) > 128 || strings.ContainsAny(name, "\\/< >\"|?*") ||
		strings.IndexFunc(name, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return "", false
	}
	switch name {
	case "zone.identifier", "wofcompresseddata", "summaryinformation", "documentsummaryinformation":
		return "", false
	}
	eligible := false
	for _, marker := range []string{"\\users\\", "\\appdata\\", "\\temp\\", "\\downloads\\", "\\programdata\\"} {
		if strings.Contains(base, marker) {
			eligible = true
		}
	}
	if !eligible {
		return "", false
	}
	return name, true
}

// DetectAlternateDataStreams is an alert-only lab heuristic. Missing hash,
// boot or source record provenance excludes this strict rule.
func DetectAlternateDataStreams(events []Event) []Detection {
	ordered := append([]Event(nil), events...)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].Time.Equal(ordered[j].Time) {
			return ordered[i].ID < ordered[j].ID
		}
		return ordered[i].Time.Before(ordered[j].Time)
	})

	alerts := make([]Detection, 0)
	seen := make(map[string]bool)
	for _, e := range ordered {
		if !validSysmonSignal(e, "file_create_stream_hash", 15) ||
			!validSHA256Digest(e.Hash) {
			continue
		}
		stream, ok := extractSuspiciousADS(e.FilePath)
		if !ok {
			continue
		}
		fingerprint := fmt.Sprintf("%q:%q:%q:%q:%q",
			adsStreamRuleID, e.DeviceID, e.BootID, e.SourceRecordID,
			windowsPath(e.FilePath))
		if seen[fingerprint] {
			continue
		}
		seen[fingerprint] = true
		sum := sha256.Sum256([]byte(fingerprint))
		alerts = append(alerts, Detection{
			ID: hex.EncodeToString(sum[:16]), RuleID: adsStreamRuleID,
			Category: "nondefault_alternate_data_stream_creation",
			Severity: "medium", Confidence: "low",
			DeviceID: e.DeviceID, BootID: e.BootID,
			ProcessGUID: e.ProcessGUID, ProcessImage: e.Image,
			StreamEventID: e.ID, StreamPath: e.FilePath, StreamName: stream,
			ObservedAt: e.Time,
			Explanation: "Sysmon reports creation of a nondefault NTFS alternate data stream on a potentially writable path. The hash is sender-reported; stream creation is not execution or proof of malware.",
		})
	}
	return alerts
}
