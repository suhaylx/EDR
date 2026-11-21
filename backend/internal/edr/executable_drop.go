package edr

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

// EID29 FileExecutableDetected is not process start, ImageLoad or proof of
// malicious execution. This rule requires a separate EID11 file creation.
const executableDropRuleID = "TURAN-WIN-EXECUTABLE-DROP-001"

type fileDropScope struct {
	device, boot, process, path string
}

func fileScope(e Event) fileDropScope {
	return fileDropScope{e.DeviceID, e.BootID, e.ProcessGUID, windowsPath(e.FilePath)}
}

func writablePEPath(raw string) bool {
	path := windowsPath(raw)
	if len(path) < 5 || path[1] != ':' || path[2] != '\\' ||
		!(strings.HasSuffix(path, ".exe") || strings.HasSuffix(path, ".dll") ||
			strings.HasSuffix(path, ".sys")) {
		return false
	}
	for _, marker := range []string{"\\users\\", "\\appdata\\", "\\temp\\", "\\downloads\\", "\\programdata\\"} {
		if strings.Contains(path, marker) {
			return true
		}
	}
	return false
}

// DetectExecutableFileDrops requires independent EID11 FileCreate followed by
// EID29 FileExecutableDetected within 10 minutes, same reported device/boot,
// process, and normalized local file path. Missing hash for EID11 remains
// unknown, but an explicitly conflicting complete hash prevents correlation.
// A file detected as executable has NOT necessarily been executed.
func DetectExecutableFileDrops(events []Event) []Detection {
	created := make(map[fileDropScope][]Event)
	detected := make([]Event, 0)
	for _, e := range events {
		switch {
		case validSysmonSignal(e, "file_create", 11) && writablePEPath(e.FilePath):
			created[fileScope(e)] = append(created[fileScope(e)], e)
		case validSysmonSignal(e, "file_executable_detected", 29) &&
			writablePEPath(e.FilePath) && validSHA256Digest(e.Hash):
			detected = append(detected, e)
		}
	}
	sort.Slice(detected, func(i, j int) bool {
		if detected[i].Time.Equal(detected[j].Time) {
			return detected[i].ID < detected[j].ID
		}
		return detected[i].Time.Before(detected[j].Time)
	})

	alerts := make([]Detection, 0)
	seen := make(map[string]bool)
	for _, executable := range detected {
		var nearest *Event
		for _, fileCreate := range created[fileScope(executable)] {
			if fileCreate.SourceRecordID == executable.SourceRecordID ||
				!timeAfterWithin(fileCreate.Time, executable.Time, 10*time.Minute) {
				continue
			}
			if fileCreate.Hash != "" &&
				(!validSHA256Digest(fileCreate.Hash) ||
					!strings.EqualFold(fileCreate.Hash, executable.Hash)) {
				continue
			}
			if nearest == nil || fileCreate.Time.After(nearest.Time) ||
				(fileCreate.Time.Equal(nearest.Time) && fileCreate.ID < nearest.ID) {
				candidate := fileCreate
				nearest = &candidate
			}
		}
		if nearest == nil {
			continue
		}
		// Reported source EventRecordID is not authenticated; suppress replay
		// amplification of repeated identical sender claims in one evaluation.
		scope := fileScope(executable)
		fingerprint := fmt.Sprintf("%q:%q:%q:%q:%q:%q",
			executableDropRuleID, scope.device, scope.boot,
			scope.process, scope.path, executable.SourceRecordID)
		if seen[fingerprint] {
			continue
		}
		seen[fingerprint] = true
		sum := sha256.Sum256([]byte(fingerprint))
		alerts = append(alerts, Detection{
			ID: hex.EncodeToString(sum[:16]), RuleID: executableDropRuleID,
			Category: "executable_file_created_not_executed",
			Severity: "medium", Confidence: "low",
			DeviceID: scope.device, BootID: scope.boot,
			ProcessGUID: executable.ProcessGUID, ProcessImage: executable.Image,
			ExecutableFilePath: executable.FilePath,
			FileDropCreateEventID: nearest.ID,
			ExecutableDetectedEventID: executable.ID,
			ObservedAt: executable.Time,
			Explanation: "Sysmon reports a file create and subsequent executable-file detection for one path. This is a file artifact, not observed process execution or a malware verdict. Verify signer, hash provenance and expected software deployment.",
		})
	}
	return alerts
}
