package edr

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"time"
)

// Original TuranSec lab rule: EID25 "ProcessTampering" may report an image
// replacement, but it does not establish intent, memory injection or malware.
// Require independent EID1 process creation to reduce unsupported causality.
const processTamperRuleID = "TURAN-WIN-PROCESS-TAMPER-001"

type tamperProcessKey struct {
	device, boot, process string
}

func tamperKey(e Event) tamperProcessKey {
	return tamperProcessKey{device: e.DeviceID, boot: e.BootID, process: e.ProcessGUID}
}

// DetectProcessTampering is intentionally strict: only normalized
// image_replaced EID25 + matching EID1 with identical reported image and
// nonempty source records, in the same reported device/boot/process.
// The EID25 must occur 0..24h after EID1; EID25 alone is not promoted into
// a confirmed infection. A caller must not auto-remediate on this signal.
func DetectProcessTampering(events []Event) []Detection {
	processes := make(map[tamperProcessKey][]Event)
	tamperEvents := make([]Event, 0)
	for _, e := range events {
		switch {
		case validSysmonSignal(e, "process_create", 1) && e.Image != "":
			processes[tamperKey(e)] = append(processes[tamperKey(e)], e)
		case validSysmonSignal(e, "process_tampering", 25) &&
			e.TamperType == "image_replaced" && e.Image != "":
			tamperEvents = append(tamperEvents, e)
		}
	}
	sort.Slice(tamperEvents, func(i, j int) bool {
		if tamperEvents[i].Time.Equal(tamperEvents[j].Time) {
			return tamperEvents[i].ID < tamperEvents[j].ID
		}
		return tamperEvents[i].Time.Before(tamperEvents[j].Time)
	})

	alerts := make([]Detection, 0)
	seen := make(map[string]bool)
	for _, observed := range tamperEvents {
		key := tamperKey(observed)
		var preceding *Event
		for _, process := range processes[key] {
			if process.SourceRecordID == observed.SourceRecordID ||
				windowsPath(process.Image) != windowsPath(observed.Image) ||
				!timeAfterWithin(process.Time, observed.Time, 24*time.Hour) {
				continue
			}
			if preceding == nil || process.Time.After(preceding.Time) ||
				(process.Time.Equal(preceding.Time) && process.ID < preceding.ID) {
				candidate := process
				preceding = &candidate
			}
		}
		if preceding == nil {
			continue
		}
		// Source records are untrusted: repeat ingestion of the same sender
		// event in the lab must not inflate alert counts.
		fingerprint := fmt.Sprintf("%q:%q:%q:%q:%q",
			processTamperRuleID, key.device, key.boot, key.process,
			observed.SourceRecordID)
		if seen[fingerprint] {
			continue
		}
		seen[fingerprint] = true
		sum := sha256.Sum256([]byte(fingerprint))
		alerts = append(alerts, Detection{
			ID: hex.EncodeToString(sum[:16]),
			RuleID: processTamperRuleID,
			Category: "reported_process_image_replacement",
			Severity: "high", Confidence: "low",
			DeviceID: key.device, BootID: key.boot,
			ProcessGUID: key.process, ProcessImage: observed.Image,
			ProcessCreateEventID: preceding.ID, TamperEventID: observed.ID,
			TamperType: observed.TamperType, ObservedAt: observed.Time,
			Explanation: "Sysmon reports image replacement for a process whose start was also reported in this boot. Investigate legitimate instrumentation and verify raw source evidence; this is not proof of malicious injection.",
		})
	}
	return alerts
}
