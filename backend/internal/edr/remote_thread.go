package edr

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// This is a read-only lab heuristic, not proof of injection or malicious code.
// Sysmon EID10 is process handle access, NOT a created remote thread (EID8).
const processRemoteThreadRuleID = "TURAN-WIN-PROC-REMOTE-THREAD-001"

const (
	processCreateThread = uint32(0x0002)
	processVMOperation  = uint32(0x0008)
	processVMWrite      = uint32(0x0020)
)

// Only allow canonical 0x-prefixed hexadecimal DWORD values. Never accept
// signed, octal, whitespace or unbounded client-supplied GrantedAccess strings.
func parseProcessAccessMask(value string) (uint32, bool) {
	if len(value) < 3 || len(value) > 10 ||
		!(strings.HasPrefix(value, "0x") || strings.HasPrefix(value, "0X")) {
		return 0, false
	}
	for _, ch := range value[2:] {
		if !((ch >= '0' && ch <= '9') ||
			(ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')) {
			return 0, false
		}
	}
	parsed, err := strconv.ParseUint(value[2:], 16, 32)
	return uint32(parsed), err == nil && parsed != 0
}

func hasRemoteThreadAccess(mask uint32) bool {
	// Conservative triage gate: a handle with only query/read rights must not
	// be treated as a preparatory injection signal.
	required := processCreateThread | processVMOperation | processVMWrite
	return mask&required == required
}

type crossProcessKey struct {
	device, boot, source, target string
}

func crossProcessScope(e Event) crossProcessKey {
	return crossProcessKey{
		device: e.DeviceID, boot: e.BootID,
		source: strings.ToLower(e.SourceProcessGUID),
		target: strings.ToLower(e.TargetProcessGUID),
	}
}

func validCrossProcessSysmon(e Event, kind string, eventID int) bool {
	if e.Platform != "windows" || e.Source != "sysmon" ||
		e.Type != kind || e.SysmonEventID != eventID ||
		e.DeviceID == "" || e.BootID == "" ||
		e.SourceProcessGUID == "" || e.TargetProcessGUID == "" ||
		!validID(e.DeviceID) || e.ID == "" ||
		e.SourceRecordID == "" || e.Time.IsZero() {
		return false
	}
	for _, field := range []string{
		e.ID, e.SourceRecordID, e.BootID, e.SourceProcessGUID, e.TargetProcessGUID,
	} {
		if strings.TrimSpace(field) != field {
			return false
		}
	}
	if strings.EqualFold(e.SourceProcessGUID, e.TargetProcessGUID) {
		return false // self-target access is not remote-thread activity
	}
	// If the collector also sets the generic ProcessGUID, it must describe
	// the same source process. An inconsistent sender claim is discarded.
	return e.ProcessGUID == "" || strings.EqualFold(e.ProcessGUID, e.SourceProcessGUID)
}

// DetectProcessAccessRemoteThread requires independently observed EID10
// ProcessAccess and EID8 CreateRemoteThread on the same reported
// device/boot/source/target process pair. EID10 must precede EID8 by at most
// two minutes and grant CREATE_THREAD, VM_OPERATION and VM_WRITE rights.
// Neither event proves memory modification, malicious intent or execution of
// injected code. This detector MUST NOT perform automatic remediation.
func DetectProcessAccessRemoteThread(events []Event) []Detection {
	accessByPair := make(map[crossProcessKey][]Event)
	threads := make([]Event, 0)

	for _, event := range events {
		switch {
		case validCrossProcessSysmon(event, "process_access", 10):
			mask, ok := parseProcessAccessMask(event.GrantedAccess)
			if ok && hasRemoteThreadAccess(mask) {
				key := crossProcessScope(event)
				accessByPair[key] = append(accessByPair[key], event)
			}
		case validCrossProcessSysmon(event, "create_remote_thread", 8):
			if event.RemoteThreadID != 0 {
				threads = append(threads, event)
			}
		}
	}

	sort.Slice(threads, func(i, j int) bool {
		if threads[i].Time.Equal(threads[j].Time) {
			return threads[i].ID < threads[j].ID
		}
		return threads[i].Time.Before(threads[j].Time)
	})

	alerts := make([]Detection, 0)
	seen := make(map[crossProcessKey]bool)
	for _, thread := range threads {
		key := crossProcessScope(thread)
		if seen[key] {
			continue
		}

		// Choose nearest preceding access deterministically, regardless of
		// whether received events arrived in chronological order.
		var nearest *Event
		for _, access := range accessByPair[key] {
			if access.SourceRecordID == thread.SourceRecordID ||
				!timeAfterWithin(access.Time, thread.Time, 2*time.Minute) {
				continue
			}
			if nearest == nil || access.Time.After(nearest.Time) ||
				(access.Time.Equal(nearest.Time) && access.ID < nearest.ID) {
				candidate := access
				nearest = &candidate
			}
		}
		if nearest == nil {
			continue
		}
		seen[key] = true
		fingerprint := fmt.Sprintf("%s|%d:%s%d:%s%d:%s%d:%s%d:%s",
			processRemoteThreadRuleID,
			len(key.device), key.device, len(key.boot), key.boot,
			len(key.source), key.source, len(key.target), key.target,
			len(thread.ID), thread.ID)
		digest := sha256.Sum256([]byte(fingerprint))
		alerts = append(alerts, Detection{
			ID: hex.EncodeToString(digest[:16]),
			RuleID: processRemoteThreadRuleID,
			Category: "process_access_remote_thread_correlation",
			Severity: "medium", Confidence: "low",
			DeviceID: key.device, BootID: key.boot,
			ProcessGUID: thread.SourceProcessGUID,
			SourceProcessGUID: thread.SourceProcessGUID,
			TargetProcessGUID: thread.TargetProcessGUID,
			ProcessAccessEventID: nearest.ID,
			RemoteThreadEventID: thread.ID,
			GrantedAccess: nearest.GrantedAccess,
			RemoteThreadID: thread.RemoteThreadID,
			ObservedAt: thread.Time,
			Explanation: "A reported process handle access with thread and memory rights preceded a reported remote-thread creation in the same target process. Both are unverified lab telemetry; investigate context and authorized tooling before inferring code injection.",
		})
	}
	return alerts
}
