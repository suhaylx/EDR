package edr

import (
	"testing"
	"time"
)

func provenanceLoad() Event {
	return Event{
		ID: "sysmon-7-101", Platform: "windows", DeviceID: "win-01",
		Type: "module_load", FilePath: `C:\Users\Alice\AppData\Local\Temp\plugin.dll`,
		Image: `C:\Windows\System32\rundll32.exe`, ProcessGUID: "{one}",
		Hash: "abc123", Time: time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC),
	}
}

func TestDLLLoadMissingProvenanceDoesNotAlert(t *testing.T) {
	for _, tc := range []struct {
		name string
		mutate func(*Event)
	}{
		{"missing-id", func(e *Event) { e.ID = "" }},
		{"missing-timestamp", func(e *Event) { e.Time = time.Time{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			load := provenanceLoad()
			tc.mutate(&load)
			if got := DetectSuspiciousDLLLoads([]Event{load}); len(got) != 0 {
				t.Fatalf("invalid DLL-load provenance produced %d detections: %+v", len(got), got)
			}
		})
	}
}

func TestDLLCreateEnrichmentIgnoresIncompleteProvenance(t *testing.T) {
	load := provenanceLoad()
	for _, tc := range []struct {
		name string
		mutate func(*Event)
	}{
		{"missing-id", func(e *Event) { e.ID = "" }},
		{"missing-timestamp", func(e *Event) { e.Time = time.Time{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			valid := Event{ID: "valid-create", Platform: "windows",
				DeviceID: load.DeviceID, Type: "file_create",
				FilePath: load.FilePath, Hash: load.Hash,
				Time: load.Time.Add(-2 * time.Minute),
			}
			malformed := valid
			malformed.ID = "malformed-create"
			malformed.Time = load.Time.Add(-time.Minute)
			tc.mutate(&malformed)
			got := DetectSuspiciousDLLLoads([]Event{valid, malformed, load})
			if len(got) != 1 || got[0].LoadEventID != load.ID ||
				got[0].FileCreateEventID != valid.ID {
				t.Fatalf("incomplete create evidence shadowed valid create: %+v", got)
			}
		})
	}
}

func TestDLLCorrelationRejectsOutOfScopeCreatesAndDeduplicates(t *testing.T) {
	load := provenanceLoad()
	valid := Event{ID: "valid-create", Platform: "windows",
		DeviceID: load.DeviceID, Type: "file_create",
		FilePath: load.FilePath, Hash: load.Hash,
		Time: load.Time.Add(-time.Minute),
	}
	created := []Event{
		valid,
		{ID: "other-device", Platform: "windows", DeviceID: "win-02",
			Type: "file_create", FilePath: load.FilePath, Time: load.Time.Add(-time.Second)},
		{ID: "future-create", Platform: "windows", DeviceID: load.DeviceID,
			Type: "file_create", FilePath: load.FilePath, Time: load.Time.Add(time.Second)},
		{ID: "old-create", Platform: "windows", DeviceID: load.DeviceID,
			Type: "file_create", FilePath: load.FilePath, Time: load.Time.Add(-25 * time.Hour)},
		{ID: "wrong-hash", Platform: "windows", DeviceID: load.DeviceID,
			Type: "file_create", FilePath: load.FilePath, Hash: "different",
			Time: load.Time.Add(-time.Second)},
	}
	if got := DetectSuspiciousDLLLoads(created); len(got) != 0 {
		t.Fatalf("file creates without module load triggered: %+v", got)
	}
	events := append(created, load, load)
	got := DetectSuspiciousDLLLoads(events)
	if len(got) != 1 || got[0].LoadEventID != load.ID ||
		got[0].FileCreateEventID != valid.ID {
		t.Fatalf("expected a single correctly linked DLL load: %+v", got)
	}
	if got[0].Severity != "medium" || got[0].Confidence != "low" {
		t.Fatalf("overstated alert severity/confidence: %+v", got[0])
	}
}

func TestDLLAlertExposesUnverifiedSourceRecordAndReceipt(t *testing.T) {
	load := provenanceLoad()
	load.SourceRecordID = "EventRecordID:1007"
	load.TimeOrigin = "sender_reported_unverified"
	load.ReceivedAt = load.Time.Add(3 * time.Second)
	got := DetectSuspiciousDLLLoads([]Event{load})
	if len(got) != 1 {
		t.Fatalf("expected one provisional DLL alert, got %+v", got)
	}
	alert := got[0]
	if alert.LoadEventID != load.ID ||
		alert.LoadSourceRecordID != load.SourceRecordID ||
		alert.LoadTimeOrigin != load.TimeOrigin ||
		!alert.LoadReceivedAt.Equal(load.ReceivedAt) ||
		!alert.ObservedAt.Equal(load.Time) {
		t.Fatalf("source and receipt provenance not preserved: %+v", alert)
	}
	if alert.Confidence != "low" {
		t.Fatalf("unauthenticated source must not increase confidence: %+v", alert)
	}
}
