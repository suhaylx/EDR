package edr

import (
	"strings"
	"testing"
	"time"
)

func provenanceLoad() Event {
	return Event{
		ID: "sysmon-7-101", Platform: "windows", DeviceID: "win-01",
		Type: "module_load", FilePath: `C:\Users\Alice\AppData\Local\Temp\plugin.dll`,
		Image: `C:\Windows\System32\rundll32.exe`, ProcessGUID: "{one}",
		BootID: "boot-a", Hash: strings.Repeat("a", 64), Time: time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC),
	}
}

func TestDLLLoadMissingProvenanceDoesNotAlert(t *testing.T) {
	for _, tc := range []struct {
		name string
		mutate func(*Event)
	}{
		{"missing-id", func(e *Event) { e.ID = "" }},
		{"leading-space-id", func(e *Event) { e.ID = " " + e.ID }},
		{"trailing-space-id", func(e *Event) { e.ID += " " }},
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
		{"padded-id", func(e *Event) { e.ID = " " + e.ID }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			valid := Event{ID: "valid-create", Platform: "windows",
				DeviceID: load.DeviceID, Type: "file_create",
				FilePath: load.FilePath, BootID: load.BootID, Hash: load.Hash,
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
		FilePath: load.FilePath, BootID: load.BootID, Hash: load.Hash,
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
			Type: "file_create", FilePath: load.FilePath, BootID: load.BootID, Hash: "different",
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

func TestDLLCreateEvidenceRequiresSameExplicitBootScope(t *testing.T) {
	load := provenanceLoad()
	for _, tc := range []struct {
		name string
		createBoot string
		loadBoot string
		wantLink bool
	}{
		{"same-boot", "boot-a", "boot-a", true},
		{"different-boot", "boot-b", "boot-a", false},
		{"missing-create-boot", "", "boot-a", false},
		{"missing-load-boot", "boot-a", "", false},
		{"both-missing", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := load
			l.BootID = tc.loadBoot
			create := Event{ID: "create-1", Platform: "windows", DeviceID: l.DeviceID,
				Type: "file_create", FilePath: l.FilePath, Hash: l.Hash,
				BootID: tc.createBoot, Time: l.Time.Add(-time.Minute)}
			got := DetectSuspiciousDLLLoads([]Event{create, l})
			if len(got) != 1 {
				t.Fatalf("module load must still alert: %+v", got)
			}
			linked := got[0].FileCreateEventID != ""
			if linked != tc.wantLink {
				t.Fatalf("unexpected cross-boot evidence link: %+v", got[0])
			}
		})
	}
}

func TestDLLCreateEvidenceRequiresMatchingNonemptyHashes(t *testing.T) {
	load := provenanceLoad()
	for _, tc := range []struct {
		name string
		createHash string
		loadHash string
		wantLink bool
	}{
		{"matching", strings.Repeat("a", 64), strings.Repeat("a", 64), true},
		{"case-insensitive-match", strings.Repeat("A", 64), strings.Repeat("a", 64), true},
		{"different", "different", strings.Repeat("a", 64), false},
		{"invalid-short-but-equal", "abc123", "abc123", false},
		{"invalid-nonhex-but-equal", strings.Repeat("g", 64), strings.Repeat("g", 64), false},
		{"missing-create-hash", "", strings.Repeat("a", 64), false},
		{"missing-load-hash", strings.Repeat("a", 64), "", false},
		{"both-missing", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := load
			l.Hash = tc.loadHash
			create := Event{ID: "create-1", Platform: "windows", DeviceID: l.DeviceID,
				Type: "file_create", FilePath: l.FilePath, BootID: l.BootID,
				Hash: tc.createHash, Time: l.Time.Add(-time.Minute)}
			got := DetectSuspiciousDLLLoads([]Event{create, l})
			if len(got) != 1 {
				t.Fatalf("module load must still alert: %+v", got)
			}
			if linked := got[0].FileCreateEventID != ""; linked != tc.wantLink {
				t.Fatalf("unexpected hash-based evidence linkage: %+v", got[0])
			}
		})
	}
}

func TestDLLAlertFingerprintSeparatesReportedBootSessions(t *testing.T) {
	first := provenanceLoad()
	second := first
	second.BootID = "boot-b"
	alerts := DetectSuspiciousDLLLoads([]Event{first, second})
	if len(alerts) != 2 {
		t.Fatalf("same record ID in distinct boot sessions collapsed: %+v", alerts)
	}
	if alerts[0].ID == alerts[1].ID {
		t.Fatalf("distinct reported boot sessions share detection ID: %+v", alerts)
	}
	if got := DetectSuspiciousDLLLoads([]Event{first, first}); len(got) != 1 {
		t.Fatalf("duplicate record within one reported boot was not deduplicated: %+v", got)
	}
}

func TestDLLAlertFingerprintIsUnambiguousWithDelimiters(t *testing.T) {
	// Naive pipe-delimited concatenation would make these tuples identical.
	a := provenanceLoad()
	a.ProcessGUID = "proc|part"
	a.FilePath = `C:\Users\Alice\Temp\plugin.dll`
	b := a
	b.ProcessGUID = "proc"
	b.FilePath = `part|C:\Users\Alice\Temp\plugin.dll`
	// Both paths must still be suspicious and independently reported.
	if !suspiciousDLLPath(a.FilePath) || !suspiciousDLLPath(b.FilePath) {
		t.Fatal("test paths must be in heuristic scope")
	}
	got := DetectSuspiciousDLLLoads([]Event{a, b})
	if len(got) != 2 || got[0].ID == got[1].ID {
		t.Fatalf("distinct tuples collapsed into one alert: %+v", got)
	}
}
