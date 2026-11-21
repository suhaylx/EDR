package edr

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func syntheticRemoteThreadPair() []Event {
	t0 := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	common := Event{
		DeviceID: "win01", BootID: "boot-a", Platform: "windows",
		Source: "sysmon", SourceProcessGUID: "{source-1}",
		TargetProcessGUID: "{target-2}",
	}
	access := common
	access.ID = "access-1"
	access.SourceRecordID = "record-1010"
	access.SysmonEventID = 10
	access.Type = "process_access"
	access.GrantedAccess = "0x1fffff"
	access.Time = t0
	thread := common
	thread.ID = "thread-1"
	thread.SourceRecordID = "record-1008"
	thread.SysmonEventID = 8
	thread.Type = "create_remote_thread"
	thread.RemoteThreadID = 4242
	thread.Time = t0.Add(time.Minute)
	return []Event{access, thread}
}

func TestRemoteThreadNeedsTwoIndependentObservedSysmonRecords(t *testing.T) {
	pair := syntheticRemoteThreadPair()
	if got := DetectProcessAccessRemoteThread(pair[:1]); len(got) != 0 {
		t.Fatalf("EID10 alone claimed remote-thread behavior: %+v", got)
	}
	if got := DetectProcessAccessRemoteThread(pair[1:]); len(got) != 0 {
		t.Fatalf("EID8 alone claimed correlated access: %+v", got)
	}
	got := DetectProcessAccessRemoteThread(pair)
	if len(got) != 1 {
		t.Fatalf("expected one EID10+8 correlation, got %+v", got)
	}
	alert := got[0]
	if alert.RuleID != processRemoteThreadRuleID ||
		alert.Category != "process_access_remote_thread_correlation" ||
		alert.Severity != "medium" || alert.Confidence != "low" ||
		alert.ProcessAccessEventID != "access-1" ||
		alert.RemoteThreadEventID != "thread-1" ||
		alert.SourceProcessGUID != "{source-1}" ||
		alert.TargetProcessGUID != "{target-2}" ||
		alert.GrantedAccess != "0x1fffff" ||
		alert.RemoteThreadID != 4242 || alert.BootID != "boot-a" {
		t.Fatalf("detection evidence or confidence wrong: %+v", alert)
	}
}

func TestRemoteThreadRejectsIncompleteOrCrossScopeEvidence(t *testing.T) {
	cases := []struct {
		name string
		edit func([]Event)
	}{
		{"different-device", func(e []Event) { e[1].DeviceID = "win02" }},
		{"different-boot", func(e []Event) { e[1].BootID = "boot-b" }},
		{"missing-boot", func(e []Event) { e[0].BootID = "" }},
		{"different-source-process", func(e []Event) { e[1].SourceProcessGUID = "{other}" }},
		{"different-target-process", func(e []Event) { e[1].TargetProcessGUID = "{other}" }},
		{"self-target", func(e []Event) { e[0].TargetProcessGUID = e[0].SourceProcessGUID; e[1].TargetProcessGUID = e[1].SourceProcessGUID }},
		{"missing-source-guid", func(e []Event) { e[0].SourceProcessGUID = "" }},
		{"missing-target-guid", func(e []Event) { e[1].TargetProcessGUID = "" }},
		{"inconsistent-process-guid", func(e []Event) { e[0].ProcessGUID = "{not-source}" }},
		{"non-Sysmon-source", func(e []Event) { e[0].Source = "other" }},
		{"Linux-platform", func(e []Event) { e[1].Platform = "linux" }},
		{"wrong-access-event-ID", func(e []Event) { e[0].SysmonEventID = 11 }},
		{"wrong-thread-event-ID", func(e []Event) { e[1].SysmonEventID = 10 }},
		{"wrong-access-type", func(e []Event) { e[0].Type = "file_create" }},
		{"wrong-thread-type", func(e []Event) { e[1].Type = "process_access" }},
		{"missing-access-record", func(e []Event) { e[0].SourceRecordID = "" }},
		{"missing-thread-record", func(e []Event) { e[1].SourceRecordID = "" }},
		{"same-source-record", func(e []Event) { e[1].SourceRecordID = e[0].SourceRecordID }},
		{"missing-event-receipt", func(e []Event) { e[1].ID = "" }},
		{"zero-new-thread", func(e []Event) { e[1].RemoteThreadID = 0 }},
		{"read-only-access", func(e []Event) { e[0].GrantedAccess = "0x10" }},
		{"query-only-access", func(e []Event) { e[0].GrantedAccess = "0x1000" }},
		{"thread-right-only", func(e []Event) { e[0].GrantedAccess = "0x2" }},
		{"missing-write-right", func(e []Event) { e[0].GrantedAccess = "0xa" }},
		{"missing-operation-right", func(e []Event) { e[0].GrantedAccess = "0x22" }},
		{"no-access-mask", func(e []Event) { e[0].GrantedAccess = "" }},
		{"reverse-order", func(e []Event) { e[0].Time = e[1].Time.Add(time.Second) }},
		{"window-exceeded", func(e []Event) { e[1].Time = e[0].Time.Add(2*time.Minute + time.Second) }},
		{"missing-time", func(e []Event) { e[1].Time = time.Time{} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pair := syntheticRemoteThreadPair()
			tc.edit(pair)
			if got := DetectProcessAccessRemoteThread(pair); len(got) != 0 {
				t.Fatalf("invalid evidence linked into remote-thread alert: %+v", got)
			}
		})
	}
}

func TestRemoteThreadCorrelationDedupIsDeterministic(t *testing.T) {
	pair := syntheticRemoteThreadPair()
	expected := DetectProcessAccessRemoteThread(pair)
	shuffled := []Event{pair[1], pair[0], pair[1], pair[0]}
	got := DetectProcessAccessRemoteThread(shuffled)
	if len(expected) != 1 || len(got) != 1 ||
		expected[0].ID != got[0].ID || got[0].ProcessAccessEventID != "access-1" {
		t.Fatalf("duplicate/shuffled evidence changed detection: initial=%+v shuffled=%+v", expected, got)
	}
	other := syntheticRemoteThreadPair()
	for i := range other {
		other[i].BootID = "boot-b"
	}
	two := DetectProcessAccessRemoteThread(append(shuffled, other...))
	if len(two) != 2 || two[0].ID == two[1].ID {
		t.Fatalf("separate boot events collapsed: %+v", two)
	}
}

func TestRemoteThreadChoosesNearestPriorQualifiedHandle(t *testing.T) {
	pair := syntheticRemoteThreadPair()
	older := pair[0]
	older.ID = "access-old"
	older.SourceRecordID = "100"
	older.Time = pair[0].Time.Add(-30*time.Second)
	nearer := pair[0]
	nearer.ID = "access-near"
	nearer.SourceRecordID = "101"
	nearer.Time = pair[0].Time.Add(30*time.Second)
	unqualified := pair[0]
	unqualified.ID = "access-irrelevant"
	unqualified.GrantedAccess = "0x10"
	unqualified.Time = pair[0].Time.Add(50*time.Second)
	got := DetectProcessAccessRemoteThread([]Event{
		unqualified, pair[1], older, pair[0], nearer,
	})
	if len(got) != 1 || got[0].ProcessAccessEventID != "access-near" {
		t.Fatalf("did not choose nearest qualified handle: %+v", got)
	}
}

func TestAccessMaskValidationAndIngestRejection(t *testing.T) {
	for _, mask := range []string{"0x2a", "0X2A", "0x1fffff", "0xffffffff"} {
		if _, ok := parseProcessAccessMask(mask); !ok {
			t.Errorf("valid hexadecimal access mask refused: %q", mask)
		}
	}
	for _, mask := range []string{
		"0x", "0x0", "0x100000000", "0x+2", "0x-2", "42", "0b1010",
		" 0x2a", "0x2a ", "0xgh", "0x2a\n",
	} {
		if _, ok := parseProcessAccessMask(mask); ok {
			t.Errorf("invalid access mask accepted: %q", mask)
		}
	}
	cases := []struct {
		name string
		edit func(*Event)
	}{
		{"invalid-mask", func(e *Event) { e.GrantedAccess = "0xGG" }},
		{"oversized-mask", func(e *Event) { e.GrantedAccess = "0x1ffffffff" }},
		{"source-guid-too-long", func(e *Event) { e.SourceProcessGUID = strings.Repeat("X", 129) }},
		{"target-guid-too-long", func(e *Event) { e.TargetProcessGUID = strings.Repeat("X", 129) }},
		{"control-character", func(e *Event) { e.SourceProcessGUID = "source\nforged" }},
		{"trailing-space-guid", func(e *Event) { e.TargetProcessGUID = "target " }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := NewStore()
			if _, err := store.CheckIn(Agent{ID: "win01", Platform: "windows"}); err != nil {
				t.Fatal(err)
			}
			access := syntheticRemoteThreadPair()[0]
			tc.edit(&access)
			if _, err := store.Ingest(access); err == nil {
				t.Fatalf("malformed Sysmon evidence accepted: %+v", access)
			}
			if len(store.Snapshot().Events) != 0 {
				t.Fatal("rejected record must not enter evidence store")
			}
		})
	}
}

func TestRemoteThreadRuleVisibleFromAuthenticatedLabAPI(t *testing.T) {
	store := NewStore()
	if _, err := store.CheckIn(Agent{ID: "win01", Platform: "windows"}); err != nil {
		t.Fatal(err)
	}
	for _, event := range syntheticRemoteThreadPair() {
		if _, err := store.Ingest(event); err != nil {
			t.Fatalf("typed Sysmon ingest rejected: %v", err)
		}
	}
	handler := (&Server{Store: store, Token: "lab-development-token-123", WebDir: t.TempDir()}).Handler()
	req := httptest.NewRequest(http.MethodGet, "/api/detections", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated lab API unexpectedly exposed detections: %d", rec.Code)
	}
	req = httptest.NewRequest(http.MethodGet, "/api/detections", nil)
	req.Header.Set("Authorization", "Bearer lab-development-token-123")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	var results []Detection
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &results) != nil ||
		len(results) != 1 || results[0].RuleID != processRemoteThreadRuleID ||
		results[0].RemoteThreadEventID == "" || results[0].ProcessAccessEventID == "" {
		t.Fatalf("lab API omitted EID8+10 evidence: status=%d response=%s", rec.Code, rec.Body.String())
	}
}
