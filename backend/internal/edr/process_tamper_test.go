package edr

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func syntheticTamperEvents() []Event {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	process := Event{
		ID: "start-1", SourceRecordID: "sysmon-1", DeviceID: "win-tamper",
		BootID: "boot-a", Platform: "windows", Source: "sysmon",
		SysmonEventID: 1, Type: "process_create",
		ProcessGUID: "{process-01}", Image: `C:\Users\Alice\Temp\app.exe`,
		Time: now,
	}
	tamper := process
	tamper.ID, tamper.SourceRecordID = "tamper-25", "sysmon-25"
	tamper.Type, tamper.SysmonEventID = "process_tampering", 25
	tamper.TamperType = "image_replaced"
	tamper.Time = now.Add(time.Minute)
	return []Event{process, tamper}
}

func TestImageReplacementRequiresEID1AndEID25(t *testing.T) {
	e := syntheticTamperEvents()
	if got := DetectProcessTampering(e[:1]); len(got) != 0 {
		t.Fatalf("process creation only produced tamper alert: %+v", got)
	}
	if got := DetectProcessTampering(e[1:]); len(got) != 0 {
		t.Fatalf("EID25 without source process was escalated: %+v", got)
	}
	got := DetectProcessTampering(e)
	if len(got) != 1 || got[0].RuleID != processTamperRuleID ||
		got[0].Severity != "high" || got[0].Confidence != "low" ||
		got[0].TamperType != "image_replaced" ||
		got[0].ProcessCreateEventID != "start-1" ||
		got[0].TamperEventID != "tamper-25" {
		t.Fatalf("process tamper evidence lost: %+v", got)
	}
}

func TestTamperRejectsFalseCorrelations(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func([]Event)
	}{
		{"cross-device", func(e []Event) { e[0].DeviceID = "other" }},
		{"cross-boot", func(e []Event) { e[1].BootID = "other" }},
		{"missing-boot", func(e []Event) { e[0].BootID = "" }},
		{"wrong-process", func(e []Event) { e[1].ProcessGUID = "{other}" }},
		{"different-image", func(e []Event) { e[1].Image = `C:\Windows\System32\svchost.exe` }},
		{"missing-image", func(e []Event) { e[0].Image = "" }},
		{"wrong-EID25", func(e []Event) { e[1].SysmonEventID = 10 }},
		{"wrong-EID1", func(e []Event) { e[0].SysmonEventID = 11 }},
		{"wrong-type", func(e []Event) { e[1].Type = "process_access" }},
		{"other-tamper-type", func(e []Event) { e[1].TamperType = "image_locked" }},
		{"missing-tamper-type", func(e []Event) { e[1].TamperType = "" }},
		{"missing-source-record", func(e []Event) { e[1].SourceRecordID = "" }},
		{"same-source-record", func(e []Event) { e[1].SourceRecordID = e[0].SourceRecordID }},
		{"no-collector", func(e []Event) { e[1].Source = "other" }},
		{"linux-event", func(e []Event) { e[0].Platform = "linux" }},
		{"late-event", func(e []Event) { e[1].Time = e[0].Time.Add(25*time.Hour) }},
		{"reverse-time", func(e []Event) { e[0].Time = e[1].Time.Add(time.Second) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := syntheticTamperEvents()
			tc.edit(e)
			if got := DetectProcessTampering(e); len(got) != 0 {
				t.Fatalf("false tamper correlation: %+v", got)
			}
		})
	}
}

func TestTamperDedupAndOrderIndependence(t *testing.T) {
	e := syntheticTamperEvents()
	expected := DetectProcessTampering(e)
	got := DetectProcessTampering([]Event{e[1], e[0], e[1], e[0]})
	if len(expected) != 1 || len(got) != 1 || expected[0].ID != got[0].ID {
		t.Fatalf("tamper duplicates/reorder changed signal: %+v %+v", expected, got)
	}
	other := syntheticTamperEvents()
	for i := range other {
		other[i].BootID = "boot-b"
	}
	got = DetectProcessTampering(append(e, other...))
	if len(got) != 2 || got[0].ID == got[1].ID {
		t.Fatalf("cross-boot tamper collapsed: %+v", got)
	}
}

func TestTamperMetadataIngestRejectsInvalidType(t *testing.T) {
	for _, tamperType := range []string{"image injected", "image_replaced\nforged", strings.Repeat("x", 33), "executable"} {
		s := NewStore()
		if _, err := s.CheckIn(Agent{ID: "win-tamper", Platform: "windows"}); err != nil {
			t.Fatal(err)
		}
		e := syntheticTamperEvents()[1]
		e.TamperType = tamperType
		if _, err := s.Ingest(e); err == nil || len(s.Snapshot().Events) != 0 {
			t.Fatalf("bad process tamper type admitted: %v %q", err, tamperType)
		}
	}
}

func TestTamperRuleInLabDetectionsAPI(t *testing.T) {
	s := NewStore()
	if _, err := s.CheckIn(Agent{ID: "win-tamper", Platform: "windows"}); err != nil {
		t.Fatal(err)
	}
	for _, e := range syntheticTamperEvents() {
		if _, err := s.Ingest(e); err != nil {
			t.Fatal(err)
		}
	}
	h := (&Server{Store: s, Token: "dev-tamper-token-12345", WebDir: t.TempDir()}).Handler()
	denied := httptest.NewRecorder()
	h.ServeHTTP(denied, httptest.NewRequest(http.MethodGet, "/api/detections", nil))
	if denied.Code != http.StatusUnauthorized { t.Fatalf("lab auth bypass: %d", denied.Code) }
	req := httptest.NewRequest(http.MethodGet, "/api/detections", nil)
	req.Header.Set("Authorization", "Bearer dev-tamper-token-12345")
	got := httptest.NewRecorder()
	h.ServeHTTP(got, req)
	var alerts []Detection
	if got.Code != http.StatusOK || json.Unmarshal(got.Body.Bytes(), &alerts) != nil ||
		len(alerts) != 1 || alerts[0].RuleID != processTamperRuleID {
		t.Fatalf("tamper detection unavailable: %d %s", got.Code, got.Body.String())
	}
}
