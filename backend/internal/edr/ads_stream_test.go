package edr

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func syntheticADS() Event {
	return Event{
		ID: "ads-15", SourceRecordID: "sysmon-record-15",
		DeviceID: "win-ads", BootID: "boot-a", Platform: "windows",
		Source: "sysmon", Type: "file_create_stream_hash",
		SysmonEventID: 15, ProcessGUID: "{proc-a}",
		Image: "C:\\Windows\\explorer.exe",
		FilePath: "C:\\Users\\Alice\\Downloads\\archive.zip:payload",
		Hash: strings.Repeat("a", 64),
		Time: time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC),
	}
}

func TestADSDetectorNeedsRealEID15AndNonMOTWStream(t *testing.T) {
	e := syntheticADS()
	got := DetectAlternateDataStreams([]Event{e})
	if len(got) != 1 || got[0].RuleID != adsStreamRuleID ||
		got[0].StreamEventID != "ads-15" ||
		got[0].StreamName != "payload" ||
		got[0].Confidence != "low" || got[0].Severity != "medium" {
		t.Fatalf("valid non-MOTW alternate stream missing evidence: %+v", got)
	}
	e.FilePath = "C:\\Users\\Alice\\Downloads\\sample.exe:payload:$DATA"
	if got := DetectAlternateDataStreams([]Event{e}); len(got) != 1 {
		t.Fatalf("explicit named NTFS data stream rejected: %+v", got)
	}
}

func TestADSDetectorSuppressesMOTWAndUnsupportedInputs(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*Event)
	}{
		{"zone-identifier", func(e *Event) { e.FilePath = "C:\\Users\\Alice\\Downloads\\demo.exe:Zone.Identifier" }},
		{"zone-identifier-data", func(e *Event) { e.FilePath = "C:\\Users\\Alice\\Downloads\\demo.exe:Zone.Identifier:$DATA" }},
		{"default-data-stream", func(e *Event) { e.FilePath = "C:\\Users\\Alice\\Downloads\\demo.exe::$DATA" }},
		{"metadata-stream", func(e *Event) { e.FilePath = "C:\\Users\\Alice\\Downloads\\file.bin:WofCompressedData" }},
		{"missing-stream", func(e *Event) { e.FilePath = "C:\\Users\\Alice\\Downloads\\demo.exe" }},
		{"wrong-EID", func(e *Event) { e.SysmonEventID = 11 }},
		{"wrong-type", func(e *Event) { e.Type = "file_create" }},
		{"different-source", func(e *Event) { e.Source = "user_upload" }},
		{"different-platform", func(e *Event) { e.Platform = "linux" }},
		{"missing-boot", func(e *Event) { e.BootID = "" }},
		{"missing-process", func(e *Event) { e.ProcessGUID = "" }},
		{"missing-source-record", func(e *Event) { e.SourceRecordID = "" }},
		{"missing-time", func(e *Event) { e.Time = time.Time{} }},
		{"missing-hash", func(e *Event) { e.Hash = "" }},
		{"invalid-hash", func(e *Event) { e.Hash = strings.Repeat("g", 64) }},
		{"system-file", func(e *Event) { e.FilePath = "C:\\Windows\\System32\\kernel32.dll:payload" }},
		{"invalid-ADS-char", func(e *Event) { e.FilePath = "C:\\Users\\Alice\\Downloads\\demo.exe:bad?name" }},
		{"nested-colon", func(e *Event) { e.FilePath = "C:\\Users\\Alice\\Downloads\\demo.exe:payload:other" }},
		{"relative-path", func(e *Event) { e.FilePath = "..\\demo.exe:payload" }},
		{"network-path", func(e *Event) { e.FilePath = "\\\\server\\share\\demo.exe:payload" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := syntheticADS()
			tc.edit(&e)
			if got := DetectAlternateDataStreams([]Event{e}); len(got) != 0 {
				t.Fatalf("unsupported/benign stream produced alert: %+v", got)
			}
		})
	}
}

func TestADSNoDuplicatesAndBootScope(t *testing.T) {
	e := syntheticADS()
	repeated := DetectAlternateDataStreams([]Event{e, e})
	if len(repeated) != 1 {
		t.Fatalf("replayed event counted twice: %+v", repeated)
	}
	other := e
	other.BootID = "boot-b"
	got := DetectAlternateDataStreams([]Event{e, other})
	if len(got) != 2 || got[0].ID == got[1].ID {
		t.Fatalf("cross-boot ADS events combined: %+v", got)
	}
}

func TestADSVisibleFromAuthorizedLabDetectionsAPI(t *testing.T) {
	s := NewStore()
	if _, err := s.CheckIn(Agent{ID:"win-ads", Platform:"windows"}); err != nil { t.Fatal(err) }
	if _, err := s.Ingest(syntheticADS()); err != nil { t.Fatal(err) }
	h := (&Server{Store:s, Token:"ads-development-token-123", WebDir:t.TempDir()}).Handler()
	out := httptest.NewRecorder()
	h.ServeHTTP(out, httptest.NewRequest(http.MethodGet, "/api/detections", nil))
	if out.Code != http.StatusUnauthorized { t.Fatalf("missing dev token accepted: %d", out.Code) }
	req := httptest.NewRequest(http.MethodGet, "/api/detections", nil)
	req.Header.Set("Authorization", "Bearer ads-development-token-123")
	out = httptest.NewRecorder()
	h.ServeHTTP(out, req)
	var detections []Detection
	if out.Code != http.StatusOK || json.Unmarshal(out.Body.Bytes(), &detections) != nil ||
		len(detections) != 1 || detections[0].RuleID != adsStreamRuleID {
		t.Fatalf("EID15 signal missing from lab API: %d %s", out.Code, out.Body.String())
	}
}
