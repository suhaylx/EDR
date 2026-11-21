package edr

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func syntheticExecutableDrop() []Event {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	create := Event{
		ID: "file-11", SourceRecordID: "source-file-11",
		DeviceID: "win-drop", BootID: "boot-a", Platform: "windows",
		Source: "sysmon", SysmonEventID: 11, Type: "file_create",
		ProcessGUID: "{writer-1}", Image: "C:\\Windows\\explorer.exe",
		FilePath: "C:\\Users\\Alice\\Downloads\\installer.exe",
		Time: now,
	}
	exe := create
	exe.ID, exe.SourceRecordID = "exe-29", "source-file-29"
	exe.SysmonEventID, exe.Type = 29, "file_executable_detected"
	exe.Hash = strings.Repeat("b", 64)
	exe.Time = now.Add(time.Minute)
	return []Event{create, exe}
}

func TestFileCreateAndExecutableDetectionRequiredButNotExecution(t *testing.T) {
	e := syntheticExecutableDrop()
	if got := DetectExecutableFileDrops(e[:1]); len(got) != 0 {
		t.Fatalf("EID11 alone falsely detected executable: %+v", got)
	}
	if got := DetectExecutableFileDrops(e[1:]); len(got) != 0 {
		t.Fatalf("EID29 alone was linked to missing file create: %+v", got)
	}
	got := DetectExecutableFileDrops(e)
	if len(got) != 1 || got[0].RuleID != executableDropRuleID ||
		got[0].FileDropCreateEventID != "file-11" ||
		got[0].ExecutableDetectedEventID != "exe-29" ||
		got[0].Confidence != "low" || got[0].Severity != "medium" ||
		got[0].Category != "executable_file_created_not_executed" {
		t.Fatalf("EID11+29 linkage or meaning incorrect: %+v", got)
	}
}

func TestExecutableDropRejectsUncorroboratedAndFalseEvidence(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func([]Event)
	}{
		{"different-device", func(e []Event) { e[0].DeviceID = "other" }},
		{"different-boot", func(e []Event) { e[1].BootID = "other" }},
		{"missing-boot", func(e []Event) { e[0].BootID = "" }},
		{"different-process", func(e []Event) { e[0].ProcessGUID = "{other}" }},
		{"different-path", func(e []Event) { e[1].FilePath = "C:\\Users\\Alice\\Downloads\\other.exe" }},
		{"system32-file", func(e []Event) { e[1].FilePath = "C:\\Windows\\System32\\setup.exe"; e[0].FilePath = e[1].FilePath }},
		{"wrong-create-EID", func(e []Event) { e[0].SysmonEventID = 7 }},
		{"wrong-executable-EID", func(e []Event) { e[1].SysmonEventID = 11 }},
		{"wrong-executable-type", func(e []Event) { e[1].Type = "file_create" }},
		{"wrong-create-type", func(e []Event) { e[0].Type = "process_create" }},
		{"wrong-source", func(e []Event) { e[0].Source = "filesystem" }},
		{"wrong-platform", func(e []Event) { e[1].Platform = "linux" }},
		{"same-source-record", func(e []Event) { e[1].SourceRecordID = e[0].SourceRecordID }},
		{"missing-source-record", func(e []Event) { e[1].SourceRecordID = "" }},
		{"missing-process", func(e []Event) { e[0].ProcessGUID = "" }},
		{"missing-hash", func(e []Event) { e[1].Hash = "" }},
		{"invalid-hash", func(e []Event) { e[1].Hash = strings.Repeat("g",64) }},
		{"different-valid-hash", func(e []Event) { e[0].Hash = strings.Repeat("a",64) }},
		{"malformed-create-hash", func(e []Event) { e[0].Hash = "short" }},
		{"file-not-pe-extension", func(e []Event) { e[1].FilePath = "C:\\Users\\Alice\\Downloads\\note.txt"; e[0].FilePath = e[1].FilePath }},
		{"reverse-time", func(e []Event) { e[0].Time = e[1].Time.Add(time.Second) }},
		{"stale-file-create", func(e []Event) { e[0].Time = e[1].Time.Add(-11*time.Minute) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := syntheticExecutableDrop()
			tc.edit(e)
			if got := DetectExecutableFileDrops(e); len(got) != 0 {
				t.Fatalf("false EID11/29 linkage: %+v", got)
			}
		})
	}
}

func TestExecutableDropReorderingDedupAndBootScope(t *testing.T) {
	e := syntheticExecutableDrop()
	baseline := DetectExecutableFileDrops(e)
	reverse := DetectExecutableFileDrops([]Event{e[1], e[0], e[1], e[0]})
	if len(baseline) != 1 || len(reverse) != 1 || baseline[0].ID != reverse[0].ID {
		t.Fatalf("duplicate/reordered file-drop changed detection: %+v %+v", baseline, reverse)
	}
	other := syntheticExecutableDrop()
	for i := range other { other[i].BootID = "boot-b" }
	two := DetectExecutableFileDrops(append(e, other...))
	if len(two) != 2 || two[0].ID == two[1].ID {
		t.Fatalf("separate reported boots collapsed: %+v", two)
	}
}

func TestExecutableDropReadOnlyLabAPI(t *testing.T) {
	s := NewStore()
	if _, err := s.CheckIn(Agent{ID:"win-drop", Platform:"windows"}); err != nil {t.Fatal(err)}
	for _, e := range syntheticExecutableDrop() {
		if _, err := s.Ingest(e); err != nil { t.Fatal(err) }
	}
	h := (&Server{Store:s, Token:"file-drop-lab-token-12345", WebDir:t.TempDir()}).Handler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet,"/api/detections",nil))
	if rec.Code != http.StatusUnauthorized {t.Fatalf("anonymous access: %d",rec.Code)}
	req := httptest.NewRequest(http.MethodGet,"/api/detections",nil)
	req.Header.Set("Authorization","Bearer file-drop-lab-token-12345")
	rec=httptest.NewRecorder()
	h.ServeHTTP(rec,req)
	var got []Detection
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &got) != nil ||
		len(got) != 1 || got[0].RuleID != executableDropRuleID {
		t.Fatalf("lab API did not return EID11/29 signal: %d %s",rec.Code,rec.Body.String())
	}
}
