package edr

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func syntheticRegistryEvents() []Event {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	common := Event{
		DeviceID: "win-reg", BootID: "boot-a", Platform: "windows",
		Source: "sysmon", ProcessGUID: "{process-a}",
		Image: `C:\Users\Alice\Downloads\update.exe`,
	}
	create := common
	create.ID, create.SourceRecordID = "reg-12", "source-12"
	create.SysmonEventID, create.Type, create.RegistryOperation = 12, "registry_object", "create_key"
	create.RegistryTarget = `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
	create.Time = now

	rename := common
	rename.ID, rename.SourceRecordID = "reg-14", "source-14"
	rename.SysmonEventID, rename.Type, rename.RegistryOperation = 14, "registry_rename", "rename_value"
	rename.RegistryTarget = create.RegistryTarget + `\OldName`
	rename.RegistryNewName = create.RegistryTarget + `\Updater`
	rename.Time = now.Add(time.Minute)

	set := common
	set.ID, set.SourceRecordID = "reg-13", "source-13"
	set.SysmonEventID, set.Type, set.RegistryOperation = 13, "registry_value_set", "set_value"
	set.RegistryTarget = rename.RegistryNewName
	set.Time = now.Add(2 * time.Minute)
	return []Event{create, rename, set}
}

func TestRegistryAutorunNeedsValueSetNotCreateOrRename(t *testing.T) {
	events := syntheticRegistryEvents()
	for _, partial := range [][]Event{events[:1], events[:2], {events[1]}} {
		if got := DetectRegistryAutorunSet(partial); len(got) != 0 {
			t.Fatalf("EID12/14 alone was treated as autorun value set: %+v", got)
		}
	}
	if got := DetectRegistryAutorunSet(events[2:]); len(got) != 1 ||
		got[0].RegistryCreateEventID != "" || got[0].RegistryRenameEventID != "" {
		t.Fatalf("EID13 alone should be provisional without invented context: %+v", got)
	}
	alerts := DetectRegistryAutorunSet(events)
	if len(alerts) != 1 || alerts[0].RegistrySetEventID != "reg-13" ||
		alerts[0].RegistryCreateEventID != "reg-12" ||
		alerts[0].RegistryRenameEventID != "reg-14" ||
		alerts[0].Confidence != "low" || alerts[0].Severity != "medium" ||
		alerts[0].RuleID != registryAutorunRuleID {
		t.Fatalf("wrong Registry evidence IDs or confidence: %+v", alerts)
	}
}

func TestRegistryRunValuePathExactness(t *testing.T) {
	accept := []string{
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Good`,
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\Updater`,
		`HKU\S-1-5-21-1234\Software\Microsoft\Windows\CurrentVersion\Run\Up`,
		`HKLM\Software\WOW6432NODE\Microsoft\Windows\CurrentVersion\Run\Good`,
	}
	for _, p := range accept {
		if _, ok := registryAutorunValueKey(p); !ok {
			t.Errorf("ordinary autostart path rejected: %q", p)
		}
	}
	reject := []string{
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`,
		`HKCU\Software\Microsoft\Windows\CurrentVersion\RunOther\Good`,
		`HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices\Good`,
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Value\Subkey`,
		`HKLM\Software\Vendor\Run\Good`,
		`HKU\WrongSID\Software\Microsoft\Windows\CurrentVersion\Run\Good`,
		`HKCR\Software\Microsoft\Windows\CurrentVersion\Run\Good`,
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Run\`,
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Run\..`,
	}
	for _, p := range reject {
		if _, ok := registryAutorunValueKey(p); ok {
			t.Errorf("unrelated or non-value autostart path matched: %q", p)
		}
	}
}

func TestRegistryRuleNegativeEvidenceAndFalsePositives(t *testing.T) {
	cases := []struct {
		name string
		mutate func([]Event)
	}{
		{"wrong-event-id", func(e []Event) { e[2].SysmonEventID = 12 }},
		{"wrong-event-type", func(e []Event) { e[2].Type = "registry_object" }},
		{"delete-operation", func(e []Event) { e[2].RegistryOperation = "delete_value" }},
		{"non-sysmon", func(e []Event) { e[2].Source = "other" }},
		{"missing-boot", func(e []Event) { e[2].BootID = "" }},
		{"missing-record-id", func(e []Event) { e[2].SourceRecordID = "" }},
		{"missing-process", func(e []Event) { e[2].ProcessGUID = "" }},
		{"missing-image", func(e []Event) { e[2].Image = "" }},
		{"trusted-system-location", func(e []Event) { e[2].Image = `C:\Windows\System32\msiexec.exe` }},
		{"not-an-exe", func(e []Event) { e[2].Image = `C:\Users\Alice\Temp\script.ps1` }},
		{"not-run-key", func(e []Event) { e[2].RegistryTarget = strings.Replace(e[2].RegistryTarget, `\Run\`, `\RunOther\`, 1) }},
		{"not-windows", func(e []Event) { e[2].Platform = "linux" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := syntheticRegistryEvents()
			tc.mutate(e)
			if got := DetectRegistryAutorunSet(e); len(got) != 0 {
				t.Fatalf("false Registry signal was emitted: %+v", got)
			}
		})
	}
}

func TestRegistryEnrichmentRequiresSameBootProcessAndTime(t *testing.T) {
	for _, tc := range []struct {
		name string
		mutate func([]Event)
	}{
		{"cross-boot-create", func(e []Event) { e[0].BootID = "other" }},
		{"cross-device-create", func(e []Event) { e[0].DeviceID = "other" }},
		{"cross-process-rename", func(e []Event) { e[1].ProcessGUID = "{other}" }},
		{"too-old-create", func(e []Event) { e[0].Time = e[2].Time.Add(-11 * time.Minute) }},
		{"rename-after-set", func(e []Event) { e[1].Time = e[2].Time.Add(time.Second) }},
		{"delete-key", func(e []Event) { e[0].RegistryOperation = "delete_key" }},
		{"rename-new-name-different", func(e []Event) { e[1].RegistryNewName += "Other" }},
		{"same-source-record", func(e []Event) { e[1].SourceRecordID = e[2].SourceRecordID }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := syntheticRegistryEvents()
			tc.mutate(e)
			got := DetectRegistryAutorunSet(e)
			if len(got) != 1 {
				t.Fatalf("valid EID13 was discarded due to unrelated context: %+v", got)
			}
			if strings.Contains(tc.name, "create") || tc.name == "delete-key" {
				if got[0].RegistryCreateEventID != "" {
					t.Fatalf("invalid EID12 evidence linked: %+v", got)
				}
			} else if got[0].RegistryRenameEventID != "" {
				t.Fatalf("invalid EID14 evidence linked: %+v", got)
			}
		})
	}
}

func TestRegistryDetectorStableUnderDuplicateAndShuffledInputs(t *testing.T) {
	e := syntheticRegistryEvents()
	original := DetectRegistryAutorunSet(e)
	shuffled := []Event{e[2], e[1], e[0], e[2], e[0]}
	got := DetectRegistryAutorunSet(shuffled)
	if len(original) != 1 || len(got) != 1 ||
		original[0].ID != got[0].ID ||
		got[0].RegistryCreateEventID != "reg-12" || got[0].RegistryRenameEventID != "reg-14" {
		t.Fatalf("duplicate or shuffled observations altered alert: %+v vs %+v", original, got)
	}
}

func TestRegistryMetadataValidationAndAPIContract(t *testing.T) {
	for _, val := range []struct {
		name string
		mutate func(*Event)
	}{
		{"target-overlong", func(e *Event) { e.RegistryTarget = strings.Repeat("a", 1025) }},
		{"target-newline", func(e *Event) { e.RegistryTarget = "HKCU\\fake\nforged" }},
		{"target-trailing-space", func(e *Event) { e.RegistryTarget += " " }},
		{"new-name-control", func(e *Event) { e.RegistryNewName = "X\x7f" }},
		{"invalid-operation", func(e *Event) { e.RegistryOperation = "execute" }},
	} {
		t.Run(val.name, func(t *testing.T) {
			s := NewStore()
			if _, err := s.CheckIn(Agent{ID: "win-reg", Platform: "windows"}); err != nil { t.Fatal(err) }
			ev := syntheticRegistryEvents()[2]
			val.mutate(&ev)
			if _, err := s.Ingest(ev); err == nil || len(s.Snapshot().Events) != 0 {
				t.Fatalf("malformed registry record persisted: %v %+v", err, ev)
			}
		})
	}
	s := NewStore()
	if _, err := s.CheckIn(Agent{ID: "win-reg", Platform: "windows"}); err != nil { t.Fatal(err) }
	for _, ev := range syntheticRegistryEvents() {
		if _, err := s.Ingest(ev); err != nil { t.Fatalf("ingest: %v", err) }
	}
	h := (&Server{Store: s, Token: "dev-registry-token-12345", WebDir: t.TempDir()}).Handler()
	req := httptest.NewRequest(http.MethodGet, "/api/detections", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized { t.Fatalf("missing auth accepted: %d", rec.Code) }
	req = httptest.NewRequest(http.MethodGet, "/api/detections", nil)
	req.Header.Set("Authorization", "Bearer dev-registry-token-12345")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var got []Detection
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &got) != nil ||
		len(got) != 1 || got[0].RuleID != registryAutorunRuleID {
		t.Fatalf("registry signal not available via authorized API: status=%d body=%s", rec.Code, rec.Body.String())
	}
}
