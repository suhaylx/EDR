package edr

import (
	"encoding/json"
	"strings"
	"testing"
)

// Synthetic payloads only: no actual clipboard, credentials or live Sysmon data.
func TestSEC076ClipboardMetadataStripsPrivateDetailBeforePersistence(t *testing.T) {
	store := NewStore()
	if _, err := store.CheckIn(Agent{ID: "win-privacy-lab", Platform: "windows"}); err != nil {
		t.Fatal(err)
	}
	event := Event{
		DeviceID: "win-privacy-lab", Platform: "windows", Source: "sysmon",
		SourceProvider: "Microsoft-Windows-Sysmon",
		SourceChannel: "Microsoft-Windows-Sysmon/Operational",
		SourceEventID: 24, SourceRecordID: "431",
		Type: "clipboard_change_metadata",
		Detail: "PRIVATE_CLIPBOARD_TEST_MARKER",
	}
	saved, err := store.Ingest(event)
	if err != nil {
		t.Fatalf("metadata-only event denied: %v", err)
	}
	if saved.Detail != "Sysmon clipboard change observed; clipboard content not collected" {
		t.Fatalf("free-form clipboard detail survived sanitization: %q", saved.Detail)
	}
	snapshot, err := json.Marshal(store.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(snapshot), "PRIVATE_CLIPBOARD_TEST_MARKER") {
		t.Fatal("private clipboard detail leaked into retained event snapshot")
	}
	if len(store.Snapshot().Events) != 1 {
		t.Fatal("expected exactly one retained metadata-only event")
	}
}

func TestSEC076ClipboardRejectsHiddenHashAndInvalidSourceRecord(t *testing.T) {
	for _, tc := range []struct {
		name string
		hash string
		record string
		fields map[string]string
	}{
		{"clipboard-hash", "PRIVATE_HASH_TEST", "1", nil},
		{"nonnumeric-record", "", "SECRET_RECORD", nil},
		{"oversize-record", "", "123456789012345678901", nil},
		{"private-source-field", "", "1", map[string]string{"query_name": "PRIVATE_FIELD"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := NewStore()
			if _, err := store.CheckIn(Agent{ID: "win-privacy-lab", Platform: "windows"}); err != nil {
				t.Fatal(err)
			}
			_, err := store.Ingest(Event{
				DeviceID: "win-privacy-lab", Platform: "windows", Source: "sysmon",
				SourceEventID: 24, SourceRecordID: tc.record,
				Type: "clipboard_change_metadata", Hash: tc.hash, SourceFields: tc.fields,
			})
			if err == nil || len(store.Snapshot().Events) != 0 {
				t.Fatalf("unsafe clipboard metadata accepted or retained: %q", tc.name)
			}
		})
	}
}

func TestSEC076SourceProviderCannotClaimSysmonWithoutNumberedEvent(t *testing.T) {
	store := NewStore()
	if _, err := store.CheckIn(Agent{ID: "win-privacy-lab", Platform: "windows"}); err != nil {
		t.Fatal(err)
	}
	taggedUnknown := Event{
		DeviceID: "win-privacy-lab", Platform: "windows", Source: "sysmon",
		SourceProvider: "Microsoft-Windows-Sysmon",
		SourceChannel: "Microsoft-Windows-Sysmon/Operational",
		Type: "legacy_unknown", SourceEventID: 0,
	}
	if _, err := store.Ingest(taggedUnknown); err == nil {
		t.Fatal("tagged Sysmon event without numerical Event ID was accepted")
	}
	if len(store.Snapshot().Events) != 0 {
		t.Fatal("rejected forged source changed event history")
	}
	// Legacy untagged lab observations stay explicitly unverified.
	taggedUnknown.SourceProvider = ""
	taggedUnknown.SourceChannel = ""
	if _, err := store.Ingest(taggedUnknown); err != nil {
		t.Fatalf("unclassified legacy lab observation should remain accepted: %v", err)
	}
}
