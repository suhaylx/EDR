package edr

import (
	"strings"
	"testing"
	"time"
)

func TestIngestRecordsServerReceiptAndUnverifiedSenderTime(t *testing.T) {
	store := NewStore()
	if _, err := store.CheckIn(Agent{ID: "win-01", Platform: "windows"}); err != nil {
		t.Fatal(err)
	}
	senderTime := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	before := time.Now().UTC()
	event, err := store.Ingest(Event{
		DeviceID: "win-01", Platform: "windows", Type: "module_load",
		Source: "sysmon-synthetic", SourceRecordID: "EventRecordID:42",
		Time: senderTime, TimeOrigin: "trusted", ReceivedAt: senderTime,
	})
	after := time.Now().UTC()
	if err != nil {
		t.Fatal(err)
	}
	if event.Time != senderTime || event.TimeOrigin != "sender_reported_unverified" {
		t.Fatalf("sender time misrepresented: %+v", event)
	}
	if event.ReceivedAt.Before(before) || event.ReceivedAt.After(after) {
		t.Fatalf("client-controlled receipt time was accepted: %+v", event)
	}
	if event.SourceRecordID != "EventRecordID:42" {
		t.Fatalf("source record identifier not retained: %+v", event)
	}
	stored := store.Snapshot().Events[0]
	if stored.TimeOrigin != event.TimeOrigin || !stored.ReceivedAt.Equal(event.ReceivedAt) {
		t.Fatalf("receipt provenance missing from snapshot: %+v", stored)
	}
}

func TestIngestFallbackTimeIsMarkedServerReceived(t *testing.T) {
	store := NewStore()
	if _, err := store.CheckIn(Agent{ID: "win-01", Platform: "windows"}); err != nil {
		t.Fatal(err)
	}
	event, err := store.Ingest(Event{
		DeviceID: "win-01", Platform: "windows", Type: "process_create",
		TimeOrigin: "sender_reported_unverified",
	})
	if err != nil {
		t.Fatal(err)
	}
	if event.Time.IsZero() || event.ReceivedAt.IsZero() ||
		!event.Time.Equal(event.ReceivedAt) || event.TimeOrigin != "server_received" {
		t.Fatalf("server fallback timestamp not labeled correctly: %+v", event)
	}
}

func TestIngestRejectsMalformedSourceRecordID(t *testing.T) {
	store := NewStore()
	if _, err := store.CheckIn(Agent{ID: "win-01", Platform: "windows"}); err != nil {
		t.Fatal(err)
	}
	for _, sourceID := range []string{
		strings.Repeat("x", 257), "record\nforged", "record\rforged", "record\x00forged",
		"record\tforged", "record\x1bforged", "record\x7fforged", "record\ufffdforged",
	} {
		if _, err := store.Ingest(Event{
			DeviceID: "win-01", Platform: "windows", Type: "module_load",
			SourceRecordID: sourceID,
		}); err == nil {
			t.Fatalf("accepted malformed source record id %q", sourceID)
		}
	}
	if len(store.Snapshot().Events) != 0 {
		t.Fatal("rejected events were persisted")
	}
}

func TestIngestBoundsUntrustedTelemetryFields(t *testing.T) {
	tests := []struct {
		name string
		mutate func(*Event)
	}{
		{"source", func(e *Event) { e.Source = strings.Repeat("s", 129) }},
		{"process-guid", func(e *Event) { e.ProcessGUID = strings.Repeat("p", 129) }},
		{"parent-process-guid", func(e *Event) { e.ParentProcessGUID = strings.Repeat("p", 129) }},
		{"image", func(e *Event) { e.Image = strings.Repeat("i", 32769) }},
		{"file-path", func(e *Event) { e.FilePath = strings.Repeat("f", 32769) }},
		{"hash", func(e *Event) { e.Hash = strings.Repeat("h", 257) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := NewStore()
			if _, err := store.CheckIn(Agent{ID: "win-01", Platform: "windows"}); err != nil {
				t.Fatal(err)
			}
			event := Event{DeviceID: "win-01", Platform: "windows", Type: "module_load"}
			tc.mutate(&event)
			if _, err := store.Ingest(event); err == nil {
				t.Fatalf("oversized %s field accepted", tc.name)
			}
			if got := len(store.Snapshot().Events); got != 0 {
				t.Fatalf("rejected event persisted: %d", got)
			}
		})
	}
}

func TestIngestRejectsFutureEventTimestampWithoutRetention(t *testing.T) {
	store := NewStore()
	if _, err := store.CheckIn(Agent{ID: "win-01", Platform: "windows"}); err != nil {
		t.Fatal(err)
	}
	event := Event{
		DeviceID: "win-01", Platform: "windows", Type: "module_load",
		Time: time.Now().UTC().Add(10 * time.Minute),
	}
	if _, err := store.Ingest(event); err == nil {
		t.Fatal("accepted event with timestamp far in the future")
	}
	if got := len(store.Snapshot().Events); got != 0 {
		t.Fatalf("future-dated event was retained: %d", got)
	}
}

func TestIngestOverwritesClientSuppliedIDAndReceiptProvenance(t *testing.T) {
	store := NewStore()
	if _, err := store.CheckIn(Agent{ID: "win-01", Platform: "windows"}); err != nil {
		t.Fatal(err)
	}
	sender := Event{
		ID: "forged-ingest-id", DeviceID: "win-01", Platform: "windows",
		Type: "module_load", SourceRecordID: "42",
		ReceivedAt: time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC),
		TimeOrigin: "trusted",
	}
	first, err := store.Ingest(sender)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.Ingest(sender)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID == sender.ID || second.ID == sender.ID || first.ID == second.ID {
		t.Fatalf("client forged or reused ingest ID: %q %q", first.ID, second.ID)
	}
	for _, e := range []Event{first, second} {
		if e.TimeOrigin != "server_received" || !e.ReceivedAt.Equal(e.Time) ||
			e.ReceivedAt.Year() == 2000 {
			t.Fatalf("client-controlled provenance accepted: %+v", e)
		}
	}
	if len(store.Snapshot().Events) != 2 {
		t.Fatal("lab prototype must not silently suppress repeated source records")
	}
}
