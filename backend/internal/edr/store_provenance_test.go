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
