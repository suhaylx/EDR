package edr

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func syntheticWMISubscription() []Event {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	common := Event{DeviceID: "win-wmi", BootID: "boot-a", Platform: "windows", Source: "sysmon"}
	filter := common
	filter.ID, filter.SourceRecordID = "wmi-19", "source-19"
	filter.Type, filter.SysmonEventID = "wmi_filter", 19
	filter.WMIFilterName = "AuditFilter"
	filter.Time = now
	consumer := common
	consumer.ID, consumer.SourceRecordID = "wmi-20", "source-20"
	consumer.Type, consumer.SysmonEventID = "wmi_consumer", 20
	consumer.WMIConsumerName = "AuditConsumer"
	consumer.Time = now.Add(time.Minute)
	binding := common
	binding.ID, binding.SourceRecordID = "wmi-21", "source-21"
	binding.Type, binding.SysmonEventID = "wmi_binding", 21
	binding.WMIFilterName, binding.WMIConsumerName = "AuditFilter", "AuditConsumer"
	binding.Time = now.Add(2 * time.Minute)
	return []Event{filter, consumer, binding}
}

func TestWMICorrelationRequiresThreeIndependentEvents(t *testing.T) {
	e := syntheticWMISubscription()
	for _, partial := range [][]Event{
		e[:1], e[:2], {e[1]}, {e[2]}, {e[0], e[2]}, {e[1], e[2]},
	} {
		if got := DetectWMIPermanentSubscription(partial); len(got) != 0 {
			t.Fatalf("incomplete WMI chain claimed persistence: %+v", got)
		}
	}
	got := DetectWMIPermanentSubscription(e)
	if len(got) != 1 || got[0].RuleID != wmiSubscriptionRuleID ||
		got[0].WMIFilterEventID != "wmi-19" ||
		got[0].WMIConsumerEventID != "wmi-20" ||
		got[0].WMIBindingEventID != "wmi-21" ||
		got[0].WMIFilterName != "AuditFilter" ||
		got[0].WMIConsumerName != "AuditConsumer" ||
		got[0].Confidence != "low" || got[0].Severity != "medium" {
		t.Fatalf("full WMI subscription evidence missing/wrong: %+v", got)
	}
}

func TestWMISubscriptionRejectsCrossScopeAndInvalidEvidence(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func([]Event)
	}{
		{"different-filter-device", func(e []Event) { e[0].DeviceID = "other" }},
		{"different-consumer-device", func(e []Event) { e[1].DeviceID = "other" }},
		{"different-filter-boot", func(e []Event) { e[0].BootID = "boot-b" }},
		{"different-consumer-boot", func(e []Event) { e[1].BootID = "boot-b" }},
		{"missing-binding-boot", func(e []Event) { e[2].BootID = "" }},
		{"wrong-filter-name", func(e []Event) { e[0].WMIFilterName = "Other" }},
		{"wrong-consumer-name", func(e []Event) { e[1].WMIConsumerName = "Other" }},
		{"empty-filter-name", func(e []Event) { e[0].WMIFilterName = "" }},
		{"empty-consumer-name", func(e []Event) { e[1].WMIConsumerName = "" }},
		{"non-sysmon-consumer", func(e []Event) { e[1].Source = "unknown" }},
		{"wrong-filter-EID", func(e []Event) { e[0].SysmonEventID = 18 }},
		{"wrong-consumer-EID", func(e []Event) { e[1].SysmonEventID = 19 }},
		{"wrong-binding-EID", func(e []Event) { e[2].SysmonEventID = 20 }},
		{"wrong-binding-type", func(e []Event) { e[2].Type = "wmi_filter" }},
		{"missing-source-record", func(e []Event) { e[2].SourceRecordID = "" }},
		{"same-filter-binding-record", func(e []Event) { e[0].SourceRecordID = e[2].SourceRecordID }},
		{"same-consumer-binding-record", func(e []Event) { e[1].SourceRecordID = e[2].SourceRecordID }},
		{"same-filter-consumer-record", func(e []Event) { e[1].SourceRecordID = e[0].SourceRecordID }},
		{"filter-after-binding", func(e []Event) { e[0].Time = e[2].Time.Add(time.Second) }},
		{"consumer-after-binding", func(e []Event) { e[1].Time = e[2].Time.Add(time.Second) }},
		{"filter-too-old", func(e []Event) { e[0].Time = e[2].Time.Add(-31*time.Minute) }},
		{"consumer-too-old", func(e []Event) { e[1].Time = e[2].Time.Add(-31*time.Minute) }},
		{"linux-not-windows", func(e []Event) { e[0].Platform = "linux" }},
		{"binding-missing-identity", func(e []Event) { e[2].WMIConsumerName = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := syntheticWMISubscription()
			tc.edit(e)
			if got := DetectWMIPermanentSubscription(e); len(got) != 0 {
				t.Fatalf("incorrect WMI evidence joined: %+v", got)
			}
		})
	}
}

func TestWMINameCaseIndependenceAndOutOfOrderDedup(t *testing.T) {
	e := syntheticWMISubscription()
	e[0].WMIFilterName = "AUDITFILTER"
	e[1].WMIConsumerName = "auditconsumer"
	first := DetectWMIPermanentSubscription(e)
	reversed := DetectWMIPermanentSubscription([]Event{e[2], e[1], e[0], e[2], e[1]})
	if len(first) != 1 || len(reversed) != 1 || first[0].ID != reversed[0].ID {
		t.Fatalf("case/duplicate/out-of-order changed WMI correlation: %+v %+v", first, reversed)
	}
	other := syntheticWMISubscription()
	for i := range other {
		other[i].BootID = "boot-b"
	}
	both := DetectWMIPermanentSubscription(append(e, other...))
	if len(both) != 2 || both[0].ID == both[1].ID {
		t.Fatalf("distinct reported boot sessions collapsed: %+v", both)
	}
}

func TestWMIIngestBoundsAndSourceUnverified(t *testing.T) {
	for _, tc := range []struct{
		name string
		change func(*Event)
	}{
		{"long-filter", func(e *Event) { e.WMIFilterName = strings.Repeat("x", 257) }},
		{"long-consumer", func(e *Event) { e.WMIConsumerName = strings.Repeat("x", 257) }},
		{"filter-newline", func(e *Event) { e.WMIFilterName = "filter\nforged" }},
		{"consumer-tab", func(e *Event) { e.WMIConsumerName = "bad\tconsumer" }},
		{"consumer-trailing-space", func(e *Event) { e.WMIConsumerName = "consumer " }},
		{"filter-replacement-char", func(e *Event) { e.WMIFilterName = "f\ufffdo" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := NewStore()
			if _, err := s.CheckIn(Agent{ID:"win-wmi", Platform:"windows"}); err != nil { t.Fatal(err) }
			e := syntheticWMISubscription()[2]
			tc.change(&e)
			if _, err := s.Ingest(e); err == nil || len(s.Snapshot().Events) != 0 {
				t.Fatalf("malformed WMI evidence retained: %v %+v", err, e)
			}
		})
	}
}

func TestWMIReadOnlyDetectorAvailableThroughLabAPI(t *testing.T) {
	s := NewStore()
	if _, err := s.CheckIn(Agent{ID:"win-wmi", Platform:"windows"}); err != nil { t.Fatal(err) }
	for _, e := range syntheticWMISubscription() {
		if _, err := s.Ingest(e); err != nil { t.Fatal(err) }
	}
	h := (&Server{Store:s, Token:"wmi-development-token-123", WebDir:t.TempDir()}).Handler()
	unauthorized := httptest.NewRecorder()
	h.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/api/detections", nil))
	if unauthorized.Code != http.StatusUnauthorized { t.Fatalf("anonymous API returned %d", unauthorized.Code) }
	req := httptest.NewRequest(http.MethodGet, "/api/detections", nil)
	req.Header.Set("Authorization", "Bearer wmi-development-token-123")
	out := httptest.NewRecorder()
	h.ServeHTTP(out, req)
	var got []Detection
	if out.Code != http.StatusOK || json.Unmarshal(out.Body.Bytes(), &got) != nil ||
		len(got) != 1 || got[0].RuleID != wmiSubscriptionRuleID {
		t.Fatalf("WMI detection absent from lab endpoint: %d %s", out.Code, out.Body.String())
	}
}
