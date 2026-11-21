package edr

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func syntheticNetworkTrio() []Event {
	start := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	return []Event{
		{ID: "proc-1", DeviceID: "win01", BootID: "boot-a",
			Platform: "windows", Source: "sysmon", SourceRecordID: "1001",
			Type: "process_create", SysmonEventID: 1, ProcessGUID: "process-a",
			Image: `C:\Users\Alice\Downloads\setup.exe`, Time: start},
		{ID: "dns-1", DeviceID: "win01", BootID: "boot-a",
			Platform: "windows", Source: "sysmon", SourceRecordID: "1002",
			Type: "dns_query", SysmonEventID: 22, ProcessGUID: "process-a",
			DNSQuery: "updates.example.test",
			DNSAnswers: []string{"93.184.216.34", "2606:4700::1111"},
			Time: start.Add(time.Minute)},
		{ID: "net-1", DeviceID: "win01", BootID: "boot-a",
			Platform: "windows", Source: "sysmon", SourceRecordID: "1003",
			Type: "network_connect", SysmonEventID: 3, ProcessGUID: "process-a",
			DestinationIP: "93.184.216.34", DestinationPort: 443,
			Time: start.Add(2 * time.Minute)},
	}
}

func TestProcessDNSNetworkNeedsThreeIndependentSysmonEvents(t *testing.T) {
	trio := syntheticNetworkTrio()
	for _, partial := range [][]Event{trio[:1], trio[:2], {trio[0], trio[2]}, {trio[1], trio[2]}} {
		if got := DetectSuspiciousProcessDNSNetwork(partial); len(got) != 0 {
			t.Fatalf("incomplete Sysmon sequence produced alert: %+v", got)
		}
	}
	got := DetectSuspiciousProcessDNSNetwork(trio)
	if len(got) != 1 {
		t.Fatalf("expected one provisional three-event correlation: %+v", got)
	}
	d := got[0]
	if d.RuleID != processDNSNetworkRuleID || d.Category != "process_dns_network_correlation" ||
		d.Severity != "medium" || d.Confidence != "low" ||
		d.ProcessCreateEventID != "proc-1" || d.DNSEventID != "dns-1" ||
		d.NetworkEventID != "net-1" || d.DNSQuery != "updates.example.test" ||
		d.DestinationIP != "93.184.216.34" || d.DestinationPort != 443 {
		t.Fatalf("incorrect three-event evidence or confidence: %+v", d)
	}
}

func TestProcessDNSNetworkRefusesFalseEvidenceLinks(t *testing.T) {
	tests := []struct {
		name string
		mutate func([]Event)
	}{
		{"cross-device-dns", func(e []Event) { e[1].DeviceID = "other" }},
		{"cross-device-network", func(e []Event) { e[2].DeviceID = "other" }},
		{"cross-boot-dns", func(e []Event) { e[1].BootID = "boot-b" }},
		{"cross-boot-network", func(e []Event) { e[2].BootID = "boot-b" }},
		{"missing-boot", func(e []Event) { e[0].BootID = "" }},
		{"cross-process-dns", func(e []Event) { e[1].ProcessGUID = "other" }},
		{"cross-process-network", func(e []Event) { e[2].ProcessGUID = "other" }},
		{"non-sysmon-process", func(e []Event) { e[0].Source = "unknown" }},
		{"missing-source-record", func(e []Event) { e[1].SourceRecordID = "" }},
		{"wrong-process-eid", func(e []Event) { e[0].SysmonEventID = 11 }},
		{"wrong-dns-eid", func(e []Event) { e[1].SysmonEventID = 3 }},
		{"wrong-network-eid", func(e []Event) { e[2].SysmonEventID = 22 }},
		{"missing-dns-answer", func(e []Event) { e[1].DNSAnswers = nil }},
		{"dns-IP-mismatch", func(e []Event) { e[2].DestinationIP = "1.1.1.1" }},
		{"private-IP", func(e []Event) { e[1].DNSAnswers = []string{"192.168.1.1"}; e[2].DestinationIP = "192.168.1.1" }},
		{"loopback", func(e []Event) { e[1].DNSAnswers = []string{"127.0.0.1"}; e[2].DestinationIP = "127.0.0.1" }},
		{"missing-network-port", func(e []Event) { e[2].DestinationPort = 0 }},
		{"process-too-old", func(e []Event) { e[0].Time = e[0].Time.Add(-7 * time.Minute) }},
		{"dns-after-connection", func(e []Event) { e[1].Time = e[2].Time.Add(time.Second) }},
		{"DNS-too-old", func(e []Event) { e[1].Time = e[0].Time.Add(-time.Second) }},
		{"wrong-platform", func(e []Event) { e[2].Platform = "linux" }},
		{"system-directory-binary", func(e []Event) { e[0].Image = `C:\Windows\System32\svchost.exe` }},
		{"non-EXE-binary", func(e []Event) { e[0].Image = `C:\Users\Alice\Downloads\script.ps1` }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := syntheticNetworkTrio()
			tc.mutate(e)
			if got := DetectSuspiciousProcessDNSNetwork(e); len(got) != 0 {
				t.Fatalf("false evidence correlation accepted: %+v", got)
			}
		})
	}
}

func TestProcessDNSNetworkDedupAndOrderIndependence(t *testing.T) {
	e := syntheticNetworkTrio()
	baseline := DetectSuspiciousProcessDNSNetwork(e)
	input := []Event{e[2], e[1], e[0], e[0], e[1], e[2]}
	got := DetectSuspiciousProcessDNSNetwork(input)
	if len(baseline) != 1 || len(got) != 1 ||
		baseline[0].ID != got[0].ID || got[0].ProcessCreateEventID != "proc-1" {
		t.Fatalf("duplicate or reversed input altered result: base=%+v reverse=%+v", baseline, got)
	}
	other := syntheticNetworkTrio()
	for i := range other {
		other[i].BootID = "boot-b"
	}
	got = DetectSuspiciousProcessDNSNetwork(append(input, other...))
	if len(got) != 2 || got[0].ID == got[1].ID {
		t.Fatalf("distinct boot records were collapsed: %+v", got)
	}
}

func TestProcessDNSNetworkIPv6AnswerAndAddress(t *testing.T) {
	e := syntheticNetworkTrio()
	e[2].DestinationIP = "2606:4700::1111"
	if got := DetectSuspiciousProcessDNSNetwork(e); len(got) != 1 {
		t.Fatalf("matching IPv6 DNS and connection not correlated: %+v", got)
	}
}

func TestTypedNetworkFieldsRejectMalformedIngest(t *testing.T) {
	cases := []struct {
		name string
		edit func(*Event)
	}{
		{"destination-IP", func(e *Event) { e.DestinationIP = "bad_ip" }},
		{"destination-zone", func(e *Event) { e.DestinationIP = "fe80::1%eth0" }},
		{"destination-port", func(e *Event) { e.DestinationPort = 65536 }},
		{"event-ID", func(e *Event) { e.SysmonEventID = 999 }},
		{"DNS-answer", func(e *Event) { e.DNSAnswers = []string{"not-an-ip"} }},
		{"too-many-DNS-answers", func(e *Event) { e.DNSAnswers = make([]string, 17) }},
		{"DNS-control", func(e *Event) { e.DNSQuery = "bad\nquery" }},
		{"DNS-long", func(e *Event) { e.DNSQuery = strings.Repeat("a", 254) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := NewStore()
			if _, err := s.CheckIn(Agent{ID: "win01", Platform: "windows"}); err != nil {
				t.Fatal(err)
			}
			event := syntheticNetworkTrio()[1]
			tc.edit(&event)
			if _, err := s.Ingest(event); err == nil {
				t.Fatalf("accepted malformed typed network evidence: %+v", event)
			}
			if len(s.Snapshot().Events) != 0 {
				t.Fatal("rejected malformed event was persisted")
			}
		})
	}
}

func TestMultiSignalDetectionHTTPContract(t *testing.T) {
	s := NewStore()
	if _, err := s.CheckIn(Agent{ID: "win01", Platform: "windows"}); err != nil {
		t.Fatal(err)
	}
	for _, e := range syntheticNetworkTrio() {
		if _, err := s.Ingest(e); err != nil {
			t.Fatalf("ingest failed: %v", err)
		}
	}
	h := (&Server{Store: s, Token: "lab-auth-token-123", WebDir: t.TempDir()}).Handler()
	req := httptest.NewRequest(http.MethodGet, "/api/detections", nil)
	out := httptest.NewRecorder()
	h.ServeHTTP(out, req)
	if out.Code != http.StatusUnauthorized {
		t.Fatalf("missing dev auth accepted: %d", out.Code)
	}
	req = httptest.NewRequest(http.MethodGet, "/api/detections", nil)
	req.Header.Set("Authorization", "Bearer lab-auth-token-123")
	out = httptest.NewRecorder()
	h.ServeHTTP(out, req)
	var got []Detection
	if out.Code != http.StatusOK || json.Unmarshal(out.Body.Bytes(), &got) != nil ||
		len(got) != 1 || got[0].RuleID != processDNSNetworkRuleID {
		t.Fatalf("API omitted new detection or returned invalid JSON: status=%d body=%s", out.Code, out.Body.String())
	}
}
