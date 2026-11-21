package edr

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestProcessInvestigationFullLineageAndObservedEvidence(t *testing.T) {
	now := time.Date(2026, 11, 21, 8, 0, 0, 0, time.UTC)
	events := []Event{
		{ID: "p1", DeviceID: "win-01", Platform: "windows", ProcessGUID: "A", Type: "process_create", Image: "explorer.exe", Time: now},
		{ID: "p2", DeviceID: "win-01", Platform: "windows", ProcessGUID: "B", ParentProcessGUID: "A", Type: "process_create", Image: "powershell.exe", Time: now.Add(time.Minute)},
		{ID: "p3", DeviceID: "win-01", Platform: "windows", ProcessGUID: "C", ParentProcessGUID: "B", Type: "process_create", Image: "rundll32.exe", Time: now.Add(2 * time.Minute)},
		{ID: "file", DeviceID: "win-01", Platform: "windows", ProcessGUID: "B", Type: "file_create", FilePath: `C:\Users\x\Temp\abc.dll`, Time: now.Add(3 * time.Minute)},
		{ID: "load", DeviceID: "win-01", Platform: "windows", ProcessGUID: "C", Type: "module_load", FilePath: `C:\Users\x\Temp\abc.dll`, Image: "rundll32.exe", Time: now.Add(4 * time.Minute)},
		{ID: "dns", DeviceID: "win-01", Platform: "windows", ProcessGUID: "C", Type: "dns_query", Detail: "example.test", Time: now.Add(5 * time.Minute)},
		{ID: "network", DeviceID: "win-01", Platform: "windows", ProcessGUID: "C", Type: "network_connect", Detail: "203.0.113.7:443", Time: now.Add(6 * time.Minute)},
		{ID: "other", DeviceID: "win-02", Platform: "windows", ProcessGUID: "C", Type: "network_connect", Detail: "sensitive-other-device", Time: now},
	}
	det := Detection{ID: "det-01", DeviceID: "win-01", ProcessGUID: "C", RuleID: "TEST-DLL", Category: "suspicious_dll_load", LoadEventID: "load", FileCreateEventID: "file", Severity: "medium", Confidence: "low"}
	g, err := BuildProcessInvestigation(events, []Detection{det}, "win-01", "", "det-01", 3, 100)
	if err != nil {
		t.Fatal(err)
	}
	if g.SeedProcessGUID != "C" || g.SeedDetectionID != "det-01" {
		t.Fatal("wrong seed", g)
	}
	procs := map[string]bool{}
	etypes := map[string]bool{}
	files := 0
	detections := 0
	for _, n := range g.Nodes {
		if n.Kind == "process" {
			procs[n.ProcessGUID] = true
		}
		if n.Kind == "event" {
			etypes[n.EventType] = true
		}
		if n.Kind == "file" {
			files++
		}
		if n.Kind == "detection" {
			detections++
		}
	}
	if len(procs) != 3 || !procs["A"] || !procs["B"] || !procs["C"] || files != 1 || detections != 1 {
		t.Fatalf("missing process evidence procs=%v file=%d detections=%d", procs, files, detections)
	}
	if !etypes["dns_query"] || !etypes["network_connect"] || !etypes["module_load"] || !etypes["file_create"] {
		t.Fatalf("missing evidence %v", etypes)
	}
	for _, n := range g.Nodes {
		if strings.Contains(n.Detail, "sensitive-other-device") {
			t.Fatalf("cross-device event leaked: %+v", n)
		}
	}
	observedParentEdges := 0
	for _, e := range g.Edges {
		if e.Relation == "parent_process" && e.Provenance == "observed" {
			observedParentEdges++
		}
	}
	if observedParentEdges != 2 {
		t.Fatalf("process lineage not sourced by EID1; observed edges=%d", observedParentEdges)
	}
}

func TestProcessInvestigationDoesNotInventParentOrInfection(t *testing.T) {
	g, err := BuildProcessInvestigation([]Event{{ID: "only", DeviceID: "win-01", ProcessGUID: "child", ParentProcessGUID: "unknown-parent", Type: "dns_query", Detail: "query"}}, nil, "win-01", "child", "", 2, 40)
	if err != nil {
		t.Fatal(err)
	}
	parentReferenced := false
	weakEdge := false
	for _, n := range g.Nodes {
		if n.Kind == "process" && n.ProcessGUID == "unknown-parent" && n.Status == "referenced" {
			parentReferenced = true
		}
		if strings.Contains(strings.ToLower(n.Label), "infected") {
			t.Fatal("invented infection")
		}
	}
	for _, e := range g.Edges {
		if e.Relation == "parent_process" && e.Provenance == "reported" {
			weakEdge = true
		}
	}
	if !parentReferenced || !weakEdge {
		t.Fatal("weak parent relationship must not be labelled confirmed")
	}
}

func TestProcessInvestigationValidationAndLimits(t *testing.T) {
	evs := []Event{{ID: "x", DeviceID: "win-01", ProcessGUID: "P", Type: "process_create"}, {ID: "y", DeviceID: "win-01", ProcessGUID: "P", Type: "file_create", FilePath: `C:\Users\demo\a.exe`}}
	cases := []struct {
		device, process, det string
		depth, max           int
		wantErr              error
	}{
		{"win-01", "P", "no-detection", 2, 20, nil}, // two selectors invalid
		{"win-01", "unknown", "", 2, 20, ErrInvestigationNotFound},
		{"win-02", "P", "", 2, 20, ErrInvestigationNotFound},
		{"win-01", "P", "", 0, 20, nil},
		{"bad/device", "P", "", 2, 20, nil},
	}
	for _, tc := range cases {
		_, err := BuildProcessInvestigation(evs, nil, tc.device, tc.process, tc.det, tc.depth, tc.max)
		if err == nil {
			t.Fatalf("missing rejection %+v", tc)
		}
		if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
			t.Fatalf("wrong error %v", err)
		}
	}
	g, err := BuildProcessInvestigation(evs, nil, "win-01", "P", "", 2, 1)
	if err != nil || !g.Truncated || len(g.Nodes) != 1 {
		t.Fatalf("missing truncation g=%+v err=%v", g, err)
	}
}

func TestInvestigationHTTPAuthAndSelectors(t *testing.T) {
	store := NewStore()
	if _, err := store.CheckIn(Agent{ID: "win-01", Platform: "windows"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Ingest(Event{DeviceID: "win-01", Platform: "windows", ProcessGUID: "P", Type: "process_create"}); err != nil {
		t.Fatal(err)
	}
	handler := (&Server{Store: store, Token: "0123456789abcdef", WebDir: t.TempDir()}).Handler()
	for _, tc := range []struct {
		query, auth string
		status      int
	}{
		{"/api/investigations?device_id=win-01&process_guid=P", "", 401},
		{"/api/investigations?device_id=win-01&process_guid=P", "0123456789abcdef", 200},
		{"/api/investigations?device_id=win-02&process_guid=P", "0123456789abcdef", 404},
		{"/api/investigations?device_id=win-01&process_guid=P&depth=7", "0123456789abcdef", 400},
		{"/api/investigations?device_id=win-01", "0123456789abcdef", 400},
	} {
		req := httptest.NewRequest("GET", tc.query, nil)
		if tc.auth != "" {
			req.Header.Set("Authorization", "Bearer "+tc.auth)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != tc.status {
			t.Errorf("%q status=%d want=%d body=%s", tc.query, rec.Code, tc.status, rec.Body.String())
		}
		if tc.status == 200 {
			var g InvestigationGraph
			if err := json.Unmarshal(rec.Body.Bytes(), &g); err != nil || g.SeedProcessGUID != "P" {
				t.Fatalf("graph decode err=%v g=%+v", err, g)
			}
		}
	}
}
