package edr

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestScanJobValidationAndIdempotency(t *testing.T) {
	s := NewStore()
	_, _ = s.CheckIn(Agent{ID: "win1", Platform: "windows"})
	_, _ = s.CheckIn(Agent{ID: "linux1", Platform: "linux"})
	now := time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC)
	reject := []ScanRequest{
		{AgentID: "unknown", RequestID: "req-1", ScanType: "quick"},
		{AgentID: "win1", RequestID: "bad/ID", ScanType: "quick"},
		{AgentID: "win1", RequestID: "req-2", ScanType: "execute"},
		{AgentID: "win1", RequestID: "req-3", ScanType: "quick", Path: `C:\test`},
		{AgentID: "win1", RequestID: "req-4", ScanType: "path", Path: `\\server\share`},
		{AgentID: "win1", RequestID: "req-5", ScanType: "path", Path: `C:\tmp\..\system`},
		{AgentID: "win1", RequestID: "req-6", ScanType: "path", Path: `C:\tmp\`},
		{AgentID: "linux1", RequestID: "req-7", ScanType: "path", Path: `../etc`},
		{AgentID: "linux1", RequestID: "req-8", ScanType: "path", Path: `/tmp/../etc`},
		{AgentID: "linux1", RequestID: "req-9", ScanType: "path", Path: `/`},
	}
	for _, r := range reject {
		if _, err := s.CreateScan(r, now); err == nil {
			t.Errorf("accepted invalid request: %+v", r)
		}
	}
	for _, r := range []ScanRequest{
		{AgentID: "win1", RequestID: "win-path", ScanType: "path", Path: `C:\Windows\System32`},
		{AgentID: "linux1", RequestID: "linux-path", ScanType: "path", Path: "/home/user"},
		{AgentID: "linux1", RequestID: "linux-quick", ScanType: "quick"},
	} {
		job, err := s.CreateScan(r, now)
		if err != nil {
			t.Fatalf("valid scan rejected: %+v: %v", r, err)
		}
		retry, err := s.CreateScan(r, now.Add(1*time.Minute))
		if err != nil || retry.ID != job.ID {
			t.Fatal("idempotent retry duplicated job")
		}
	}
	if len(s.ScanJobs()) != 3 {
		t.Fatalf("expected 3 unique jobs, got %d", len(s.ScanJobs()))
	}
	if _, err := s.CreateScan(ScanRequest{AgentID: "win1", RequestID: "win-path", ScanType: "full"}, now); err == nil {
		t.Fatal("accepted conflicting idempotency key")
	}
}

func TestScanLeaseCompleteAndExpiry(t *testing.T) {
	s := NewStore()
	_, _ = s.CheckIn(Agent{ID: "win1", Platform: "windows"})
	_, _ = s.CheckIn(Agent{ID: "win2", Platform: "windows"})
	now := time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC)
	job, err := s.CreateScan(ScanRequest{AgentID: "win1", RequestID: "abc", ScanType: "path", Path: `C:\Lab\sample.txt`}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := s.LeaseScan("win2", now); err != nil || ok {
		t.Fatal("other agent received scan")
	}
	if _, err = s.CompleteScan(job.ID, ScanCompletion{AgentID: "win1", Engine: "clamav", Verdict: "clean_by_signature"}, now); err == nil {
		t.Fatal("accepted completion before lease")
	}
	lease, ok, err := s.LeaseScan("win1", now)
	if err != nil || !ok || lease.ID != job.ID || lease.LeaseID == "" {
		t.Fatal("failed to lease job")
	}
	if _, ok, _ := s.LeaseScan("win1", now.Add(time.Second)); ok {
		t.Fatal("duplicate concurrent lease")
	}
	if _, err := s.CompleteScan(job.ID, ScanCompletion{AgentID: "win2", LeaseID: lease.LeaseID, Engine: "clamav", Verdict: "clean_by_signature"}, now); err == nil {
		t.Fatal("cross-agent result accepted")
	}
	if _, err := s.CompleteScan(job.ID, ScanCompletion{AgentID: "win1", LeaseID: lease.LeaseID, Engine: "clamav", Verdict: "malicious"}, now); err == nil {
		t.Fatal("unnamed malware accepted")
	}
	result := ScanCompletion{AgentID: "win1", LeaseID: lease.LeaseID, Engine: "clamav", EngineVersion: "test", DatabaseVersion: "test-db", Verdict: "malicious", ThreatName: "Eicar-Test-Signature"}
	complete, err := s.CompleteScan(job.ID, result, now.Add(2*time.Second))
	if err != nil || complete.Status != "completed" {
		t.Fatalf("completion rejected: %v", err)
	}
	if _, err := s.CompleteScan(job.ID, result, now.Add(time.Minute)); err != nil {
		t.Fatal("idempotent completion rejected")
	}
	if _, err := s.CompleteScan(job.ID, ScanCompletion{AgentID: "win1", LeaseID: lease.LeaseID, Engine: "clamav", Verdict: "clean_by_signature"}, now.Add(time.Minute)); err == nil {
		t.Fatal("changed verdict accepted")
	}
	if _, ok, _ := s.LeaseScan("win1", now.Add(time.Minute)); ok {
		t.Fatal("completed job leased again")
	}

	exp, _ := s.CreateScan(ScanRequest{AgentID: "win1", RequestID: "expiry", ScanType: "full"}, now)
	if _, ok, err := s.LeaseScan("win1", now.Add(31*time.Minute)); err != nil || ok {
		t.Fatalf("expired scan dispatched: %v", err)
	}
	if _, err := s.CompleteScan(exp.ID, result, now.Add(31*time.Minute)); err == nil {
		t.Fatal("expired job accepted result")
	}
}

func TestConcurrentScanLeasing(t *testing.T) {
	s := NewStore()
	_, _ = s.CheckIn(Agent{ID: "win1", Platform: "windows"})
	now := time.Now().UTC()
	_, err := s.CreateScan(ScanRequest{AgentID: "win1", RequestID: "first", ScanType: "quick"}, now)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan bool, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, ok, _ := s.LeaseScan("win1", now); results <- ok }()
	}
	wg.Wait()
	close(results)
	claimed := 0
	for r := range results {
		if r {
			claimed++
		}
	}
	if claimed != 1 {
		t.Fatalf("expected exactly one lease, got %d", claimed)
	}
}

func TestScanAPIContract(t *testing.T) {
	s := &Server{Store: NewStore(), Token: "abcdefghijklmnop", WebDir: t.TempDir()}
	h := s.Handler()
	call := func(method, path, content string, authorize bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(content))
		if authorize {
			req.Header.Set("Authorization", "Bearer abcdefghijklmnop")
		}
		if method == http.MethodPost {
			req.Header.Set("Content-Type", "application/json")
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	if r := call("POST", "/api/scan-jobs", `{"agent_id":"win1","request_id":"first","scan_type":"quick"}`, false); r.Code != 401 {
		t.Fatal("unauthenticated scan created")
	}
	if r := call("POST", "/api/agents", `{"id":"win1","platform":"windows"}`, true); r.Code != 200 {
		t.Fatalf("agent enrollment failed: %d", r.Code)
	}
	r := call("POST", "/api/scan-jobs", `{"agent_id":"win1","request_id":"first","scan_type":"path","path":"C:\\Lab\\sample.txt"}`, true)
	if r.Code != 201 {
		t.Fatalf("scan request failed: %d %s", r.Code, r.Body.String())
	}
	var job ScanJob
	if err := json.NewDecoder(bytes.NewReader(r.Body.Bytes())).Decode(&job); err != nil || job.ID == "" {
		t.Fatal("invalid scan response", err)
	}
	lease := call("POST", "/api/agents/win1/scan-lease", "{}", true)
	if lease.Code != 200 {
		t.Fatalf("lease: %d", lease.Code)
	}
	var leased ScanJob
	if err := json.Unmarshal(lease.Body.Bytes(), &leased); err != nil || leased.LeaseID == "" {
		t.Fatal("lease missing nonce", err)
	}
	resultBody, _ := json.Marshal(ScanCompletion{AgentID: "win1", LeaseID: leased.LeaseID, Engine: "clamav", Verdict: "clean_by_signature"})
	result := call("POST", "/api/scan-jobs/"+job.ID+"/result", string(resultBody), true)
	if result.Code != 200 {
		t.Fatalf("result rejected: %d: %s", result.Code, result.Body.String())
	}
	if r := call("POST", "/api/agents/win1/scan-lease", "{}", true); r.Code != 204 {
		t.Fatalf("expected 204 empty queue, got %d", r.Code)
	}
	if r := call("GET", "/api/scan-jobs", "", true); r.Code != 200 || !strings.Contains(r.Body.String(), `"completed"`) {
		t.Fatal("scan job missing in history")
	}
}
