package edr

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDLLCreateIsNotDLLExecution(t *testing.T) {
	now := time.Now().UTC()
	creation := Event{ID: "create-1", Platform: "windows", DeviceID: "win-01", Type: "file_create", FilePath: `C:\Users\Alice\AppData\Local\Temp\plugin.dll`, Time: now}
	if got := DetectSuspiciousDLLLoads([]Event{creation}); len(got) != 0 {
		t.Fatalf("file creation alone yielded %d detections", len(got))
	}
}

func TestActualModuleLoadRequiredAndEnriched(t *testing.T) {
	now := time.Now().UTC()
	path := `C:\Users\Alice\AppData\Local\Temp\plugin.dll`
	creation := Event{ID: "create-1", Platform: "windows", DeviceID: "win-01", Type: "file_create", FilePath: path, Hash: "sha256sample", Time: now}
	load := Event{ID: "load-1", Platform: "windows", DeviceID: "win-01", Type: "module_load", FilePath: path, Image: `C:\Windows\System32\rundll32.exe`, ProcessGUID: "{one}", Hash: "sha256sample", Time: now.Add(time.Minute)}
	alerts := DetectSuspiciousDLLLoads([]Event{creation, load})
	if len(alerts) != 1 || alerts[0].LoadEventID != "load-1" || alerts[0].FileCreateEventID != "create-1" {
		t.Fatalf("expected a linked, actually loaded DLL detection: %+v", alerts)
	}
	if alerts[0].Confidence != "low" || alerts[0].Severity != "medium" {
		t.Fatalf("unsafe overconfident severity: %+v", alerts[0])
	}
}

func TestDLLLoadScopeAndDedup(t *testing.T) {
	now := time.Now().UTC()
	base := Event{ID: "load-1", Platform: "windows", DeviceID: "win-01", Type: "module_load", FilePath: `C:\Users\Alice\Downloads\demo.dll`, Image: `C:\Windows\System32\rundll32.exe`, ProcessGUID: "{one}", Time: now}
	otherDeviceCreate := Event{ID: "create-other", Platform: "windows", DeviceID: "win-02", Type: "file_create", FilePath: base.FilePath, Time: now.Add(-time.Minute)}
	alerts := DetectSuspiciousDLLLoads([]Event{otherDeviceCreate, base, base})
	if len(alerts) != 1 || alerts[0].FileCreateEventID != "" {
		t.Fatalf("duplicate load or cross-device linkage: %+v", alerts)
	}
	base.FilePath = `C:\Windows\System32\kernel32.dll`
	if got := DetectSuspiciousDLLLoads([]Event{base}); len(got) != 0 {
		t.Fatalf("normal system DLL unexpectedly matched: %+v", got)
	}
	base.Platform = "linux"
	base.FilePath = `/home/alice/Downloads/demo.dll`
	if got := DetectSuspiciousDLLLoads([]Event{base}); len(got) != 0 {
		t.Fatalf("windows-only rule matched Linux event: %+v", got)
	}
}

func TestDetectionHTTPDevAuth(t *testing.T) {
	store := NewStore()
	_, _ = store.CheckIn(Agent{ID: "win-01", Platform: "windows"})
	_, err := store.Ingest(Event{Platform: "windows", DeviceID: "win-01", Type: "module_load", Image: `C:\Windows\System32\rundll32.exe`, ProcessGUID: "{one}", FilePath: `C:\Users\Alice\Temp\demo.dll`})
	if err != nil {
		t.Fatal(err)
	}
	srv := (&Server{Store: store, Token: "0123456789abcdef", WebDir: t.TempDir()}).Handler()
	req := httptest.NewRequest("GET", "/api/detections", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated detections accessible: %d", rec.Code)
	}
	req = httptest.NewRequest("GET", "/api/detections", nil)
	req.Header.Set("Authorization", "Bearer 0123456789abcdef")
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("authorized status: %d", rec.Code)
	}
	var d []Detection
	if err := json.Unmarshal(rec.Body.Bytes(), &d); err != nil || len(d) != 1 {
		t.Fatalf("invalid detection output %v %s", err, rec.Body.String())
	}
}
