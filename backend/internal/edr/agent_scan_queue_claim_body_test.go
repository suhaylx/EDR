package edr

import (
	"database/sql/driver"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// A legal io.Reader can produce no bytes and no error before later
// producing client data. A single Read is not an EOF check.
type delayedClaimBody struct {
	emptyReads int
	bytes      []byte
}

func (r *delayedClaimBody) Read(p []byte) (int, error) {
	if r.emptyReads > 0 {
		r.emptyReads--
		return 0, nil
	}
	if len(r.bytes) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.bytes)
	r.bytes = r.bytes[n:]
	return n, nil
}

// A claim must not even reach PostgreSQL if hidden request bytes were
// supplied after an initial empty read; the lease token must not be issued.
func TestAgentClaimRejectsDelayedRequestBodyBeforeDatabase(t *testing.T) {
	var databaseQueries atomic.Int32
	db := scanDB(t, func(query string, args []driver.NamedValue) (driver.Rows, error) {
		databaseQueries.Add(1)
		return &scanRows{
			columns: []string{"job_id", "scan_root", "attempt_count"},
			values: [][]driver.Value{{testUUID, "C:/Lab", int64(1)}},
		}, nil
	})
	handler := AgentScanQueueHandler(PostgresScanJobQueue{DB: db})
	identity := &AgentIdentity{TenantID: "tenantA", AgentID: "win01"}
	const path = "/agent/v1/tenants/tenantA/agents/win01/scan-jobs/claim"

	for _, tc := range []struct {
		name       string
		emptyReads int
		body       string
	}{
		{"delayed-one-byte", 1, "x"},
		{"delayed-tenant-override", 1, `{"tenant_id":"tenantB"}`},
		{"multiple-empty-reads", 3, `{}`},
		{"immediate-unexpected-body", 0, "x"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := scanRequest(http.MethodPost, path, "", identity)
			request.Body = io.NopCloser(&delayedClaimBody{
				emptyReads: tc.emptyReads,
				bytes:      []byte(tc.body),
			})
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("hidden claim payload got HTTP %d, want 400", response.Code)
			}
			if calls := databaseQueries.Load(); calls != 0 {
				t.Fatalf("untrusted claim body reached SQL %d times", calls)
			}
		})
	}

	// Several (0,nil) reads followed by real EOF are still a valid empty
	// claim. Preserve the existing successful authorized lease flow.
	request := scanRequest(http.MethodPost, path, "", identity)
	request.Body = io.NopCloser(&delayedClaimBody{emptyReads: 3})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("valid empty claim got HTTP %d, want 200: %s",
			response.Code, response.Body.String())
	}
	if calls := databaseQueries.Load(); calls != 1 {
		t.Fatalf("expected one authorized SQL claim, got %d", calls)
	}
}
