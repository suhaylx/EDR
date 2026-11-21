package edr

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Day 2: shared-token lab authentication must not accept a naked token.
// This verifies the actual Server.Handler and representative read/write
// paths; production mTLS operator/tenant authorization is a separate server.
func TestQAThreeDayLabAPIRequiresBearerScheme(t *testing.T) {
	const token = "QA_DEVELOPMENT_ONLY_TOKEN"
	store := NewStore()
	handler := (&Server{Store: store, Token: token, WebDir: "."}).Handler()
	routes := []string{
		"/api/agents",
		"/api/overview?days=7",
		"/api/events",
		"/api/detections",
		"/api/policy-metadata",
		"/api/policies",
		"/api/assignments",
		"/api/scan-job-metadata",
		"/api/scan-jobs",
	}
	badHeaders := []string{
		"", token, "Basic " + token, "bearer " + token,
		"Token " + token, "Bearer" + token,
		"Bearer  " + token, "Bearer " + token + "suffix",
	}
	for _, route := range routes {
		for _, header := range badHeaders {
			t.Run(route+"_"+header, func(t *testing.T) {
				req := httptest.NewRequest(http.MethodGet, route, nil)
				if header != "" {
					req.Header.Set("Authorization", header)
				}
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, req)
				if response.Code != http.StatusUnauthorized {
					t.Fatalf("route %s accepted non-Bearer token %q: HTTP %d", route, header, response.Code)
				}
				if response.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("denied API response was cacheable")
				}
			})
		}
		t.Run(route+"_valid", func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, route, nil)
			req.Header.Set("Authorization", "Bearer "+token)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, req)
			if response.Code != http.StatusOK {
				t.Fatalf("valid Bearer token rejected at %s: HTTP %d body=%s", route, response.Code, response.Body.String())
			}
		})
	}
}

func TestQAThreeDayBareTokenCannotMutatePolicy(t *testing.T) {
	store := NewStore()
	const token = "QA_DEVELOPMENT_ONLY_TOKEN"
	handler := (&Server{Store: store, Token: token, WebDir: "."}).Handler()
	for _, header := range []string{token, "Basic " + token} {
		req := httptest.NewRequest(http.MethodPost, "/api/policies",
			strings.NewReader(`{"name":"Bad policy","platform":"windows","xml":"<Sysmon/>"}`))
		req.Header.Set("Authorization", header)
		req.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("non-Bearer POST should be denied: HTTP %d", response.Code)
		}
	}
	if len(store.Snapshot().Policies) != 0 {
		t.Fatal("unauthorized request mutated policy catalog")
	}
}

func TestQAThreeDayMetadataRoutesRejectUnauthenticatedRequestsBeforeData(t *testing.T) {
	const token = "QA_DEVELOPMENT_ONLY_TOKEN"
	handler := (&Server{Store: NewStore(), Token: token, WebDir: "."}).Handler()
	for _, route := range []string{"/api/policy-metadata", "/api/scan-job-metadata"} {
		req := httptest.NewRequest(http.MethodGet, route, nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("no token at %s: HTTP %d", route, response.Code)
		}
		if strings.Contains(response.Body.String(), "signature_reported") ||
			strings.Contains(response.Body.String(), "sha256") {
			t.Fatalf("metadata leak before authentication at %s", route)
		}
	}
}
