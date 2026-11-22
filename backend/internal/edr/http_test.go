package edr

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEndpointAuth(t *testing.T) {
	s := &Server{Store: NewStore(), Token: "abcdefghijklmnop", WebDir: t.TempDir()}
	h := s.Handler()
	for _, c := range []struct {
		path, token string
		status      int
	}{
		{"/api/health", "", http.StatusOK},
		{"/api/agents", "", http.StatusUnauthorized},
		{"/api/agents", "wrong", http.StatusUnauthorized},
		{"/api/agents", "abcdefghijklmnop", http.StatusOK},
	} {
		req := httptest.NewRequest("GET", c.path, nil)
		if c.token != "" {
			req.Header.Set("Authorization", "Bearer "+c.token)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != c.status {
			t.Errorf("%s token=%q got %d want %d", c.path, c.token, rec.Code, c.status)
		}
	}
}

func TestJSONRejectsTrailingGarbage(t *testing.T) {
	s := &Server{Store: NewStore(), Token: "abcdefghijklmnop", WebDir: t.TempDir()}
	for _, input := range []string{`{"id":"a","platform":"windows"} {}`, `{"id":"a","platform":"windows"}garbage`} {
		req := httptest.NewRequest("POST", "/api/agents", strings.NewReader(input))
		req.Header.Set("Authorization", "Bearer abcdefghijklmnop")
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		if rec.Code != 400 {
			t.Errorf("accepted trailing garbage with status %d", rec.Code)
		}
	}
}
