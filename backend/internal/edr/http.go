package edr

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Server struct {
	Store  *Store
	Token  string
	WebDir string
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "method not allowed", 405)
			return
		}
		reply(w, 200, map[string]string{"status": "ok", "mode": "development"})
	})
	mux.Handle("/", http.FileServer(http.Dir(s.WebDir)))
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if s.Token == "" {
			http.Error(w, "development token missing", 503)
			return
		}
		auth := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(auth), []byte(s.Token)) != 1 {
			http.Error(w, "unauthorized", 401)
			return
		}
		if r.Method == "POST" {
			r.Body = http.MaxBytesReader(w, r.Body, 128*1024)
		}
		switch {
		case r.URL.Path == "/api/agents" && r.Method == "GET":
			reply(w, 200, s.Store.Snapshot().Agents)
		case r.URL.Path == "/api/agents" && r.Method == "POST":
			var v Agent
			if !decode(w, r, &v) {
				return
			}
			a, err := s.Store.CheckIn(v)
			if fail(w, err) {
				return
			}
			reply(w, 200, a)
		case r.URL.Path == "/api/events" && r.Method == "GET":
			events := s.Store.Snapshot().Events
			if len(events) > 100 {
				events = events[len(events)-100:]
			}
			reply(w, 200, events)
		case r.URL.Path == "/api/detections" && r.Method == "GET":
			reply(w, 200, DetectSuspiciousDLLLoads(s.Store.Snapshot().Events))
		case r.URL.Path == "/api/events" && r.Method == "POST":
			var e Event
			if !decode(w, r, &e) {
				return
			}
			saved, err := s.Store.Ingest(e)
			if fail(w, err) {
				return
			}
			reply(w, 201, saved)
		case r.URL.Path == "/api/policies" && r.Method == "GET":
			reply(w, 200, s.Store.Snapshot().Policies)
		case r.URL.Path == "/api/policies" && r.Method == "POST":
			var v struct {
				Name     string `json:"name"`
				Platform string `json:"platform"`
				XML      string `json:"xml"`
			}
			if !decode(w, r, &v) {
				return
			}
			p, err := s.Store.CreatePolicy(v.Name, v.Platform, v.XML)
			if fail(w, err) {
				return
			}
			reply(w, 201, p)
		case r.URL.Path == "/api/assignments" && r.Method == "GET":
			reply(w, 200, s.Store.Snapshot().Assignments)
		case r.URL.Path == "/api/assignments" && r.Method == "POST":
			var a Assignment
			if !decode(w, r, &a) {
				return
			}
			if fail(w, s.Store.Assign(a)) {
				return
			}
			reply(w, 200, a)
		case r.URL.Path == "/api/scan-jobs" && r.Method == "GET":
			reply(w, 200, s.Store.ScanJobs())
		case r.URL.Path == "/api/scan-jobs" && r.Method == "POST":
			var request ScanRequest
			if !decode(w, r, &request) {
				return
			}
			job, err := s.Store.CreateScan(request, time.Now().UTC())
			if fail(w, err) {
				return
			}
			reply(w, 201, job)
		case strings.HasPrefix(r.URL.Path, "/api/agents/") && strings.HasSuffix(r.URL.Path, "/scan-lease") && r.Method == "POST":
			agentID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/agents/"), "/scan-lease")
			job, ok, err := s.Store.LeaseScan(agentID, time.Now().UTC())
			if fail(w, err) {
				return
			}
			if !ok {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			reply(w, 200, job)
		case strings.HasPrefix(r.URL.Path, "/api/scan-jobs/") && strings.HasSuffix(r.URL.Path, "/result") && r.Method == "POST":
			jobID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/scan-jobs/"), "/result")
			var result ScanCompletion
			if !decode(w, r, &result) {
				return
			}
			job, err := s.Store.CompleteScan(jobID, result, time.Now().UTC())
			if fail(w, err) {
				return
			}
			reply(w, 200, job)
		case r.URL.Path == "/api/overview" && r.Method == "GET":
			data := s.Store.Snapshot()
			online := 0
			for _, a := range data.Agents {
				if time.Since(a.LastSeen) < 5*time.Minute {
					online++
				}
			}
			reply(w, 200, map[string]int{"agents": len(data.Agents), "online": online, "events": len(data.Events), "policies": len(data.Policies), "assignments": len(data.Assignments)})
		case strings.HasPrefix(r.URL.Path, "/api/agents/") && r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/desired-policy"):
			agentID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/agents/"), "/desired-policy")
			if !validID(agentID) {
				http.Error(w, "invalid id", 400)
				return
			}
			p, ok := s.Store.Desired(agentID)
			if !ok {
				reply(w, 200, map[string]any{"assigned": false})
				return
			}
			reply(w, 200, map[string]any{"assigned": true, "policy": p})
		case strings.HasPrefix(r.URL.Path, "/api/agents/") && r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/policy-ack"):
			agentID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/agents/"), "/policy-ack")
			if !validID(agentID) {
				http.Error(w, "invalid id", 400)
				return
			}
			var a struct {
				PolicyID string `json:"policy_id"`
				Revision int    `json:"revision"`
				Success  bool   `json:"success"`
				Detail   string `json:"detail"`
			}
			if !decode(w, r, &a) {
				return
			}
			if fail(w, s.Store.Ack(agentID, a.PolicyID, a.Revision, a.Success, a.Detail)) {
				return
			}
			reply(w, 200, map[string]bool{"acknowledged": true})
		default:
			http.Error(w, "not found or method not allowed", 404)
		}
	})
	return logging(mux)
}
func decode(w http.ResponseWriter, r *http.Request, d any) bool {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		http.Error(w, "Content-Type must be application/json", 415)
		return false
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(d); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), 400)
		return false
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		http.Error(w, "only one JSON document allowed", 400)
		return false
	}
	return true
}
func reply(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}
func fail(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}
	http.Error(w, err.Error(), 400)
	return true
}
func logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; object-src 'none'")
		next.ServeHTTP(w, r)
		log.Printf("%s %s", r.Method, r.URL.Path)
	})
}
func WebPath() string {
	if p := os.Getenv("EDR_WEB_DIR"); p != "" {
		return p
	}
	return filepath.Join(".", "web")
}
