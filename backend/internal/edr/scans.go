package edr

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"
	"time"
)

// ScanJob is a control-plane request, NOT proof that the endpoint scanned anything.
// In this lab, all routes use the development bearer token. Production requires
// per-device mTLS identity, tenant authorization, signed commands, and persistence.
type ScanJob struct {
	ID              string     `json:"id"`
	RequestID       string     `json:"request_id"`
	AgentID         string     `json:"agent_id"`
	ScanType        string     `json:"scan_type"` // quick, full, path
	Path            string     `json:"path,omitempty"`
	Status          string     `json:"status"` // queued, leased, completed, failed, expired
	CreatedAt       time.Time  `json:"created_at"`
	ExpiresAt       time.Time  `json:"expires_at"`
	LeaseUntil      *time.Time `json:"lease_until,omitempty"`
	LeaseID         string     `json:"lease_id,omitempty"` // one-time delivery capability, rotated on retry
	CompletedAt     *time.Time `json:"completed_at,omitempty"`
	Engine          string     `json:"engine,omitempty"`
	EngineVersion   string     `json:"engine_version,omitempty"`
	DatabaseVersion string     `json:"database_version,omitempty"`
	Verdict         string     `json:"verdict,omitempty"` // clean_by_signature, malicious, suspicious, error, unscanned
	ThreatName      string     `json:"threat_name,omitempty"`
	Detail          string     `json:"detail,omitempty"`
}

type ScanRequest struct {
	RequestID string `json:"request_id"`
	AgentID   string `json:"agent_id"`
	ScanType  string `json:"scan_type"`
	Path      string `json:"path,omitempty"`
}

type ScanCompletion struct {
	AgentID         string `json:"agent_id"`
	LeaseID         string `json:"lease_id"`
	Verdict         string `json:"verdict"`
	Engine          string `json:"engine"`
	EngineVersion   string `json:"engine_version,omitempty"`
	DatabaseVersion string `json:"database_version,omitempty"`
	ThreatName      string `json:"threat_name,omitempty"`
	Detail          string `json:"detail,omitempty"`
}

var windowsDrivePath = regexp.MustCompile(`^[A-Za-z]:\\`)

func scanPathAllowed(platform, p string) bool {
	if len(p) > 512 || strings.ContainsAny(p, "\x00\r\n") {
		return false
	}
	if platform == "windows" {
		if !windowsDrivePath.MatchString(p) || strings.Contains(p, "/") {
			return false // disallow UNC/network paths and mixed separators for MVP
		}
		for _, segment := range strings.Split(p[3:], `\`) {
			if segment == ".." || segment == "." || segment == "" {
				return false
			}
		}
		return true
	}
	return strings.HasPrefix(p, "/") && p != "/" && path.Clean(p) == p
}

func (s *Store) CreateScan(req ScanRequest, now time.Time) (ScanJob, error) {
	if !validID(req.AgentID) || !validID(req.RequestID) {
		return ScanJob{}, errors.New("agent_id and request_id must be valid identifiers")
	}
	if req.ScanType != "quick" && req.ScanType != "full" && req.ScanType != "path" {
		return ScanJob{}, errors.New("unsupported scan_type")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var agent *Agent
	for i := range s.data.Agents {
		if s.data.Agents[i].ID == req.AgentID {
			agent = &s.data.Agents[i]
			break
		}
	}
	if agent == nil {
		return ScanJob{}, errors.New("unknown agent")
	}
	if req.ScanType == "path" {
		if !scanPathAllowed(agent.Platform, req.Path) {
			return ScanJob{}, errors.New("invalid local scan path for agent platform")
		}
	} else if req.Path != "" {
		return ScanJob{}, errors.New("path allowed only for path scans")
	}
	for _, prev := range s.scans {
		if prev.AgentID == req.AgentID && prev.RequestID == req.RequestID {
			if prev.ScanType != req.ScanType || prev.Path != req.Path {
				return ScanJob{}, errors.New("request_id reused with different parameters")
			}
			return prev, nil // retry-safe: no duplicate scan job
		}
	}
	key, err := id()
	if err != nil {
		return ScanJob{}, err
	}
	job := ScanJob{ID: key, AgentID: req.AgentID, RequestID: req.RequestID, ScanType: req.ScanType, Path: req.Path,
		Status: "queued", CreatedAt: now.UTC(), ExpiresAt: now.UTC().Add(30 * time.Minute)}
	s.scans = append(s.scans, job)
	return job, nil
}

func (s *Store) ScanJobs() []ScanJob {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]ScanJob, len(s.scans))
	copy(result, s.scans)
	for i := range result {
		result[i].LeaseID = ""
	}
	return result
}

// LeaseScan is explicitly scoped to one agent and returns at most one command.
// The in-memory lab queue is not crash-safe and cannot replace durable delivery.
func (s *Store) LeaseScan(agentID string, now time.Time) (ScanJob, bool, error) {
	if !validID(agentID) {
		return ScanJob{}, false, errors.New("invalid agent id")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	exists := false
	for _, agent := range s.data.Agents {
		if agent.ID == agentID {
			exists = true
			break
		}
	}
	if !exists {
		return ScanJob{}, false, errors.New("unknown agent")
	}
	for i := range s.scans {
		j := &s.scans[i]
		if j.AgentID != agentID || j.Status == "completed" || j.Status == "failed" || j.Status == "expired" {
			continue
		}
		if !now.Before(j.ExpiresAt) {
			j.Status = "expired"
			j.LeaseUntil = nil
			j.LeaseID = ""
			continue
		}
		if j.Status == "leased" && j.LeaseUntil != nil && now.Before(*j.LeaseUntil) {
			continue
		}
		leaseID, err := id()
		if err != nil {
			return ScanJob{}, false, err
		}
		until := now.UTC().Add(60 * time.Second)
		j.LeaseID = leaseID
		j.LeaseUntil = &until
		j.Status = "leased"
		return *j, true, nil
	}
	return ScanJob{}, false, nil
}

func (s *Store) CompleteScan(jobID string, req ScanCompletion, now time.Time) (ScanJob, error) {
	if !validID(jobID) || !validID(req.AgentID) || !validID(req.LeaseID) {
		return ScanJob{}, errors.New("invalid job or agent id")
	}
	if req.Engine != "clamav" {
		return ScanJob{}, errors.New("unsupported scan engine")
	}
	switch req.Verdict {
	case "clean_by_signature", "malicious", "suspicious", "error", "unscanned":
	default:
		return ScanJob{}, errors.New("invalid scan verdict")
	}
	if len(req.EngineVersion) > 96 || len(req.DatabaseVersion) > 96 || len(req.ThreatName) > 256 || len(req.Detail) > 1024 {
		return ScanJob{}, errors.New("scan result field too long")
	}
	if req.Verdict == "malicious" && strings.TrimSpace(req.ThreatName) == "" {
		return ScanJob{}, errors.New("malicious verdict requires threat_name")
	}
	if req.Verdict != "malicious" && req.ThreatName != "" {
		return ScanJob{}, errors.New("threat_name only valid for malicious verdict")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.scans {
		j := &s.scans[i]
		if j.ID != jobID {
			continue
		}
		if j.AgentID != req.AgentID {
			return ScanJob{}, errors.New("agent identity mismatch")
		}
		if j.LeaseID != req.LeaseID {
			return ScanJob{}, errors.New("scan lease identity mismatch")
		}
		// LAB CAPABILITY GATE: quick/full scan execution is not implemented.
		// A claimed successful verdict cannot establish that a scan occurred.
		// Remove only after real worker capability negotiation and QA evidence.
		if j.ScanType != "path" && req.Verdict != "unscanned" && req.Verdict != "error" {
			return ScanJob{}, errors.New("quick/full scan not implemented: cannot claim scanned verdict")
		}
		if j.Status == "completed" || j.Status == "failed" {
			if j.Verdict == req.Verdict && j.Engine == req.Engine && j.ThreatName == req.ThreatName && j.EngineVersion == req.EngineVersion && j.DatabaseVersion == req.DatabaseVersion && j.Detail == req.Detail {
				return *j, nil
			}
			return ScanJob{}, errors.New("conflicting scan result")
		}
		if j.Status != "leased" || j.LeaseUntil == nil || !now.Before(*j.LeaseUntil) || !now.Before(j.ExpiresAt) {
			return ScanJob{}, fmt.Errorf("scan job not leased or lease expired")
		}
		j.Engine, j.EngineVersion, j.DatabaseVersion = req.Engine, req.EngineVersion, req.DatabaseVersion
		j.Verdict, j.ThreatName, j.Detail = req.Verdict, req.ThreatName, req.Detail
		completed := now.UTC()
		j.CompletedAt = &completed
		j.LeaseUntil = nil
		j.Status = "completed"
		if req.Verdict == "error" || req.Verdict == "unscanned" {
			j.Status = "failed"
		}
		result := *j
		result.LeaseID = ""
		return result, nil
	}
	return ScanJob{}, errors.New("scan job not found")
}
