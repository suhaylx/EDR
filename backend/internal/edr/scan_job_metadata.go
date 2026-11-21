package edr

import "time"

// ScanJobReview is a display-only projection for the shared-token Go lab
// analyst UI. Never serialize scan paths, request IDs, lease capabilities,
// signature names or untrusted worker details to the browser.
// A reported_signature flag is metadata, not a ClamAV attestation.
type ScanJobReview struct {
	ID                string     `json:"id"`
	AgentID           string     `json:"agent_id"`
	ScanType          string     `json:"scan_type"`
	Status            string     `json:"status"`
	CreatedAt         time.Time  `json:"created_at"`
	ExpiresAt         time.Time  `json:"expires_at"`
	LeaseUntil        *time.Time `json:"lease_until,omitempty"`
	CompletedAt       *time.Time `json:"completed_at,omitempty"`
	Engine            string     `json:"engine,omitempty"`
	EngineVersion     string     `json:"engine_version,omitempty"`
	DatabaseVersion   string     `json:"database_version,omitempty"`
	Verdict           string     `json:"verdict,omitempty"`
	SignatureReported bool       `json:"signature_reported"`
}

func scanJobReviewMetadata(jobs []ScanJob) []ScanJobReview {
	result := make([]ScanJobReview, 0, len(jobs))
	for _, j := range jobs {
		result = append(result, ScanJobReview{
			ID: j.ID, AgentID: j.AgentID, ScanType: j.ScanType, Status: j.Status,
			CreatedAt: j.CreatedAt, ExpiresAt: j.ExpiresAt, LeaseUntil: j.LeaseUntil,
			CompletedAt: j.CompletedAt, Engine: j.Engine, EngineVersion: j.EngineVersion,
			DatabaseVersion: j.DatabaseVersion, Verdict: j.Verdict,
			SignatureReported: j.ThreatName != "",
		})
	}
	return result
}
