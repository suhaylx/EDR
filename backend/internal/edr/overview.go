package edr

import (
	"sort"
	"time"
)

const OnlineHeartbeatThreshold = 5 * time.Minute

type EndpointActivity struct {
	ID              string    `json:"id"`
	Platform        string    `json:"platform"`
	Group           string    `json:"group"`
	LastSeen        time.Time `json:"last_seen"`
	Status          string    `json:"status"` // online, offline, unknown
	InactiveSeconds int64     `json:"inactive_seconds"`
	InactiveDays    float64   `json:"inactive_days"`
	Events          int       `json:"events"`
	Alerts          int       `json:"alerts"`
	ReportedHealth  string    `json:"reported_health"`
	AppliedPolicyID string    `json:"applied_policy_id,omitempty"`
	AppliedRevision int       `json:"applied_revision,omitempty"`
	LastPolicyError string    `json:"last_policy_error,omitempty"`
}

type SeverityBucket struct {
	Severity string `json:"severity"`
	Count    int    `json:"count"`
}

type DailyAlertCount struct {
	Day   string `json:"day"` // UTC calendar day
	Count int    `json:"count"`
}

type RuleHitCount struct {
	RuleID   string `json:"rule_id"`
	Severity string `json:"severity"`
	Count    int    `json:"count"`
}

type PolicyCoverage struct {
	PolicyID   string `json:"policy_id"`
	PolicyName string `json:"policy_name"`
	Endpoints  int    `json:"endpoints"`
}

type ScanHealthSummary struct {
	Queued int `json:"queued"`
	Leased int `json:"leased"`
	Failed int `json:"failed"`
	Done   int `json:"completed"`
}

type SOCOverview struct {
	GeneratedAt         time.Time          `json:"generated_at"`
	WindowDays          int                `json:"window_days"`
	DataSource          string             `json:"data_source"`
	HeartbeatTTLSeconds int64              `json:"heartbeat_ttl_seconds"`
	Agents              int                `json:"agents"`
	Online              int                `json:"online"`
	Offline             int                `json:"offline"`
	Unknown             int                `json:"unknown"`
	Events              int                `json:"events"` // retained events in window
	Policies            int                `json:"policies"`
	Assignments         int                `json:"assignments"`
	Alerts              int                `json:"alerts"`
	HighRiskAlerts      int                `json:"high_risk_alerts"`
	PolicyErrors        int                `json:"policy_errors"`
	Severity            []SeverityBucket   `json:"severity"`
	AlertTrend          []DailyAlertCount  `json:"alert_trend"`
	TopRules            []RuleHitCount     `json:"top_rules"`
	PolicyCoverage      []PolicyCoverage   `json:"policy_coverage"`
	MostActive          []EndpointActivity `json:"most_active"`
	InactiveMachines    []EndpointActivity `json:"inactive_machines"`
	Endpoints           []EndpointActivity `json:"endpoints"`
	Scans               ScanHealthSummary  `json:"scans"`
	Unavailable         []string           `json:"unavailable"`
}

// BuildSOCOverview computes truthful, scoped lab telemetry summaries.
// An agent is online ONLY when a server-received heartbeat is recent; the
// client supplied 'health' string is not used to determine connectivity.
// Data is limited to the in-memory event/scan retention and untrusted lab
// collection; these counters are not historical fleet-wide security metrics.
func BuildSOCOverview(data Snapshot, scans []ScanJob, now time.Time, days int) SOCOverview {
	if days != 1 && days != 7 && days != 30 {
		days = 7
	}
	now = now.UTC()
	// Use the first UTC calendar midnight shown in the chart for all KPI windows.
	// A rolling N*24h cutoff wrongly includes a day absent from the chart.
	startDay := now.Truncate(24*time.Hour).AddDate(0, 0, -(days - 1))
	since := startDay
	result := SOCOverview{
		GeneratedAt: now, WindowDays: days,
		DataSource:          "development_in_memory_retained_telemetry",
		HeartbeatTTLSeconds: int64(OnlineHeartbeatThreshold.Seconds()),
		Agents:              len(data.Agents), Policies: len(data.Policies), Assignments: len(data.Assignments),
		Endpoints: []EndpointActivity{}, InactiveMachines: []EndpointActivity{}, MostActive: []EndpointActivity{},
		TopRules: []RuleHitCount{}, PolicyCoverage: []PolicyCoverage{}, AlertTrend: []DailyAlertCount{},
		Severity:    []SeverityBucket{},
		Unavailable: []string{"real_endpoint_scan_attestation", "signature_database_freshness", "sysmon_collection_loss", "active_incident_sla", "tenant_isolation", "tamper_protection", "false_positive_rate"},
	}
	index := make(map[string]int, len(data.Agents))
	policyNames := make(map[string]string, len(data.Policies))
	for _, policy := range data.Policies {
		policyNames[policy.ID] = policy.Name
	}
	policyUses := make(map[string]int)
	for _, a := range data.Agents {
		endpoint := EndpointActivity{
			ID: a.ID, Platform: a.Platform, Group: a.Group, LastSeen: a.LastSeen,
			ReportedHealth: a.Health, AppliedPolicyID: a.AppliedPolicyID, AppliedRevision: a.AppliedRevision,
			LastPolicyError: a.LastPolicyError,
		}
		switch {
		case a.LastSeen.IsZero() || a.LastSeen.After(now):
			endpoint.Status = "unknown"
			result.Unknown++
		case now.Sub(a.LastSeen) <= OnlineHeartbeatThreshold:
			endpoint.Status = "online"
			result.Online++
		default:
			endpoint.Status = "offline"
			elapsed := now.Sub(a.LastSeen)
			endpoint.InactiveSeconds = int64(elapsed.Seconds())
			endpoint.InactiveDays = float64(endpoint.InactiveSeconds) / 86400
			result.Offline++
		}
		if endpoint.LastPolicyError != "" {
			result.PolicyErrors++
		}
		if endpoint.AppliedPolicyID != "" {
			policyUses[endpoint.AppliedPolicyID]++
		}
		index[a.ID] = len(result.Endpoints)
		result.Endpoints = append(result.Endpoints, endpoint)
	}
	for _, ev := range data.Events {
		if ev.Time.Before(since) || ev.Time.After(now) {
			continue
		}
		result.Events++
		if j, ok := index[ev.DeviceID]; ok {
			result.Endpoints[j].Events++
		}
	}
	all := DetectSuspiciousDLLLoads(data.Events)
	severity := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
	type hit struct {
		severity string
		count    int
	}
	rules := map[string]hit{}
	daysMap := map[string]int{}
	for _, det := range all {
		if det.ObservedAt.Before(since) || det.ObservedAt.After(now) {
			continue
		}
		result.Alerts++
		level := det.Severity
		if _, ok := severity[level]; !ok {
			level = "informational"
		}
		severity[level]++
		if level == "critical" || level == "high" {
			result.HighRiskAlerts++
		}
		if j, ok := index[det.DeviceID]; ok {
			result.Endpoints[j].Alerts++
		}
		d := det.ObservedAt.UTC().Format("2006-01-02")
		daysMap[d]++
		h := rules[det.RuleID]
		h.count++
		h.severity = level
		rules[det.RuleID] = h
	}
	for _, k := range []string{"critical", "high", "medium", "low", "informational"} {
		result.Severity = append(result.Severity, SeverityBucket{Severity: k, Count: severity[k]})
	}
	for n := 0; n < days; n++ {
		day := startDay.AddDate(0, 0, n).Format("2006-01-02")
		result.AlertTrend = append(result.AlertTrend, DailyAlertCount{Day: day, Count: daysMap[day]})
	}
	for ruleID, h := range rules {
		result.TopRules = append(result.TopRules, RuleHitCount{RuleID: ruleID, Severity: h.severity, Count: h.count})
	}
	sort.Slice(result.TopRules, func(i, j int) bool {
		if result.TopRules[i].Count != result.TopRules[j].Count {
			return result.TopRules[i].Count > result.TopRules[j].Count
		}
		return result.TopRules[i].RuleID < result.TopRules[j].RuleID
	})
	if len(result.TopRules) > 10 {
		result.TopRules = result.TopRules[:10]
	}
	for pid, count := range policyUses {
		name := policyNames[pid]
		if name == "" {
			name = "Unknown policy"
		}
		result.PolicyCoverage = append(result.PolicyCoverage, PolicyCoverage{PolicyID: pid, PolicyName: name, Endpoints: count})
	}
	sort.Slice(result.PolicyCoverage, func(i, j int) bool {
		if result.PolicyCoverage[i].Endpoints != result.PolicyCoverage[j].Endpoints {
			return result.PolicyCoverage[i].Endpoints > result.PolicyCoverage[j].Endpoints
		}
		return result.PolicyCoverage[i].PolicyID < result.PolicyCoverage[j].PolicyID
	})
	// The most active machines are ranked by retained event volume, NOT CPU,
	// network throughput or host risk. Offline endpoints may have old events.
	result.MostActive = append(result.MostActive, result.Endpoints...)
	sort.Slice(result.MostActive, func(i, j int) bool {
		a, b := result.MostActive[i], result.MostActive[j]
		if a.Events != b.Events {
			return a.Events > b.Events
		}
		if a.Alerts != b.Alerts {
			return a.Alerts > b.Alerts
		}
		return a.ID < b.ID
	})
	if len(result.MostActive) > 10 {
		result.MostActive = result.MostActive[:10]
	}
	for _, endpoint := range result.Endpoints {
		if endpoint.Status != "online" {
			result.InactiveMachines = append(result.InactiveMachines, endpoint)
		}
	}
	// All offline or unknown devices are shown, oldest heartbeat first.
	// A zero timestamp is unknown, not 'offline for 50 years'.
	sort.Slice(result.InactiveMachines, func(i, j int) bool {
		a, b := result.InactiveMachines[i], result.InactiveMachines[j]
		if a.Status != b.Status {
			return a.Status == "offline"
		}
		if a.InactiveSeconds != b.InactiveSeconds {
			return a.InactiveSeconds > b.InactiveSeconds
		}
		return a.ID < b.ID
	})
	for _, scan := range scans {
		if scan.CreatedAt.Before(since) || scan.CreatedAt.After(now) {
			continue
		}
		switch scan.Status {
		case "queued":
			result.Scans.Queued++
		case "leased":
			result.Scans.Leased++
		case "completed":
			result.Scans.Done++
		case "failed", "expired":
			result.Scans.Failed++
		}
	}
	return result
}
