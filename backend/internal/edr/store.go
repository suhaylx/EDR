package edr

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

type Agent struct {
	ID              string    `json:"id"`
	Platform        string    `json:"platform"`
	Group           string    `json:"group"`
	LastSeen        time.Time `json:"last_seen"`
	Health          string    `json:"health"`
	AppliedPolicyID string    `json:"applied_policy_id,omitempty"`
	AppliedRevision int       `json:"applied_revision,omitempty"`
	LastPolicyError string    `json:"last_policy_error,omitempty"`
}
type Policy struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Platform  string    `json:"platform"`
	Revision  int       `json:"revision"`
	XML       string    `json:"xml"`
	SHA256    string    `json:"sha256"`
	CreatedAt time.Time `json:"created_at"`
}
type Assignment struct {
	TargetType string `json:"target_type"`
	TargetID   string `json:"target_id"`
	Platform   string `json:"platform"`
	PolicyID   string `json:"policy_id"`
}
type Event struct {
	ID                string    `json:"id"`
	DeviceID          string    `json:"device_id"`
	Platform          string    `json:"platform"`
	Source            string    `json:"source"`
	// Sender-reported event-log provider and channel, never a verified OS assertion.
	SourceProvider    string    `json:"source_provider,omitempty"`
	SourceChannel     string    `json:"source_channel,omitempty"`
	// Sysmon numerical event ID, reported by the lab agent (not authenticated).
	SourceEventID     uint32    `json:"source_event_id,omitempty"`
	// Bounded, explicitly allowlisted non-secret source metadata.
	SourceFields      map[string]string `json:"source_fields,omitempty"`
	Type              string    `json:"type"`
	Time              time.Time `json:"time"`
	ReceivedAt        time.Time `json:"received_at"`
	TimeOrigin        string    `json:"time_origin"`
	// A sender-reported source record identifier; not an authenticated Sysmon proof.
	SourceRecordID    string    `json:"source_record_id,omitempty"`
	// Sender-reported boot/session marker, not cryptographically authenticated.
	BootID            string    `json:"boot_id,omitempty"`
	ProcessGUID       string    `json:"process_guid,omitempty"`
	ParentProcessGUID string    `json:"parent_process_guid,omitempty"`
	Image             string    `json:"image,omitempty"`
	FilePath          string    `json:"file_path,omitempty"`
	Hash              string    `json:"sha256,omitempty"`
	Detail            string    `json:"detail,omitempty"`
}
type Snapshot struct {
	Agents      []Agent      `json:"agents"`
	Policies    []Policy     `json:"policies"`
	Assignments []Assignment `json:"assignments"`
	Events      []Event      `json:"events"`
}
type Store struct {
	mu    sync.RWMutex
	data  Snapshot
	scans []ScanJob
}

func NewStore() *Store {
	return &Store{data: Snapshot{Agents: []Agent{}, Policies: []Policy{}, Assignments: []Assignment{}, Events: []Event{}}}
}
func clone[T any](a T) T {
	b, _ := json.Marshal(a)
	var result T
	_ = json.Unmarshal(b, &result)
	return result
}
func (s *Store) Snapshot() Snapshot { s.mu.RLock(); defer s.mu.RUnlock(); return clone(s.data) }
func (s *Store) CheckIn(a Agent) (Agent, error) {
	if !validID(a.ID) {
		return Agent{}, errors.New("invalid agent id")
	}
	if !validPlatform(a.Platform) {
		return Agent{}, errors.New("unsupported platform")
	}
	if len(a.Group) > 64 || strings.ContainsAny(a.Group, "/\\\x00") {
		return Agent{}, errors.New("invalid group")
	}
	if a.Group == "" {
		a.Group = "default"
	}
	a.LastSeen = time.Now().UTC()
	if a.Health == "" {
		a.Health = "online"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, old := range s.data.Agents {
		if old.ID == a.ID {
			if old.Platform != a.Platform {
				return Agent{}, errors.New("agent platform cannot change")
			}
			a.AppliedPolicyID = old.AppliedPolicyID
			a.AppliedRevision = old.AppliedRevision
			a.LastPolicyError = old.LastPolicyError
			s.data.Agents[i] = a
			return a, nil
		}
	}
	s.data.Agents = append(s.data.Agents, a)
	return a, nil
}
func validID(v string) bool {
	if len(v) < 1 || len(v) > 96 {
		return false
	}
	for _, c := range v {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}
func validPlatform(v string) bool { return v == "windows" || v == "linux" }
func validateXML(raw string) error {
	if len(raw) == 0 || len(raw) > 64*1024 {
		return errors.New("XML must be between 1 and 65536 bytes")
	}
	upper := strings.ToUpper(raw)
	if strings.Contains(upper, "<!DOCTYPE") || strings.Contains(upper, "<!ENTITY") {
		return errors.New("XML entities/DTDs prohibited")
	}
	d := xml.NewDecoder(strings.NewReader(raw))
	d.Strict = true
	depth := 0
	root := ""
	hasFilter := false
	for {
		token, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("invalid XML: %w", err)
		}
		switch t := token.(type) {
		case xml.StartElement:
			depth++
			if depth > 32 {
				return errors.New("XML too deeply nested")
			}
			if depth == 1 {
				root = t.Name.Local
				if root != "Sysmon" {
					return errors.New("root must be Sysmon")
				}
			}
			if t.Name.Local == "EventFiltering" {
				hasFilter = true
			}
		case xml.EndElement:
			depth--
		}
	}
	if depth != 0 || root != "Sysmon" || !hasFilter {
		return errors.New("Sysmon XML requires EventFiltering")
	}
	return nil
}
func id() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
func (s *Store) CreatePolicy(name, platform, raw string) (Policy, error) {
	if len(strings.TrimSpace(name)) < 2 || len(name) > 96 {
		return Policy{}, errors.New("policy name must be 2..96 chars")
	}
	if !validPlatform(platform) {
		return Policy{}, errors.New("unsupported platform")
	}
	if err := validateXML(raw); err != nil {
		return Policy{}, err
	}
	newid, err := id()
	if err != nil {
		return Policy{}, err
	}
	sum := sha256.Sum256([]byte(raw))
	p := Policy{ID: newid, Name: strings.TrimSpace(name), Platform: platform, XML: raw, SHA256: hex.EncodeToString(sum[:]), CreatedAt: time.Now().UTC()}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, old := range s.data.Policies {
		if old.Name == p.Name && old.Platform == p.Platform && old.Revision >= p.Revision {
			p.Revision = old.Revision + 1
		}
	}
	if p.Revision == 0 {
		p.Revision = 1
	}
	s.data.Policies = append(s.data.Policies, p)
	return p, nil
}
func (s *Store) findPolicy(id string) (Policy, bool) {
	for _, p := range s.data.Policies {
		if p.ID == id {
			return p, true
		}
	}
	return Policy{}, false
}
func (s *Store) Assign(a Assignment) error {
	if a.TargetType != "agent" && a.TargetType != "group" && a.TargetType != "default" {
		return errors.New("target_type must be agent, group or default")
	}
	if a.TargetType == "default" {
		a.TargetID = "*"
	} else if !validID(a.TargetID) {
		return errors.New("invalid target_id")
	}
	if !validPlatform(a.Platform) {
		return errors.New("invalid platform")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.findPolicy(a.PolicyID)
	if !ok {
		return errors.New("policy not found")
	}
	if p.Platform != a.Platform {
		return errors.New("policy platform mismatch")
	}
	if a.TargetType == "agent" {
		found := false
		for _, agent := range s.data.Agents {
			if agent.ID == a.TargetID && agent.Platform == a.Platform {
				found = true
			}
		}
		if !found {
			return errors.New("target agent not found or platform mismatch")
		}
	}
	for i, old := range s.data.Assignments {
		if old.TargetType == a.TargetType && old.TargetID == a.TargetID && old.Platform == a.Platform {
			s.data.Assignments[i] = a
			return nil
		}
	}
	s.data.Assignments = append(s.data.Assignments, a)
	return nil
}
func (s *Store) Desired(agentID string) (Policy, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var agent Agent
	found := false
	for _, a := range s.data.Agents {
		if a.ID == agentID {
			agent = a
			found = true
			break
		}
	}
	if !found {
		return Policy{}, false
	}
	for _, tt := range []string{"agent", "group", "default"} {
		target := agent.ID
		if tt == "group" {
			target = agent.Group
		}
		if tt == "default" {
			target = "*"
		}
		for _, a := range s.data.Assignments {
			if a.TargetType == tt && a.TargetID == target && a.Platform == agent.Platform {
				return s.findPolicy(a.PolicyID)
			}
		}
	}
	return Policy{}, false
}
func (s *Store) Ack(agentID, policyID string, revision int, success bool, detail string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.findPolicy(policyID)
	if !ok || p.Revision != revision {
		return errors.New("unknown policy revision")
	}
	for i, a := range s.data.Agents {
		if a.ID == agentID {
			if a.Platform != p.Platform {
				return errors.New("platform mismatch")
			}
			if success {
				s.data.Agents[i].AppliedPolicyID = policyID
				s.data.Agents[i].AppliedRevision = revision
				s.data.Agents[i].LastPolicyError = ""
			} else {
				s.data.Agents[i].LastPolicyError = detail
			}
			return nil
		}
	}
	return errors.New("agent not found")
}

// allowedSysmonFields is deliberately sparse. The lab collector must never
// upload CommandLine, User, ClipboardText, archived files, raw XML or
// registry data values; these are privacy-sensitive or unbounded.
var allowedSysmonFields = map[string]bool{
    "rule_name":true, "destination_ip":true, "destination_port":true,
    "source_ip":true, "source_port":true, "protocol":true,
    "query_name":true, "target_object":true, "pipe_name":true,
    "source_image":true, "target_image":true, "source_process_guid":true,
    "target_process_guid":true, "image_loaded":true,
    "operation":true, "event_type":true, "query_status":true,
    "target_filename":true, "initiated":true,
}
// Names are source classifications, not assertions that an event is authentic.
// Require the reported numerical Sysmon ID and event type to agree.
var expectedSysmonTypes = map[uint32]string{
    1:"process_create",2:"file_creation_time",3:"network_connect",
    4:"sysmon_service_state",5:"process_terminate",6:"driver_load",
    7:"module_load",8:"create_remote_thread",9:"raw_access_read",
    10:"process_access",11:"file_create",12:"registry_object",
    13:"registry_value_set",14:"registry_rename",15:"file_stream_hash",
    16:"sysmon_config_change",17:"pipe_create",18:"pipe_connect",
    19:"wmi_filter",20:"wmi_consumer",21:"wmi_binding",22:"dns_query",
    23:"file_delete_archive",24:"clipboard_change_metadata",
    25:"process_tampering",26:"file_delete_detected",
    27:"file_block_executable",28:"file_block_shredding",
    29:"file_executable_detected",255:"sysmon_error",
}
// Legacy lab records may predate provider/channel tagging. They remain
// explicitly unverified; newer records MUST report the pair consistently.
// No other Windows Event Log provider (Security, System or PowerShell) may
// masquerade as the Sysmon provider or reuse a numeric Sysmon event label.
func validateEventProvider(e Event) error {
    if e.SourceProvider == "" && e.SourceChannel == "" {
        return nil // backward-compatible, provider not verified
    }
    if len(e.SourceProvider) > 96 || len(e.SourceChannel) > 128 {
        return errors.New("source provider/channel too long")
    }
    if e.Source == "sysmon" && e.Platform == "windows" && e.SourceEventID != 0 &&
        e.SourceProvider == "Microsoft-Windows-Sysmon" &&
        e.SourceChannel == "Microsoft-Windows-Sysmon/Operational" {
        return nil
    }
    return errors.New("source provider/channel mismatch or unsupported channel")
}

func validateSysmonSourceFields(e Event) error {
    if e.SourceEventID == 0 && len(e.SourceFields) == 0 { return nil }
    if e.Source != "sysmon" || e.Platform != "windows" {
        return errors.New("source_event_id/source_fields require Windows Sysmon source")
    }
    expected, known := expectedSysmonTypes[e.SourceEventID]
    if !known {
        return errors.New("unsupported Sysmon source event ID")
    }
    if e.Type != expected {
        return errors.New("Sysmon event ID and type do not match")
    }
    if e.SourceEventID == 1 && (e.ProcessGUID == "" || e.Image == "") {
        return errors.New("Sysmon process creation requires reported process GUID and image")
    }
    if e.SourceEventID != 1 && e.ParentProcessGUID != "" {
        return errors.New("Sysmon parent process link is only valid for process creation")
    }
    if e.SourceEventID == 24 &&
        (len(e.SourceFields) != 0 || e.ProcessGUID != "" ||
         e.Image != "" || e.FilePath != "" || e.ParentProcessGUID != "") {
        return errors.New("clipboard event must contain source metadata only")
    }
    if len(e.SourceFields) > 19 {
        return errors.New("too many source fields")
    }
    total := 0
    for k, v := range e.SourceFields {
        if !allowedSysmonFields[k] { return errors.New("unsupported or private Sysmon source field") }
        if len(v) > 512 || strings.IndexFunc(v, func(r rune) bool { return r < 0x20 || r == 0x7f || r == 0xfffd }) >= 0 {
            return errors.New("invalid Sysmon source field value")
        }
        total += len(k)+len(v)
    }
    if total > 4096 { return errors.New("Sysmon source fields too large") }
    if e.SourceEventID == 24 && len(e.SourceFields) != 0 {
        return errors.New("clipboard event must be metadata only")
    }
    return nil
}

// Keep API-accepted text within the stricter React and Go-served SOC display
// contracts. One oversized value must not make the full telemetry view fail.
// Benign tabs/newlines are allowed in descriptive text, never ASCII C0 or DEL controls.
func validDisplayText(value string) bool {
	return strings.IndexFunc(value, func(r rune) bool {
		return (r < 0x20 && r != '\t' && r != '\n' && r != '\r') ||
			r == 0x7f || r == 0xfffd
	}) < 0
}

func (s *Store) Ingest(e Event) (Event, error) {
	if !validID(e.DeviceID) {
		return Event{}, errors.New("invalid device id")
	}
	if len(e.Type) < 1 || len(e.Type) > 80 || len(e.Detail) > 4096 ||
		len(e.Source) > 128 || len(e.BootID) > 128 || len(e.ProcessGUID) > 128 ||
		len(e.ParentProcessGUID) > 128 || len(e.Image) > 1024 ||
		len(e.FilePath) > 1024 || len(e.Hash) > 256 ||
		!validDisplayText(e.Type) || !validDisplayText(e.Source) ||
		!validDisplayText(e.Image) || !validDisplayText(e.FilePath) ||
		!validDisplayText(e.Detail) {
		return Event{}, errors.New("invalid event fields")
	}
	if err := validateEventProvider(e); err != nil {
		return Event{}, err
	}
	if err := validateSysmonSourceFields(e); err != nil {
		return Event{}, err
	}
	if len(e.BootID) > 128 || strings.IndexFunc(e.BootID, func(r rune) bool {
		return r < 0x20 || r == 0x7f || r == 0xfffd
	}) >= 0 {
		return Event{}, errors.New("invalid sender-reported boot id")
	}
	if len(e.SourceRecordID) > 256 || strings.IndexFunc(e.SourceRecordID, func(r rune) bool {
		return r < 0x20 || r == 0x7f || r == 0xfffd
	}) >= 0 {
		return Event{}, errors.New("invalid sender-reported source record id")
	}
	if err := stripSysmonClipboardDetail(&e); err != nil {
		return Event{}, err
	}
	// Time and source IDs sent by a lab client are unverified claims. Always
	// stamp server receipt time and overwrite client-controlled provenance tags.
	now := time.Now().UTC()
	e.ReceivedAt = now
	if e.Time.IsZero() {
		e.Time = now
		e.TimeOrigin = "server_received"
	} else {
		e.TimeOrigin = "sender_reported_unverified"
	}
	if e.Time.After(now.Add(5 * time.Minute)) {
		return Event{}, errors.New("event timestamp too far in future")
	}
	newid, err := id()
	if err != nil {
		return Event{}, err
	}
	e.ID = newid
	s.mu.Lock()
	defer s.mu.Unlock()
	found := false
	for _, a := range s.data.Agents {
		if a.ID == e.DeviceID && a.Platform == e.Platform {
			found = true
			break
		}
	}
	if !found {
		return Event{}, errors.New("agent not enrolled or platform mismatch")
	}
	s.data.Events = append(s.data.Events, e)
	if len(s.data.Events) > 2000 {
		s.data.Events = append([]Event(nil), s.data.Events[len(s.data.Events)-2000:]...)
	}
	return e, nil
}
