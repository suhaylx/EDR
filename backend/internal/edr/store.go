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
func (s *Store) Ingest(e Event) (Event, error) {
	if !validID(e.DeviceID) {
		return Event{}, errors.New("invalid device id")
	}
	if len(e.Type) < 1 || len(e.Type) > 80 || len(e.Detail) > 4096 ||
		len(e.Source) > 128 || len(e.BootID) > 128 || len(e.ProcessGUID) > 128 ||
		len(e.ParentProcessGUID) > 128 || len(e.Image) > 32768 ||
		len(e.FilePath) > 32768 || len(e.Hash) > 256 {
		return Event{}, errors.New("invalid event fields")
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
