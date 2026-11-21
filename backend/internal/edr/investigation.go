package edr

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"
)

// InvestigationGraph is an EVIDENCE graph from retained, untrusted lab data.
// It cannot prove compromise, completeness, or that a process actually ran on a real endpoint.
type InvestigationGraph struct {
	DeviceID        string              `json:"device_id"`
	SeedProcessGUID string              `json:"seed_process_guid"`
	SeedDetectionID string              `json:"seed_detection_id,omitempty"`
	DataSource      string              `json:"data_source"`
	Nodes           []InvestigationNode `json:"nodes"`
	Edges           []InvestigationEdge `json:"edges"`
	Gaps            []string            `json:"gaps"`
	Truncated       bool                `json:"truncated"`
}

type InvestigationNode struct {
	ID          string    `json:"id"`
	Kind        string    `json:"kind"` // process, event, file, detection
	Label       string    `json:"label"`
	Status      string    `json:"status"` // observed or referenced (never 'infected')
	DeviceID    string    `json:"device_id"`
	ProcessGUID string    `json:"process_guid,omitempty"`
	EventID     string    `json:"event_id,omitempty"`
	EventType   string    `json:"event_type,omitempty"`
	FilePath    string    `json:"file_path,omitempty"`
	Image       string    `json:"image,omitempty"`
	SHA256      string    `json:"sha256,omitempty"`
	Detail      string    `json:"detail,omitempty"`
	Severity    string    `json:"severity,omitempty"`
	Confidence  string    `json:"confidence,omitempty"`
	Time        time.Time `json:"time,omitempty"`
}

type InvestigationEdge struct {
	From       string `json:"from"`
	To         string `json:"to"`
	Relation   string `json:"relation"`
	Provenance string `json:"provenance"` // observed or reported (not automatically causal)
	EvidenceID string `json:"evidence_id,omitempty"`
}

var ErrInvestigationNotFound = errors.New("investigation seed not found in retained records")

func graphID(prefix, deviceID, entity string) string {
	digest := sha256.Sum256([]byte(deviceID + "\x00" + entity))
	return prefix + ":" + hex.EncodeToString(digest[:12])
}

func validInvestigationGUID(s string) bool {
	if s == "" || len(s) > 160 {
		return false
	}
	for _, c := range s {
		if c < 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}

type procGraphInfo struct {
	guid       string
	parent     string
	parentEvid string
	observed   bool
	image      string
	firstTime  time.Time
	hasEvents  bool
}

// BuildProcessInvestigation follows same-device process GUIDs across an observed
// parent/child lineage and attaches associated event/detection evidence.
// Parent GUIDs without a process-create event are explicitly weaker references.
// depth and maxNodes bound the on-demand expansion of the retained lab history.
func BuildProcessInvestigation(events []Event, detections []Detection, deviceID, processGUID, detectionID string, depth, maxNodes int) (InvestigationGraph, error) {
	if !validID(deviceID) || ((processGUID == "") == (detectionID == "")) {
		return InvestigationGraph{}, errors.New("supply device_id and exactly one of process_guid or detection_id")
	}
	if depth < 1 || depth > 6 || maxNodes < 1 || maxNodes > 500 {
		return InvestigationGraph{}, errors.New("depth must be 1..6 and max_nodes must be 1..500")
	}
	if detectionID != "" {
		found := false
		for _, d := range detections {
			if d.ID == detectionID && d.DeviceID == deviceID && validInvestigationGUID(d.ProcessGUID) {
				processGUID, found = d.ProcessGUID, true
				break
			}
		}
		if !found {
			return InvestigationGraph{}, ErrInvestigationNotFound
		}
	}
	if !validInvestigationGUID(processGUID) {
		return InvestigationGraph{}, errors.New("invalid process_guid")
	}

	g := InvestigationGraph{
		DeviceID: deviceID, SeedProcessGUID: processGUID, SeedDetectionID: detectionID,
		DataSource: "development_in_memory_retained_telemetry",
		Nodes:      []InvestigationNode{}, Edges: []InvestigationEdge{},
		Gaps: []string{
			"Retained laboratory events only (up to 2,000); gaps, endpoint installation and capture completeness are not verified.",
			"Device events use a shared development bearer token; no tenant-scoped mTLS or production event provenance exists.",
			"A graph edge is evidence or a reported relationship, not a proven infection, causality or complete attack chain.",
		},
	}
	info := map[string]*procGraphInfo{}
	ensure := func(guid string) *procGraphInfo {
		p, ok := info[guid]
		if !ok {
			p = &procGraphInfo{guid: guid}
			info[guid] = p
		}
		return p
	}
	selectedEvents := make([]Event, 0)
	for _, ev := range events {
		if ev.DeviceID != deviceID || !validInvestigationGUID(ev.ProcessGUID) {
			continue
		}
		selectedEvents = append(selectedEvents, ev)
		p := ensure(ev.ProcessGUID)
		p.hasEvents = true
		if p.firstTime.IsZero() || (!ev.Time.IsZero() && ev.Time.Before(p.firstTime)) {
			p.firstTime = ev.Time
		}
		if ev.Image != "" && (p.image == "" || ev.Type == "process_create") {
			p.image = ev.Image
		}
		if validInvestigationGUID(ev.ParentProcessGUID) && ev.ParentProcessGUID != ev.ProcessGUID {
			if ev.Type == "process_create" || p.parent == "" {
				p.parent, p.parentEvid, p.observed = ev.ParentProcessGUID, ev.ID, ev.Type == "process_create"
				ensure(ev.ParentProcessGUID) // referenced parent may lack its own Event 1
			}
		}
	}
	if _, ok := info[processGUID]; !ok {
		return InvestigationGraph{}, ErrInvestigationNotFound
	}
	// Expand ancestors and descendants from the selected seed, bounded by depth.
	included := map[string]bool{processGUID: true}
	front := []string{processGUID}
	for step := 0; step < depth && len(front) > 0; step++ {
		next := []string{}
		sorted := make([]string, 0, len(info))
		for id := range info {
			sorted = append(sorted, id)
		}
		sort.Strings(sorted)
		for _, guid := range front {
			p := info[guid]
			if p.parent != "" && !included[p.parent] {
				included[p.parent] = true
				next = append(next, p.parent)
			}
			for _, candidate := range sorted {
				if info[candidate].parent == guid && !included[candidate] {
					included[candidate] = true
					next = append(next, candidate)
				}
			}
		}
		front = next
	}
	processIDs := make([]string, 0, len(included))
	for id := range included {
		processIDs = append(processIDs, id)
	}
	sort.Strings(processIDs)
	nodes := map[string]bool{}
	addNode := func(n InvestigationNode) bool {
		if nodes[n.ID] {
			return true
		}
		if len(g.Nodes) >= maxNodes {
			g.Truncated = true
			return false
		}
		nodes[n.ID] = true
		g.Nodes = append(g.Nodes, n)
		return true
	}
	seenEdges := map[string]bool{}
	addEdge := func(e InvestigationEdge) {
		if !nodes[e.From] || !nodes[e.To] {
			return
		}
		key := e.From + "|" + e.To + "|" + e.Relation
		if seenEdges[key] {
			return
		}
		seenEdges[key] = true
		g.Edges = append(g.Edges, e)
	}
	// Prioritize the seed process when a very small maxNodes was requested.
	sort.SliceStable(processIDs, func(i, j int) bool {
		if processIDs[i] == processGUID {
			return true
		}
		if processIDs[j] == processGUID {
			return false
		}
		return processIDs[i] < processIDs[j]
	})
	for _, guid := range processIDs {
		p := info[guid]
		label := p.image
		if label == "" {
			label = "Referenced process " + guid
		}
		status := "referenced"
		if p.hasEvents {
			status = "observed"
		}
		addNode(InvestigationNode{ID: graphID("process", deviceID, guid), Kind: "process", Label: label, Status: status, DeviceID: deviceID, ProcessGUID: guid, Image: p.image, Time: p.firstTime})
	}
	referencedParents := false
	for _, guid := range processIDs {
		p := info[guid]
		if p.parent == "" || !included[p.parent] {
			continue
		}
		origin := "reported"
		if p.observed {
			origin = "observed"
		} else {
			referencedParents = true
		}
		addEdge(InvestigationEdge{From: graphID("process", deviceID, p.parent), To: graphID("process", deviceID, guid), Relation: "parent_process", Provenance: origin, EvidenceID: p.parentEvid})
	}
	if referencedParents {
		g.Gaps = append(g.Gaps, "Some parent-child relations were reported without a retained process-create event and must not be treated as confirmed spawns.")
	}

	sort.SliceStable(selectedEvents, func(i, j int) bool {
		if selectedEvents[i].Time.Equal(selectedEvents[j].Time) {
			return selectedEvents[i].ID < selectedEvents[j].ID
		}
		return selectedEvents[i].Time.Before(selectedEvents[j].Time)
	})
	for _, ev := range selectedEvents {
		if !included[ev.ProcessGUID] {
			continue
		}
		nID := graphID("event", deviceID, ev.ID)
		label := ev.Type
		if ev.FilePath != "" {
			label += " · " + ev.FilePath
		}
		if !addNode(InvestigationNode{ID: nID, Kind: "event", Label: label, Status: "observed", DeviceID: deviceID, ProcessGUID: ev.ProcessGUID, EventID: ev.ID, EventType: ev.Type, Image: ev.Image, FilePath: ev.FilePath, SHA256: ev.Hash, Detail: ev.Detail, Time: ev.Time}) {
			continue
		}
		addEdge(InvestigationEdge{From: graphID("process", deviceID, ev.ProcessGUID), To: nID, Relation: "observed_event", Provenance: "observed", EvidenceID: ev.ID})
		// File artifact existence is proven only by the original retained event; a
		// module_load edge proves an observed image load, not file creation.
		if ev.FilePath != "" && (ev.Type == "file_create" || ev.Type == "module_load" || ev.Type == "file_delete") {
			fID := graphID("file", deviceID, windowsPath(ev.FilePath))
			if addNode(InvestigationNode{ID: fID, Kind: "file", Label: ev.FilePath, Status: "referenced", DeviceID: deviceID, FilePath: ev.FilePath, SHA256: ev.Hash}) {
				relation := "references_file"
				if ev.Type == "module_load" {
					relation = "loaded_module"
				}
				if ev.Type == "file_create" {
					relation = "created_file"
				}
				if ev.Type == "file_delete" {
					relation = "deleted_file"
				}
				addEdge(InvestigationEdge{From: nID, To: fID, Relation: relation, Provenance: "observed", EvidenceID: ev.ID})
			}
		}
	}
	sort.SliceStable(detections, func(i, j int) bool { return detections[i].ID < detections[j].ID })
	for _, det := range detections {
		if det.DeviceID != deviceID || !included[det.ProcessGUID] {
			continue
		}
		dID := graphID("detection", deviceID, det.ID)
		if !addNode(InvestigationNode{ID: dID, Kind: "detection", Label: det.RuleID + " · " + det.Category, Status: "observed", DeviceID: deviceID, ProcessGUID: det.ProcessGUID, EventID: det.LoadEventID, Severity: det.Severity, Confidence: det.Confidence, Detail: det.Explanation, Time: det.ObservedAt}) {
			continue
		}
		addEdge(InvestigationEdge{From: graphID("process", deviceID, det.ProcessGUID), To: dID, Relation: "flagged_by_rule", Provenance: "observed", EvidenceID: det.LoadEventID})
		for _, evID := range []string{det.LoadEventID, det.FileCreateEventID} {
			if evID == "" {
				continue
			}
			addEdge(InvestigationEdge{From: dID, To: graphID("event", deviceID, evID), Relation: "linked_detection_evidence", Provenance: "reported", EvidenceID: evID})
		}
	}
	if g.Truncated {
		g.Gaps = append(g.Gaps, fmt.Sprintf("Response truncated at max_nodes=%d; absence of further edges does not prove no activity.", maxNodes))
	}
	return g, nil
}
