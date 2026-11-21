package edr

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The corpus contains harmless synthetic metadata, not malware or real
// Sysmon evidence. It makes the original rule's false-positive and
// correlation boundaries regression-testable as independent QA inputs.
func TestOriginalDLLRuleFixtureCorpusV2(t *testing.T) {
	fixturePath := filepath.Join("..", "..", "..", "tests", "fixtures", "security", "dll-correlation-v2.json")
	raw, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		SchemaVersion int    `json:"schema_version"`
		FixtureType   string `json:"fixture_type"`
		Note          string `json:"note"`
		Cases         []struct {
			Name           string  `json:"name"`
			Events         []Event `json:"events"`
			Detections     int     `json:"detections"`
			LinkedCreateID string  `json:"linked_create_id"`
		} `json:"cases"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&corpus); err != nil {
		t.Fatalf("invalid synthetic security fixture schema: %v", err)
	}
	if corpus.SchemaVersion != 2 || corpus.FixtureType != "synthetic_metadata_only" || len(corpus.Cases) < 12 {
		t.Fatalf("invalid or incomplete security fixture corpus: version=%d type=%q cases=%d",
			corpus.SchemaVersion, corpus.FixtureType, len(corpus.Cases))
	}
	seen := map[string]bool{}
	for _, tc := range corpus.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			if tc.Name == "" || seen[tc.Name] {
				t.Fatal("empty or duplicate fixture name")
			}
			seen[tc.Name] = true
			if tc.Detections < 0 || tc.Detections > 1 {
				t.Fatal("invalid expected detection count in lab fixture")
			}
			for _, e := range tc.Events {
				if e.Source != "sysmon_synthetic" {
					t.Fatalf("fixtures must not represent synthetic metadata as authenticated Sysmon evidence: %q", e.Source)
				}
			}
			got := DetectSuspiciousDLLLoads(tc.Events)
			if len(got) != tc.Detections {
				t.Fatalf("wanted %d provisional alerts, got %+v", tc.Detections, got)
			}
			if len(got) == 1 {
				d := got[0]
				if d.RuleID != "TURAN-WIN-DLL-LOAD-001" || d.Category != "suspicious_dll_load" ||
					d.Confidence != "low" || d.Severity != "medium" || d.LoadEventID == "" {
					t.Fatalf("untruthful detection semantics: %+v", d)
				}
				if d.FileCreateEventID != tc.LinkedCreateID {
					t.Fatalf("wrong file-create provenance link, expected %q: %+v", tc.LinkedCreateID, d)
				}
			}
		})
	}
}
