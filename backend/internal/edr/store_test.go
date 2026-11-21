package edr

import (
	"strings"
	"testing"
)

const sampleXML = `<Sysmon schemaversion="4.90"><EventFiltering><RuleGroup name="process" groupRelation="or"><ProcessCreate onmatch="exclude" /></RuleGroup></EventFiltering></Sysmon>`

func TestPolicyValidation(t *testing.T) {
	bad := []string{"", `<foo><EventFiltering/></foo>`, `<!DOCTYPE Sysmon><Sysmon><EventFiltering/></Sysmon>`, `<Sysmon><!ENTITY x "bad"><EventFiltering/></Sysmon>`, `<Sysmon><EventFiltering>`}
	for _, raw := range bad {
		if err := validateXML(raw); err == nil {
			t.Errorf("accepted invalid XML %q", raw)
		}
	}
	if err := validateXML(sampleXML); err != nil {
		t.Fatalf("valid sample rejected: %v", err)
	}
	if err := validateXML(strings.Repeat("a", 70000)); err == nil {
		t.Fatal("oversized XML accepted")
	}
}

func TestAssignmentPrecedenceAndAck(t *testing.T) {
	s := NewStore()
	if _, err := s.CheckIn(Agent{ID: "win-lab-01", Platform: "windows", Group: "finance"}); err != nil {
		t.Fatal(err)
	}
	create := func(name string) Policy {
		p, err := s.CreatePolicy(name, "windows", sampleXML)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	base, group, device := create("base"), create("finance"), create("device")
	if err := s.Assign(Assignment{TargetType: "default", Platform: "windows", PolicyID: base.ID}); err != nil {
		t.Fatal(err)
	}
	if p, ok := s.Desired("win-lab-01"); !ok || p.ID != base.ID {
		t.Fatal("default assignment not selected")
	}
	if err := s.Assign(Assignment{TargetType: "group", TargetID: "finance", Platform: "windows", PolicyID: group.ID}); err != nil {
		t.Fatal(err)
	}
	if p, ok := s.Desired("win-lab-01"); !ok || p.ID != group.ID {
		t.Fatal("group assignment not selected")
	}
	if err := s.Assign(Assignment{TargetType: "agent", TargetID: "win-lab-01", Platform: "windows", PolicyID: device.ID}); err != nil {
		t.Fatal(err)
	}
	if p, ok := s.Desired("win-lab-01"); !ok || p.ID != device.ID {
		t.Fatal("device override not selected")
	}
	if err := s.Ack("win-lab-01", device.ID, device.Revision, true, ""); err != nil {
		t.Fatal(err)
	}
	a := s.Snapshot().Agents[0]
	if a.AppliedPolicyID != device.ID || a.AppliedRevision != device.Revision {
		t.Fatal("policy ack not persisted")
	}
}

func TestEventRequiresAgent(t *testing.T) {
	s := NewStore()
	_, err := s.Ingest(Event{DeviceID: "unknown", Platform: "windows", Type: "process_create"})
	if err == nil {
		t.Fatal("orphan event accepted")
	}
	if _, err = s.CheckIn(Agent{ID: "win-lab-01", Platform: "windows"}); err != nil {
		t.Fatal(err)
	}
	e, err := s.Ingest(Event{DeviceID: "win-lab-01", Platform: "windows", Type: "process_create", Source: "sysmon-synthetic"})
	if err != nil || e.ID == "" {
		t.Fatalf("valid synthetic event: %v", err)
	}
	if len(s.Snapshot().Events) != 1 {
		t.Fatal("missing event")
	}
}

func TestCrossPlatformAssignmentRejected(t *testing.T) {
	s := NewStore()
	_, _ = s.CheckIn(Agent{ID: "linux-lab", Platform: "linux"})
	p, err := s.CreatePolicy("windows policy", "windows", sampleXML)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Assign(Assignment{TargetType: "agent", TargetID: "linux-lab", Platform: "linux", PolicyID: p.ID}); err == nil {
		t.Fatal("cross-platform policy accepted")
	}
}


func TestPolicyAckRejectsUnassignedStaleAndOverriddenPolicies(t *testing.T) {
	s := NewStore()
	if _, err := s.CheckIn(Agent{ID: "win-ack", Platform: "windows", Group: "finance"}); err != nil {
		t.Fatal(err)
	}
	base, err := s.CreatePolicy("base ack", "windows", sampleXML)
	if err != nil { t.Fatal(err) }
	group, err := s.CreatePolicy("group ack", "windows", sampleXML)
	if err != nil { t.Fatal(err) }
	device, err := s.CreatePolicy("device ack", "windows", sampleXML)
	if err != nil { t.Fatal(err) }

	// A valid-looking report cannot invent an assignment.
	if err := s.Ack("win-ack", base.ID, base.Revision, true, ""); err == nil {
		t.Fatal("unassigned policy was acknowledged")
	}
	if err := s.Assign(Assignment{TargetType: "default", Platform: "windows", PolicyID: base.ID}); err != nil { t.Fatal(err) }
	if err := s.Ack("win-ack", base.ID, base.Revision, true, ""); err != nil { t.Fatal(err) }

	if err := s.Assign(Assignment{TargetType: "group", TargetID: "finance", Platform: "windows", PolicyID: group.ID}); err != nil { t.Fatal(err) }
	if err := s.Ack("win-ack", base.ID, base.Revision, true, ""); err == nil {
		t.Fatal("old default policy was accepted after group override")
	}
	if err := s.Ack("win-ack", group.ID, group.Revision, true, ""); err != nil { t.Fatal(err) }

	if err := s.Assign(Assignment{TargetType: "agent", TargetID: "win-ack", Platform: "windows", PolicyID: device.ID}); err != nil { t.Fatal(err) }
	before := s.Snapshot().Agents[0]
	if err := s.Ack("win-ack", group.ID, group.Revision, false, "stale error"); err == nil {
		t.Fatal("stale group failure was allowed to mutate agent state")
	}
	if after := s.Snapshot().Agents[0]; after.AppliedPolicyID != before.AppliedPolicyID ||
		after.AppliedRevision != before.AppliedRevision || after.LastPolicyError != before.LastPolicyError {
		t.Fatal("stale policy acknowledgement changed recorded agent state")
	}
	if err := s.Ack("win-ack", device.ID, device.Revision, true, ""); err != nil { t.Fatal(err) }
	if got := s.Snapshot().Agents[0]; got.AppliedPolicyID != device.ID {
		t.Fatal("current device policy acknowledgement was not recorded")
	}
}
