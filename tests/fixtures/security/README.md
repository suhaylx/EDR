# Safe Security Fixtures

Use only synthetic JSON-like events and EICAR's official test file in an
isolated development lab. Never execute actual malware on a protected host.

The executable Go regression fixtures live in
`backend/internal/edr/detection_test.go`. They check:
- creation alone does not imply execution
- image-load event and process identity required
- optional prior file-create event linked only on same device/path/time/hash
- no Linux triggering, no normal System32 triggering, no duplicate alerts
- development API authentication for read-only detection list

Before validating real Sysmon, create Windows lab event captures with correct
record IDs, provider identity and process GUIDs. Store sanitized fixtures only.
