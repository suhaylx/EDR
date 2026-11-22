package edr

import "testing"

// These are rejected by the React SOC decoder as well. Accepting them into a
// heartbeat/result would poison the complete fleet snapshot on the next fetch.
func TestSOCDisplayContractRejectsInvisibleAndInvalidText(t *testing.T) {
	for _, value := range []string{"v1\u061c", "v1\ufffd", "v1\ufeff", "v1\u202e", "v1\u2066", string([]byte{'v', 0xff})} {
		if !containsUnsafeSOCText(value) {
			t.Errorf("unsafe SOC display string accepted")
		}
		if validHeartbeat(AgentHeartbeat{Platform: "linux", AgentVersion: value}) {
			t.Errorf("unsafe heartbeat persisted")
		}
	}
	for _, value := range []string{"", " ", "\u00a0"} {
		if validHeartbeat(AgentHeartbeat{Platform: "linux", AgentVersion: value}) {
			t.Error("blank required version accepted")
		}
		if validScanResult("malicious", value, "synthetic fixture") {
			t.Error("blank malicious signature accepted")
		}
	}
	if !validHeartbeat(AgentHeartbeat{Platform: "linux", AgentVersion: "0.1.0", ScanReady: false}) {
		t.Error("honest degraded heartbeat rejected")
	}
}
