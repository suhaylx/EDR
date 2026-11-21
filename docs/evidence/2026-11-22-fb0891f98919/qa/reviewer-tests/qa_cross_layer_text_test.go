package edr

import "testing"

func TestQAFrontendRejectsPersistableHeartbeatText(t *testing.T) {
 for _,v:=range []string{"v1\u061c","v1\ufffd"} {
  h:=AgentHeartbeat{Platform:"linux",AgentVersion:v,ScanReady:false}
  if validHeartbeat(h) {t.Errorf("backend accepted text that frontend operator endpoint decoder rejects: %U",[]rune(v)[2])}
 }
}

func TestQAFrontendRejectsBOMOnlyMaliciousSignature(t *testing.T) {
 if validScanResult("malicious","\ufeff","") {t.Fatal("backend accepts BOM-only signature that frontend trims to empty")}
}
