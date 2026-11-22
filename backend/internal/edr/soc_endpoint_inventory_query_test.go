package edr

import (
 "strings"
 "testing"
)

// The SQL mock driver checks query arguments but does not parse PostgreSQL.
// Explicit CTE aliases are necessary because PostgreSQL names an unaliased
// COALESCE expression "coalesce", not the underlying heartbeat column.
func TestQASOCEndpointInventoryComputedColumnsAreNamed(t *testing.T) {
 for _,col:=range []string{
  "agent_version","clamav_version","signature_version",
  "scan_ready","received_count",
 } {
  fragment:=" AS "+col
  if !strings.Contains(endpointInventoryCTE,fragment){
   t.Fatalf("inventory CTE omits computed column alias %q",col)
  }
 }
 for _,s:=range []string{listEndpointsSQL,getEndpointSQL,summaryEndpointsSQL}{
  if !strings.Contains(s,endpointInventoryCTE){
   t.Fatal("endpoint read query lost shared inventory CTE")
  }
 }
}
