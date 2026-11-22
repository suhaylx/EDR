package edr

import (
 "context"
 "errors"
 "testing"
)

func TestQAReviewExactSOCAlertActionMatching(t *testing.T){
 principal:=SOCOperatorPrincipal{TenantID:"tenantA",OperatorID:"analyst",Role:"scanner"}
 queue:=PostgresScanJobQueue{}
 for _,action:=range []string{
  "ack|resolve","ack|resolve|reopen","reopen|ack","resolve|reopen",
  "ACK","resolve ","","ack\nresolve",
 }{
  if validSOCAlertAction(action){
   t.Errorf("compound/unknown SOC action %q erroneously accepted",action)
  }
  _,err:=queue.ChangeSOCAlert(context.Background(),principal,testUUID,action,"")
  if !errors.Is(err,ErrInvalidScanQueueRequest){
   t.Errorf("action %q: got %v, want invalid request",action,err)
  }
 }
 for _,action:=range []string{"ack","resolve","reopen"}{
  if !validSOCAlertAction(action){
   t.Errorf("legitimate SOC action %q denied",action)
  }
 }
}

func TestQAReviewUnsafeSOCTextIsRefusedAcrossWritePaths(t *testing.T){
 principal:=SOCOperatorPrincipal{TenantID:"tenantA",OperatorID:"analyst",Role:"scanner"}
 queue:=PostgresScanJobQueue{}
 for _,unsafe:=range []string{
  "esc\x1b[31m","bidi\u202emalware","rlm\u200ftext",
  "isolate\u2066text","tab\tinside","line\ninside","nul\x00inside",
 }{
  if !containsUnsafeSOCText(unsafe){t.Fatalf("unsafe text accepted: %q",unsafe)}
  _,err:=queue.AddSOCAlertNote(context.Background(),principal,testUUID,unsafe)
  if !errors.Is(err,ErrInvalidScanQueueRequest){
   t.Errorf("unsafe analyst note %q: %v",unsafe,err)
  }
  _,err=queue.ChangeSOCAlert(context.Background(),principal,testUUID,"resolve",unsafe)
  if !errors.Is(err,ErrInvalidScanQueueRequest){
   t.Errorf("unsafe resolution note %q: %v",unsafe,err)
  }
  _,err=queue.ScheduleSOCScan(context.Background(),principal,"win01","unique-request-01",unsafe)
  if !errors.Is(err,ErrInvalidScanQueueRequest){
   t.Errorf("unsafe target path %q: %v",unsafe,err)
  }
  _,err=queue.CompleteWithResult(context.Background(),"tenantA","win01",
   testUUID,leaseUUID,"malicious",unsafe,"")
  if !errors.Is(err,ErrInvalidScanQueueRequest){
   t.Errorf("unsafe ClamAV signature %q: %v",unsafe,err)
  }
  _,err=queue.RecordHeartbeat(context.Background(),"tenantA","win01",
   AgentHeartbeat{Platform:"linux",AgentVersion:unsafe})
  if !errors.Is(err,ErrInvalidScanQueueRequest){
   t.Errorf("unsafe heartbeat version %q: %v",unsafe,err)
  }
 }
 for _,safe:=range []string{"ClamAV-Signature-A","analyst-note-2026",
  "windows-2022","UTF8 café","/var/opt/turansec/lab/file"}{
  if containsUnsafeSOCText(safe){t.Errorf("safe text refused: %q",safe)}
 }
}
