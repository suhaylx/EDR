package edr

import (
 "context"
 "errors"
 "testing"
)

func TestBE036To040RenewalLeaseTTLFailClosed(t *testing.T){
 cases:=[]struct{name string;ttl int}{
  {"BE036 negative duration",-300},
  {"BE037 zero duration",0},
  {"BE038 four second duration",4},
  {"BE039 301 second duration",301},
  {"BE040 maximum integer duration",int(^uint(0)>>1)},
 }
 for _,tc:=range cases {t.Run(tc.name,func(t *testing.T){
  _,err:=(PostgresScanJobQueue{}).Renew(context.Background(),"tenantA","win01",testUUID,"win01",leaseUUID,tc.ttl)
  if !errors.Is(err,ErrInvalidScanQueueRequest) {t.Fatalf("ttl=%d accepted: %v",tc.ttl,err)}
 })}
}
