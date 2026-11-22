package edr

import (
 "context"
 "errors"
 "testing"
)

func TestBE041To045RenewalLeaseTokenFailClosed(t *testing.T){
 cases:=[]struct{name,token string}{
  {"BE041 missing lease token",""},
  {"BE042 truncated lease token","22222222-2222-4222-8222"},
  {"BE043 nonhex lease token","zzzzzzzz-2222-4222-8222-222222222222"},
  {"BE044 malformed UUID separators","22222222222242228222222222222222"},
  {"BE045 whitespace lease token"," "+leaseUUID},
 }
 for _,tc:=range cases {t.Run(tc.name,func(t *testing.T){
  _,err:=(PostgresScanJobQueue{}).Renew(context.Background(),"tenantA","win01",testUUID,"win01",tc.token,30)
  if !errors.Is(err,ErrInvalidScanQueueRequest) {t.Fatalf("token accepted: %v",err)}
 })}
}
