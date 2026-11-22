package edr
import ("context";"errors";"testing")
func TestBE046To050RejectInvalidScanJobUUID(t *testing.T){
 cases:=[]struct{name,id string}{
 {"BE046 missing job ID",""},
 {"BE047 truncated job ID","11111111-1111-4111"},
 {"BE048 nonhex job ID","zzzzzzzz-1111-4111-8111-111111111111"},
 {"BE049 UUID without separators","11111111111141118111111111111111"},
 {"BE050 whitespace job ID"," "+testUUID},
 }
 for _,tc:=range cases{t.Run(tc.name,func(t *testing.T){
 _,err:=(PostgresScanJobQueue{}).Renew(context.Background(),"tenantA","win01",tc.id,"win01",leaseUUID,30)
 if !errors.Is(err,ErrInvalidScanQueueRequest){t.Fatalf("invalid job ID accepted: %v",err)}
 })}
}
