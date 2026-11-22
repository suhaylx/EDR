package edr
import ("context";"errors";"strings";"testing")
func TestBE051To055RejectInvalidRenewalWorker(t *testing.T){
 cases:=[]struct{name,owner string}{
 {"BE051 empty worker",""},
 {"BE052 whitespace-only worker","   "},
 {"BE053 oversized worker",strings.Repeat("x",257)},
 {"BE054 newline-only worker","\n"},
 {"BE055 tab-only worker","\t"},
 }
 for _,tc:=range cases{t.Run(tc.name,func(t *testing.T){
 _,err:=(PostgresScanJobQueue{}).Renew(context.Background(),"tenantA","win01",testUUID,tc.owner,leaseUUID,30)
 if !errors.Is(err,ErrInvalidScanQueueRequest){t.Fatalf("invalid worker accepted: %v",err)}
 })}
}
