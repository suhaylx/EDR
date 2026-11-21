package edr
import ("context";"errors";"strings";"testing")
func TestBE056To060RejectInvalidTenantScope(t *testing.T){
 cases:=[]struct{name,tenant string}{
 {"BE056 missing tenant",""},
 {"BE057 tenant path separator","tenant/A"},
 {"BE058 tenant parent traversal",".."},
 {"BE059 tenant newline","tenant\nA"},
 {"BE060 oversized tenant",strings.Repeat("t",257)},
 }
 for _,tc:=range cases{t.Run(tc.name,func(t *testing.T){
 _,err:=(PostgresScanJobQueue{}).Renew(context.Background(),tc.tenant,"win01",testUUID,"win01",leaseUUID,30)
 if !errors.Is(err,ErrInvalidScanQueueRequest){t.Fatalf("invalid tenant accepted: %v",err)}
 })}
}
