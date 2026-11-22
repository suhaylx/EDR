package edr
import ("context";"errors";"strings";"testing")
func TestBE061To065RejectInvalidAgentScope(t *testing.T){
 cases:=[]struct{name,agent string}{
 {"BE061 missing device",""},
 {"BE062 device path separator","win/01"},
 {"BE063 device parent traversal",".."},
 {"BE064 device newline","win\n01"},
 {"BE065 oversized device",strings.Repeat("a",257)},
 }
 for _,tc:=range cases{t.Run(tc.name,func(t *testing.T){
 _,err:=(PostgresScanJobQueue{}).Renew(context.Background(),"tenantA",tc.agent,testUUID,"win01",leaseUUID,30)
 if !errors.Is(err,ErrInvalidScanQueueRequest){t.Fatalf("invalid device accepted: %v",err)}
 })}
}
