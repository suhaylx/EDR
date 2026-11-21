package edr
import ("context";"errors";"testing")
func TestBE066To070QueueUnavailableFailsClosed(t *testing.T){
 ctx:=context.Background()
 q:=PostgresScanJobQueue{}
 t.Run("BE066 claim without database",func(t *testing.T){
  _,err:=q.Claim(ctx,"tenantA","win01","win01",leaseUUID,30)
  if !errors.Is(err,ErrScanQueueUnavailable){t.Fatalf("claim: %v",err)}
 })
 t.Run("BE067 renew without database",func(t *testing.T){
  ok,err:=q.Renew(ctx,"tenantA","win01",testUUID,"win01",leaseUUID,30)
  if ok||!errors.Is(err,ErrScanQueueUnavailable){t.Fatalf("renew: %v %v",ok,err)}
 })
 t.Run("BE068 complete without database",func(t *testing.T){
  ok,err:=q.Complete(ctx,"tenantA","win01",testUUID,leaseUUID,true)
  if ok||!errors.Is(err,ErrScanQueueUnavailable){t.Fatalf("complete: %v %v",ok,err)}
 })
 t.Run("BE069 recovery without database",func(t *testing.T){
  n,err:=q.RecoverExpired(ctx,10)
  if n!=0||!errors.Is(err,ErrScanQueueUnavailable){t.Fatalf("recover: %d %v",n,err)}
 })
 t.Run("BE070 recovery rejects excessive batch",func(t *testing.T){
  _,err:=q.RecoverExpired(ctx,1001)
  if !errors.Is(err,ErrInvalidScanQueueRequest){t.Fatalf("batch: %v",err)}
 })
}
