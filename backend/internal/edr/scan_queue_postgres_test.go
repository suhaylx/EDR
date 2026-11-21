package edr

import (
    "context"
    "database/sql"
    "database/sql/driver"
    "errors"
    "io"
    "strings"
    "testing"
)

type scanDriver struct{ query func(string,[]driver.NamedValue)(driver.Rows,error) }
type scanConn struct{ d *scanDriver }
type scanRows struct{ columns []string; values [][]driver.Value; pos int }
func (r *scanRows)Columns()[]string{return r.columns}
func (r *scanRows)Close()error{return nil}
func (r *scanRows)Next(dest []driver.Value)error{
    if r.pos>=len(r.values){return io.EOF}
    copy(dest,r.values[r.pos]);r.pos++;return nil
}
func (d *scanDriver)Open(string)(driver.Conn,error){return &scanConn{d:d},nil}
func (c *scanConn)Prepare(string)(driver.Stmt,error){return nil,errors.New("not supported")}
func (c *scanConn)Close()error{return nil}
func (c *scanConn)Begin()(driver.Tx,error){return nil,errors.New("not supported")}
func (c *scanConn)QueryContext(_ context.Context,q string,args []driver.NamedValue)(driver.Rows,error){
    return c.d.query(q,args)
}
func scanDB(t *testing.T,fn func(string,[]driver.NamedValue)(driver.Rows,error))*sql.DB{
    t.Helper()
    // sql.OpenDB uses this per-test connector without global driver registration.
    db:=sql.OpenDB(scanConnector{d:&scanDriver{query:fn}})
    t.Cleanup(func(){_ = db.Close()})
    return db
}
type scanConnector struct{d *scanDriver}
func (c scanConnector)Connect(context.Context)(driver.Conn,error){return &scanConn{d:c.d},nil}
func (c scanConnector)Driver()driver.Driver{return c.d}
const testUUID="11111111-1111-4111-8111-111111111111"
const leaseUUID="22222222-2222-4222-8222-222222222222"
func TestPostgresScanQueueClaimScoped(t *testing.T){
    db:=scanDB(t,func(q string,args []driver.NamedValue)(driver.Rows,error){
        if !strings.Contains(q,"edr_claim_scan_job")||len(args)!=5||
            args[0].Value!="tenantA"||args[1].Value!="win01"||
            args[3].Value!=leaseUUID||args[4].Value!=int64(30){
            t.Fatalf("unexpected query or args: %q %#v",q,args)
        }
        return &scanRows{columns:[]string{"job_id","scan_root","attempt_count"},
            values:[][]driver.Value{{testUUID,"C:/Lab",int64(1)}}},nil
    })
    job,err:=(PostgresScanJobQueue{DB:db}).Claim(context.Background(),"tenantA","win01","worker",leaseUUID,30)
    if err!=nil||job==nil||job.JobID!=testUUID||job.AttemptCount!=1{t.Fatalf("claim: %#v %v",job,err)}
}
func TestPostgresScanQueueEmptyAndFailures(t *testing.T){
    db:=scanDB(t,func(q string,args []driver.NamedValue)(driver.Rows,error){
        return &scanRows{columns:[]string{"job_id","scan_root","attempt_count"}},nil
    })
    q:=PostgresScanJobQueue{DB:db}
    job,err:=q.Claim(context.Background(),"tenantA","win01","worker",leaseUUID,30)
    if err!=nil||job!=nil{t.Fatalf("empty queue: %#v %v",job,err)}
    _,err=q.Claim(context.Background(),"../tenant","win01","worker",leaseUUID,30)
    if !errors.Is(err,ErrInvalidScanQueueRequest){t.Fatalf("invalid tenant: %v",err)}
    _,err=q.Claim(context.Background(),"tenantA","win01","worker","bad-token",30)
    if !errors.Is(err,ErrInvalidScanQueueRequest){t.Fatalf("invalid token: %v",err)}
    _,err=(PostgresScanJobQueue{}).Claim(context.Background(),"tenantA","win01","worker",leaseUUID,30)
    if !errors.Is(err,ErrScanQueueUnavailable){t.Fatalf("missing db: %v",err)}
}
func TestPostgresScanQueueCompleteAndRecover(t *testing.T){
    db:=scanDB(t,func(q string,args []driver.NamedValue)(driver.Rows,error){
        if strings.Contains(q,"edr_complete_scan_job"){
            if len(args)!=5||args[0].Value!="tenantA"||args[1].Value!="win01"||args[2].Value!=testUUID||
                args[3].Value!=leaseUUID||args[4].Value!=true{t.Fatalf("bad completion args: %#v",args)}
            return &scanRows{columns:[]string{"ok"},values:[][]driver.Value{{true}}},nil
        }
        if strings.Contains(q,"edr_recover_expired_scan_jobs"){
            return &scanRows{columns:[]string{"count"},values:[][]driver.Value{{int64(2)}}},nil
        }
        t.Fatalf("unexpected query %s",q);return nil,nil
    })
    q:=PostgresScanJobQueue{DB:db}
    ok,err:=q.Complete(context.Background(),"tenantA","win01",testUUID,leaseUUID,true)
    if err!=nil||!ok{t.Fatalf("complete: %v %v",ok,err)}
    n,err:=q.RecoverExpired(context.Background(),10)
    if err!=nil||n!=2{t.Fatalf("recover: %d %v",n,err)}
    _,err=q.RecoverExpired(context.Background(),1001)
    if !errors.Is(err,ErrInvalidScanQueueRequest){t.Fatalf("bad limit: %v",err)}
}
func TestPostgresScanQueueDatabaseError(t *testing.T){
    db:=scanDB(t,func(string,[]driver.NamedValue)(driver.Rows,error){
        return nil,errors.New("secret database error")
    })
    _,err:=(PostgresScanJobQueue{DB:db}).Claim(context.Background(),"tenantA","win01","worker",leaseUUID,30)
    if !errors.Is(err,ErrScanQueueUnavailable)||strings.Contains(err.Error(),"secret"){
        t.Fatalf("must fail closed without leaking SQL errors: %v",err)
    }
}
