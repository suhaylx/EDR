package edr

import (
 "bytes"
 "context"
 "crypto/sha256"
 "crypto/tls"
 "crypto/x509"
 "database/sql"
 "database/sql/driver"
 "errors"
 "io"
 "net/http"
 "net/http/httptest"
 "strings"
 "sync/atomic"
 "testing"
 "time"
)

type securityTxState struct {
 allow bool
 queryError error
 commitError error
 begin atomic.Int32
 commit atomic.Int32
 rollback atomic.Int32
 next atomic.Int32
 sink *securitySink
 beforeCommitExposed atomic.Bool
 args []driver.NamedValue
 authDelay time.Duration
}
type securityConnector struct{ s *securityTxState }
func(c securityConnector)Connect(context.Context)(driver.Conn,error){return securityConn{c.s},nil}
func(c securityConnector)Driver()driver.Driver{return securityDriver{c.s}}
type securityDriver struct{ s *securityTxState }
func(d securityDriver)Open(string)(driver.Conn,error){return securityConn{d.s},nil}
type securityConn struct{ s *securityTxState }
func(c securityConn)Prepare(string)(driver.Stmt,error){return nil,errors.New("unexpected prepare")}
func(c securityConn)Close()error{return nil}
func(c securityConn)Begin()(driver.Tx,error){c.s.begin.Add(1);return securityTx{c.s},nil}
func(c securityConn)BeginTx(context.Context,driver.TxOptions)(driver.Tx,error){return c.Begin()}
func(c securityConn)QueryContext(_ context.Context,_ string,args []driver.NamedValue)(driver.Rows,error){
 c.s.args=args
 if c.s.authDelay>0{time.Sleep(c.s.authDelay)}
 if c.s.queryError!=nil{return nil,c.s.queryError}
 return &securityRows{allow:c.s.allow},nil
}
type securityTx struct{ s *securityTxState }
func(t securityTx)Commit()error{
 t.s.commit.Add(1)
 if t.s.sink.status!=0||t.s.sink.body.Len()!=0{t.s.beforeCommitExposed.Store(true)}
 return t.s.commitError
}
func(t securityTx)Rollback()error{t.s.rollback.Add(1);return nil}
type securityRows struct{allow bool; read bool}
func(r *securityRows)Columns()[]string{return []string{"authorized"}}
func(r *securityRows)Close()error{return nil}
func(r *securityRows)Next(v []driver.Value)error{if r.read{return io.EOF};r.read=true;v[0]=r.allow;return nil}
type securitySink struct{header http.Header; status int; body bytes.Buffer}
func(s *securitySink)Header()http.Header{return s.header}
func(s *securitySink)WriteHeader(v int){if s.status==0{s.status=v}}
func(s *securitySink)Write(b []byte)(int,error){if s.status==0{s.status=200};return s.body.Write(b)}

func TestIndependentCertificateTransactionNoUncommittedSuccess(t *testing.T){
 for _,tc:=range []struct{
  name string; allow bool; queryError,commitError error; body string; handlerStatus int; overflow bool
  wantStatus int; wantBegin,wantNext,wantCommit,wantRollback int32
 }{
  {name:"successful commit",allow:true,handlerStatus:201,wantStatus:201,wantBegin:1,wantNext:1,wantCommit:1},
  {name:"commit failure hides lease",allow:true,commitError:errors.New("test commit unavailable"),handlerStatus:201,wantStatus:503,wantBegin:1,wantNext:1,wantCommit:1},
  {name:"denied certificate cannot mutate",allow:false,handlerStatus:201,wantStatus:401,wantBegin:1,wantRollback:1},
  {name:"registry SQL error cannot mutate",queryError:errors.New("test auth unavailable"),handlerStatus:201,wantStatus:503,wantBegin:1,wantRollback:1},
  {name:"handler error rolls back",allow:true,handlerStatus:409,wantStatus:409,wantBegin:1,wantNext:1,wantRollback:1},
  {name:"response overflow rolls back",allow:true,handlerStatus:201,overflow:true,wantStatus:503,wantBegin:1,wantNext:1,wantRollback:1},
  {name:"large request rejected before transaction",allow:true,body:strings.Repeat("x",8193),handlerStatus:201,wantStatus:413},
 }{
  t.Run(tc.name,func(t *testing.T){
   sink:=&securitySink{header:make(http.Header)}
   s:=&securityTxState{allow:tc.allow,queryError:tc.queryError,commitError:tc.commitError,sink:sink}
   db:=sql.OpenDB(securityConnector{s});defer db.Close()
   req:=httptest.NewRequest("POST","https://127.0.0.1/soc/v1/tenants/t/scan-jobs",strings.NewReader(tc.body))
   leaf:=[]byte("independent-test-verified-leaf-placeholder")
   req.TLS=&tls.ConnectionState{PeerCertificates:[]*x509.Certificate{{Raw:leaf,NotBefore:time.Now().Add(-time.Hour),NotAfter:time.Now().Add(time.Hour)}}}
   certificateTransaction(sink,req,db,"SELECT auth($1,$2,$3,$4)",[]any{"tenant-a","operator-a","scanner"},func(tx *sql.Tx)http.Handler{
    return http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
     s.next.Add(1);w.WriteHeader(tc.handlerStatus)
     if tc.overflow{_,_=w.Write([]byte(strings.Repeat("x",65537)))}else if tc.handlerStatus<400{_,_=w.Write([]byte("ephemeral-lease-token"))}else{_,_=w.Write([]byte("rejected"))}
    })
   })
   if sink.status!=tc.wantStatus{t.Fatalf("status=%d want=%d",sink.status,tc.wantStatus)}
   if s.begin.Load()!=tc.wantBegin||s.next.Load()!=tc.wantNext||s.commit.Load()!=tc.wantCommit||s.rollback.Load()!=tc.wantRollback{
    t.Fatalf("transaction lifecycle begin=%d next=%d commit=%d rollback=%d",s.begin.Load(),s.next.Load(),s.commit.Load(),s.rollback.Load())
   }
   if s.beforeCommitExposed.Load(){t.Fatal("success/body escaped before COMMIT")}
   if tc.wantStatus>=400&&strings.Contains(sink.body.String(),"ephemeral-lease-token"){t.Fatal("uncommitted lease token exposed")}
   if tc.wantBegin==1{
    digest:=sha256.Sum256(leaf)
    if len(s.args)!=4||s.args[0].Value!="tenant-a"||s.args[1].Value!="operator-a"||s.args[3].Value!="scanner"||!bytes.Equal(s.args[2].Value.([]byte),digest[:]){t.Fatal("verified certificate argument binding/order changed")}
   }
  })
 }
}

func TestIndependentCertificateTransactionPanicRollsBack(t *testing.T){
 sink:=&securitySink{header:make(http.Header)};s:=&securityTxState{allow:true,sink:sink}
 db:=sql.OpenDB(securityConnector{s});defer db.Close()
 req:=httptest.NewRequest("POST","https://127.0.0.1/",nil)
 req.TLS=&tls.ConnectionState{PeerCertificates:[]*x509.Certificate{{Raw:[]byte("test-leaf"),NotBefore:time.Now().Add(-time.Hour),NotAfter:time.Now().Add(time.Hour)}}}
 func(){defer func(){if recover()==nil{t.Error("fixture panic absent")}}();certificateTransaction(sink,req,db,"SELECT auth($1,$2,$3)",[]any{"tenant","agent"},func(*sql.Tx)http.Handler{return http.HandlerFunc(func(http.ResponseWriter,*http.Request){panic("test panic")})})}()
 if s.rollback.Load()!=1||s.commit.Load()!=0||sink.status!=0||sink.body.Len()!=0{t.Fatal("panic failed to rollback without response")}
}
