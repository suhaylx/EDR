package main

import (
 "context"
 "crypto/ecdsa"
 "crypto/elliptic"
 "crypto/rand"
 "crypto/x509"
 "crypto/x509/pkix"
 "encoding/pem"
 "math/big"
 "net"
 "os"
 "path/filepath"
 "strings"
 "testing"
 "time"
)

func qaWrite(t *testing.T,dir,name string,b []byte) string {t.Helper();p:=filepath.Join(dir,name);if err:=os.WriteFile(p,b,0600);err!=nil{t.Fatal(err)};return p}
func qaCA(t *testing.T,key *ecdsa.PrivateKey,serial int64)(*x509.Certificate,*ecdsa.PrivateKey,[]byte){
 t.Helper();var err error
 if key==nil{key,err=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);if err!=nil{t.Fatal(err)}}
 c:=&x509.Certificate{SerialNumber:big.NewInt(serial),Subject:pkix.Name{CommonName:"QA authority"},NotBefore:time.Now().Add(-time.Hour),NotAfter:time.Now().Add(time.Hour),BasicConstraintsValid:true,IsCA:true,KeyUsage:x509.KeyUsageCertSign|x509.KeyUsageCRLSign}
 der,err:=x509.CreateCertificate(rand.Reader,c,c,key.Public(),key);if err!=nil{t.Fatal(err)}
 parsed,err:=x509.ParseCertificate(der);if err!=nil{t.Fatal(err)}
 return parsed,key,pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:der})
}
func qaConfig(t *testing.T,registry,runtime string,reuseRootKey bool)configuration{
 t.Helper();dir:=t.TempDir()
 ca,key,agentRoot:=qaCA(t,nil,1)
 otherKey:=(*ecdsa.PrivateKey)(nil);if reuseRootKey{otherKey=key}
 _,_,operatorRoot:=qaCA(t,otherKey,2)
 serverKey,err:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);if err!=nil{t.Fatal(err)}
 server:=&x509.Certificate{SerialNumber:big.NewInt(3),NotBefore:time.Now().Add(-time.Hour),NotAfter:time.Now().Add(time.Hour),KeyUsage:x509.KeyUsageDigitalSignature,ExtKeyUsage:[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},IPAddresses:[]net.IP{net.ParseIP("127.0.0.1")}}
 der,err:=x509.CreateCertificate(rand.Reader,server,ca,serverKey.Public(),key);if err!=nil{t.Fatal(err)}
 pk,err:=x509.MarshalPKCS8PrivateKey(serverKey);if err!=nil{t.Fatal(err)}
 port:=func()string{l,e:=net.Listen("tcp","127.0.0.1:0");if e!=nil{t.Fatal(e)};s:=l.Addr().String();l.Close();return s}
 ui:=filepath.Join(dir,"ui");if err:=os.Mkdir(ui,0700);err!=nil{t.Fatal(err)};qaWrite(t,ui,"index.html",[]byte("<main>QA</main>"))
 return configuration{AgentListen:port(),SOCListen:port(),ServerCertFile:qaWrite(t,dir,"server.crt",pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:der})),ServerKeyFile:qaWrite(t,dir,"server.key",pem.EncodeToMemory(&pem.Block{Type:"PRIVATE KEY",Bytes:pk})),AgentCAFile:qaWrite(t,dir,"agent-ca.crt",agentRoot),OperatorCAFile:qaWrite(t,dir,"operator-ca.crt",operatorRoot),RegistryDSNFile:qaWrite(t,dir,"registry.dsn",[]byte(registry)),RuntimeDSNFile:qaWrite(t,dir,"runtime.dsn",[]byte(runtime)),UIDir:ui}
}

func TestQARejectsDifferentPostgresClustersWithSameDatabaseName(t *testing.T){
 if os.Getenv("QA_REGISTRY_DSN")==""{t.Fatal("isolated QA cluster required")}
 c:=qaConfig(t,os.Getenv("QA_REGISTRY_DSN"),os.Getenv("QA_OTHER_RUNTIME_DSN"),false)
 ctx,cancel:=context.WithTimeout(t.Context(),300*time.Millisecond);defer cancel()
 if err:=serve(ctx,c);err==nil||!strings.Contains(err.Error(),"one database"){t.Fatalf("split-cluster configuration was not rejected at the expected boundary: %v",err)}
}
func TestQARejectsDifferentCACertificatesWithSameSigningKey(t *testing.T){
 if os.Getenv("QA_REGISTRY_DSN")==""{t.Fatal("isolated QA cluster required")}
 c:=qaConfig(t,os.Getenv("QA_REGISTRY_DSN"),os.Getenv("QA_RUNTIME_DSN"),true)
 ctx,cancel:=context.WithTimeout(t.Context(),300*time.Millisecond);defer cancel()
 if err:=serve(ctx,c);err==nil||!strings.Contains(err.Error(),"trust roots must be separate"){t.Fatalf("shared signing-key configuration was not rejected at the expected boundary: %v",err)}
}
func TestQARejectsUnmigratedDatabaseBeforeServing(t *testing.T){
 if os.Getenv("QA_REGISTRY_DSN")==""{t.Fatal("isolated QA cluster required")}
 c:=qaConfig(t,os.Getenv("QA_EMPTY_REGISTRY_DSN"),os.Getenv("QA_EMPTY_RUNTIME_DSN"),false)
 ctx,cancel:=context.WithTimeout(t.Context(),300*time.Millisecond);defer cancel()
 if err:=serve(ctx,c);err==nil{t.Fatal("service started even though the database has no EDR tables or functions")}
}

func TestQAValidMigratedStartupControl(t *testing.T){
 c:=qaConfig(t,os.Getenv("QA_REGISTRY_DSN"),os.Getenv("QA_RUNTIME_DSN"),false)
 ctx,cancel:=context.WithTimeout(t.Context(),2*time.Second);defer cancel()
 if err:=serve(ctx,c);err!=nil{t.Fatalf("valid control failed startup: %v",err)}
}

func TestQARejectsMissingLeaseClockCapability(t *testing.T){
 if os.Getenv("QA_OLD_REGISTRY_DSN")==""||os.Getenv("QA_OLD_RUNTIME_DSN")==""{t.Fatal("old-schema fixture missing")}
 c:=qaConfig(t,os.Getenv("QA_OLD_REGISTRY_DSN"),os.Getenv("QA_OLD_RUNTIME_DSN"),false)
 ctx,cancel:=context.WithTimeout(t.Context(),2*time.Second);defer cancel()
 if err:=serve(ctx,c);err==nil||!strings.Contains(err.Error(),"migration"){t.Fatalf("schema without lease-clock capability not rejected at migration check: %v",err)}
}

func TestQARejectsUnsupportedLeaseClockCapability(t *testing.T){
 if os.Getenv("QA_WRONG_REGISTRY_DSN")==""||os.Getenv("QA_WRONG_RUNTIME_DSN")==""{t.Fatal("unsupported-schema fixture missing")}
 c:=qaConfig(t,os.Getenv("QA_WRONG_REGISTRY_DSN"),os.Getenv("QA_WRONG_RUNTIME_DSN"),false)
 ctx,cancel:=context.WithTimeout(t.Context(),2*time.Second);defer cancel()
 if err:=serve(ctx,c);err==nil||!strings.Contains(err.Error(),"migration"){t.Fatalf("unsupported lease-clock capability not rejected at migration check: %v",err)}
}
