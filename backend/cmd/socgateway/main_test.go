package main

import (
 "archive/zip"
 "bytes"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "io"
 "net/http"
 "net/http/httptest"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func packageRequest(t *testing.T,g *gateway,platform,agent,bundleType string)*httptest.ResponseRecorder{
 t.Helper()
 body,_:=json.Marshal(map[string]string{"tenant_id":"lab","platform":platform,"agent_id":agent,"bundle_type":bundleType})
 req:=httptest.NewRequest(http.MethodPost,"/auth/agent-generate",bytes.NewReader(body))
 req.Header.Set("Content-Type","application/json")
 result:=httptest.NewRecorder()
 g.generate(result,req)
 return result
}
func openBundle(t *testing.T,data []byte)map[string][]byte{
 t.Helper()
 archive,err:=zip.NewReader(bytes.NewReader(data),int64(len(data)))
 if err!=nil{t.Fatal(err)}
 out:=make(map[string][]byte)
 for _,file:=range archive.File{
  r,err:=file.Open();if err!=nil{t.Fatal(err)}
  buf,err:=io.ReadAll(r)
  if err!=nil{t.Fatal(err)}
  _=r.Close()
  if file.UncompressedSize64>0&&len(buf)==0{t.Fatalf("empty file %s",file.Name)}
  out[file.Name]=buf
 }
 return out
}
func TestSetupKitsWorkWithoutVendorBinaries(t *testing.T){
 g:=&gateway{cfg:config{PayloadDir:t.TempDir()}}
 for _,platform:=range []string{"windows","linux"}{
  t.Run(platform,func(t *testing.T){
   response:=packageRequest(t,g,platform,"agent001","setup_kit")
   if response.Code!=200{t.Fatalf("expected ZIP, got %d",response.Code)}
   if response.Header().Get("X-TuranSec-Bundle-Type")!="setup_kit"{t.Fatal("bundle type header")}
   files:=openBundle(t,response.Body.Bytes())
   script:="install-turansec.sh";if platform=="windows"{script="Install-TuranSec.ps1"}
   if len(files)!=4{t.Fatalf("unexpected files: %v",files)}
   for _,name:=range []string{"enrollment.json","README-FIRST.txt","REQUIRED-COMPONENTS.txt",script}{
    if _,ok:=files[name];!ok{t.Fatalf("missing %s",name)}
   }
   var meta map[string]any
   if err:=json.Unmarshal(files["enrollment.json"],&meta);err!=nil{t.Fatal(err)}
   if meta["agent_id"]!="agent001"||meta["bundle_type"]!="setup_kit"||meta["components_included"]!=false{
    t.Fatalf("incorrect setup-kit metadata: %v",meta)
   }
   if !strings.Contains(string(files["README-FIRST.txt"]),"NOT AN INSTALLABLE AGENT"){
    t.Fatal("missing noninstallable warning")
   }
   for name:=range files{
    if strings.HasSuffix(name,".pem")||strings.HasSuffix(name,".key")||strings.HasSuffix(name,".p12"){
     t.Fatalf("private material in kit: %s",name)
    }
   }
   full:=packageRequest(t,g,platform,"agent001","complete")
   if full.Code!=http.StatusServiceUnavailable{t.Fatalf("unapproved full package returned %d",full.Code)}
  })
 }
}
func TestCompleteBundleRequiresThreeValidPins(t *testing.T){
 root:=t.TempDir()
 g:=&gateway{cfg:config{PayloadDir:root}}
 platform:="linux"
 directory:=filepath.Join(root,platform)
 if e:=os.MkdirAll(directory,0700);e!=nil{t.Fatal(e)}
 records:=make([]artifact,0,3)
 for _,name:=range requiredAssets(platform){
  data:=[]byte("SYNTHETIC-QA-ONLY-"+name)
  if e:=os.WriteFile(filepath.Join(directory,name),data,0600);e!=nil{t.Fatal(e)}
  sha:=sha256.Sum256(data)
  records=append(records,artifact{Name:name,SHA256:hex.EncodeToString(sha[:])})
 }
 manifestBytes,_:=json.Marshal(manifest{Files:records})
 if e:=os.WriteFile(filepath.Join(directory,"approved.json"),manifestBytes,0600);e!=nil{t.Fatal(e)}
 response:=packageRequest(t,g,platform,"linux001","complete")
 if response.Code!=200{t.Fatalf("full bundle failed %d",response.Code)}
 files:=openBundle(t,response.Body.Bytes())
 if len(files)!=8{t.Fatalf("full ZIP should have 8 files: %v",files)}
 var meta map[string]any
 if e:=json.Unmarshal(files["enrollment.json"],&meta);e!=nil{t.Fatal(e)}
 if meta["components_included"]!=true || meta["bundle_type"]!="complete"{t.Fatal("incorrect complete metadata")}
 if files["approved.json"]==nil || files["TuranSec-Agent-Setup"]==nil || files["SysmonForLinux.deb"]==nil{
  t.Fatal("missing full-payload content")
 }
 if e:=os.WriteFile(filepath.Join(directory,"SysmonForLinux.deb"),[]byte("TAMPERED"),0600);e!=nil{t.Fatal(e)}
 fail:=packageRequest(t,g,platform,"linux001","complete")
 if fail.Code!=503{t.Fatalf("tampered full bundle returned %d",fail.Code)}
 // The preparation workflow must remain usable on an incomplete lab.
 kit:=packageRequest(t,g,platform,"linux001","setup_kit")
 if kit.Code!=200{t.Fatalf("kit blocked by invalid payload: %d",kit.Code)}
}
func TestAgentGeneratorInputAndReadiness(t *testing.T){
 g:=&gateway{cfg:config{PayloadDir:t.TempDir()}}
 for _,args:=range []struct{platform,id,typ string}{
  {"windows","../escape","setup_kit"},{"linux","..","setup_kit"},
  {"freebsd","valid","setup_kit"},{"windows","valid","unknown"},
 }{
  if got:=packageRequest(t,g,args.platform,args.id,args.typ);got.Code!=400{
   t.Fatalf("%v: expected bad request got %d",args,got.Code)
  }
 }
 status:=g.platformReadiness()
 if status["windows"]!=false||status["linux"]!=false||status["setup_kit"]!=true{
  t.Fatalf("incorrect readiness: %v",status)
 }
 missing:=status["missing"].(map[string][]string)
 if len(missing["windows"])!=4||len(missing["linux"])!=4{
  t.Fatalf("readiness omitted blocked components: %v",missing)
 }
}
