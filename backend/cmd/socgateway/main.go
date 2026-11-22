// socgateway provides HTTPS password login for the local Docker lab.
// The upstream SOC stays independently mTLS-authenticated; endpoints remain mTLS-only.
package main

import (
 "archive/zip"
 "crypto/rand"
 "crypto/sha256"
 "crypto/subtle"
 "crypto/tls"
 "crypto/x509"
 "crypto/pbkdf2"
 "encoding/hex"
 "encoding/json"
 "errors"
 "flag"
 "fmt"
 "io"
 "net"
 "net/http"
 "net/http/httputil"
 "net/url"
 "os"
 "path/filepath"
 "regexp"
 "strings"
 "sync"
 "time"
)

const cookieName="__Host-turansec-soc"
const sessionTTL=6*time.Hour
const passwordRounds=600000
var safeID=regexp.MustCompile("^[A-Za-z0-9_.-]{1,96}$")

type config struct {
 Listen string `json:"listen"`
 Upstream string `json:"upstream"`
 ServerCert string `json:"server_cert"`
 ServerKey string `json:"server_key"`
 ServerCA string `json:"server_ca"`
 OperatorDir string `json:"operator_dir"`
 UsersFile string `json:"users_file"`
 PayloadDir string `json:"payload_dir"`
}
type account struct {
 Username string `json:"username"`
 Role string `json:"role"`
 Salt string `json:"salt"`
 Hash string `json:"hash"`
 Iterations int `json:"iterations"`
}
type accountFile struct{ Users []account `json:"users"` }
type session struct{ username,role,csrf string; expires time.Time }
type attempts struct{ count int; until time.Time }
type gateway struct{
 cfg config
 users map[string]account
 sessions map[string]session
 failures map[string]attempts
 mu sync.Mutex
 proxy map[string]*httputil.ReverseProxy
}

func regular(path string, private bool, limit int64)([]byte,error){
 if !filepath.IsAbs(path){return nil,errors.New("absolute file required")}
 info,err:=os.Lstat(path)
 if err!=nil||!info.Mode().IsRegular()||info.Size()<1||info.Size()>limit{return nil,errors.New("missing, nonregular or oversized config")}
 if private && info.Mode().Perm()&0077!=0 {return nil,errors.New("secret permissions too broad")}
 f,err:=os.Open(path);if err!=nil{return nil,errors.New("config file unreadable")};defer f.Close()
 opened,e:=f.Stat();if e!=nil||!os.SameFile(info,opened){return nil,errors.New("config changed while opening")}
 b,e:=io.ReadAll(io.LimitReader(f,limit+1));if e!=nil||len(b)==0||int64(len(b))>limit{return nil,errors.New("bad config size")};return b,nil
}
func randomHex()(string,error){ b:=make([]byte,32);if _,e:=rand.Read(b);e!=nil{return "",e};return hex.EncodeToString(b),nil }
func newGateway(c config)(*gateway,error){
 if c.Listen!="127.0.0.1:9444"||c.Upstream!="https://127.0.0.1:9445" {return nil,errors.New("gateway addresses must be the protected lab loopback listeners")}
 for _,p:=range []string{c.OperatorDir,c.PayloadDir}{if !filepath.IsAbs(p){return nil,errors.New("gateway directories must be absolute")}}
 raw,e:=regular(c.UsersFile,true,32768);if e!=nil{return nil,e}
 var af accountFile
 if e=json.Unmarshal(raw,&af);e!=nil{return nil,errors.New("malformed password account file")}
 if len(af.Users)!=3{return nil,errors.New("exactly three operator accounts required")}
 g:=&gateway{cfg:c,users:map[string]account{},sessions:map[string]session{},failures:map[string]attempts{},proxy:map[string]*httputil.ReverseProxy{}}
 for _,a:=range af.Users{
  if (a.Username!="admin"&&a.Username!="analyst"&&a.Username!="viewer")||a.Role!=a.Username||a.Iterations!=passwordRounds{return nil,errors.New("invalid role or password cost")}
  salt,e1:=hex.DecodeString(a.Salt);hash,e2:=hex.DecodeString(a.Hash)
  if e1!=nil||e2!=nil||len(salt)!=16||len(hash)!=32||g.users[a.Username].Username!=""{return nil,errors.New("invalid or duplicate password hash")}
  g.users[a.Username]=a
 }
 target,_:=url.Parse(c.Upstream)
 ca,e:=regular(c.ServerCA,false,1<<20);if e!=nil{return nil,e}
 roots:=x509.NewCertPool();if !roots.AppendCertsFromPEM(ca){return nil,errors.New("invalid backend CA")}
 for _,user:=range []string{"admin","analyst","viewer"}{
  cert,e:=tls.LoadX509KeyPair(filepath.Join(c.OperatorDir,user+".pem"),filepath.Join(c.OperatorDir,user+".key"))
  if e!=nil{return nil,errors.New("invalid enrolled operator cert/key")}
  upstreamTLS:=&tls.Config{MinVersion:tls.VersionTLS13,RootCAs:roots,Certificates:[]tls.Certificate{cert}}
  transport:=&http.Transport{TLSClientConfig:upstreamTLS,Proxy:nil,MaxIdleConns:12,IdleConnTimeout:20*time.Second,ResponseHeaderTimeout:15*time.Second,ForceAttemptHTTP2:false}
  rp:=httputil.NewSingleHostReverseProxy(target)
  rp.Transport=transport
  rp.Rewrite=func(pr *httputil.ProxyRequest){
   pr.SetURL(target)
   pr.Out.Host=target.Host
   pr.Out.Header.Del("Origin")
   pr.Out.Header.Del("Cookie")
   pr.Out.Header.Del("Authorization")
   pr.Out.Header.Del("X-TuranSec-CSRF")
   pr.Out.Header.Del("X-Forwarded-For")
   pr.Out.Header.Del("X-Forwarded-Host")
   pr.Out.Header.Del("X-Forwarded-Proto")
  }
  rp.ErrorHandler=func(w http.ResponseWriter,_ *http.Request,_ error){http.Error(w,"upstream unavailable",502)}
  g.proxy[user]=rp
 }
 return g,nil
}
func (g *gateway) current(r *http.Request)(session,bool){
 cookie,e:=r.Cookie(cookieName);if e!=nil||len(cookie.Value)!=64{return session{},false}
 if _,e=hex.DecodeString(cookie.Value);e!=nil{return session{},false}
 g.mu.Lock();defer g.mu.Unlock()
 s,ok:=g.sessions[cookie.Value]
 if !ok||time.Now().After(s.expires){delete(g.sessions,cookie.Value);return session{},false}
 return s,true
}
func setSessionCookie(w http.ResponseWriter, token string, age int){
 http.SetCookie(w,&http.Cookie{Name:cookieName,Value:token,Path:"/",HttpOnly:true,Secure:true,SameSite:http.SameSiteStrictMode,MaxAge:age})
}
func deny(w http.ResponseWriter,status int){http.Error(w,http.StatusText(status),status)}
func (g *gateway) csrfAndOrigin(r *http.Request,s session)bool{
 if r.Header.Get("Origin")!="https://"+r.Host{return false}
 site:=r.Header.Get("Sec-Fetch-Site")
 if site!=""&&site!="same-origin"&&site!="none"{return false}
 return s.csrf!=""&&subtle.ConstantTimeCompare([]byte(r.Header.Get("X-TuranSec-CSRF")),[]byte(s.csrf))==1
}
func (g *gateway) postOrigin(r *http.Request)bool{
 site:=r.Header.Get("Sec-Fetch-Site")
 return r.Header.Get("Origin")=="https://"+r.Host&&(site==""||site=="same-origin"||site=="none")
}
func readJSON(r *http.Request, max int64, into any)error{
 if r.Header.Get("Content-Type")!="application/json"{return errors.New("JSON content required")}
 d:=json.NewDecoder(io.LimitReader(r.Body,max+1));d.DisallowUnknownFields()
 if e:=d.Decode(into);e!=nil{return e}
 var extra any;if e:=d.Decode(&extra);e!=io.EOF{return errors.New("unexpected JSON")}
 return nil
}
func (g *gateway) login(w http.ResponseWriter,r *http.Request){
 if r.Method!="POST"||!g.postOrigin(r){deny(w,403);return}
 var input struct{Username string `json:"username"`;Password string `json:"password"`}
 if readJSON(r,4096,&input)!=nil||len(input.Password)<1||len(input.Password)>256||len(input.Username)>96{deny(w,400);return}
 ip,_,_:=net.SplitHostPort(r.RemoteAddr)
 bucket:=input.Username+"|"+ip
 g.mu.Lock()
 state:=g.failures[bucket]
 blocked:=state.count>=5&&time.Now().Before(state.until)
 g.mu.Unlock()
 if blocked{deny(w,429);return}
 a,known:=g.users[input.Username]
 // The unknown-user path uses the same nonzero KDF cost.
 salt,_:=hex.DecodeString(a.Salt);expected,_:=hex.DecodeString(a.Hash)
 if !known {salt=make([]byte,16);expected=make([]byte,32)}
 derived,e:=pbkdf2.Key(sha256.New,input.Password,salt,passwordRounds,32)
 if e!=nil{deny(w,503);return}
 if !known||subtle.ConstantTimeCompare(expected,derived)!=1{
  g.mu.Lock();s:=g.failures[bucket];s.count++;if s.count>=5{s.until=time.Now().Add(2*time.Minute)};g.failures[bucket]=s;g.mu.Unlock()
  deny(w,401);return
 }
 token,e:=randomHex();if e!=nil{deny(w,503);return}
 csrf,e:=randomHex();if e!=nil{deny(w,503);return}
 g.mu.Lock()
 delete(g.failures,bucket)
 if len(g.sessions)>2048{for k,v:=range g.sessions{if time.Now().After(v.expires){delete(g.sessions,k)}}}
 if len(g.sessions)>=2048{g.mu.Unlock();deny(w,503);return}
 g.sessions[token]=session{username:a.Username,role:a.Role,csrf:csrf,expires:time.Now().Add(sessionTTL)}
 g.mu.Unlock()
 setSessionCookie(w,token,int(sessionTTL.Seconds()))
 w.Header().Set("Content-Type","application/json")
 w.WriteHeader(200);_ = json.NewEncoder(w).Encode(map[string]string{"username":a.Username,"role":a.Role,"csrf_token":csrf})
}
func (g *gateway) logout(w http.ResponseWriter,r *http.Request){
 s,ok:=g.current(r);if r.Method!="POST"||!ok||!g.csrfAndOrigin(r,s){deny(w,403);return}
 cookie,_:=r.Cookie(cookieName)
 g.mu.Lock();delete(g.sessions,cookie.Value);g.mu.Unlock()
 setSessionCookie(w,"", -1);w.WriteHeader(204)
}
func (g *gateway) handleAuth(w http.ResponseWriter,r *http.Request)bool{
 if r.URL.Path=="/auth/login"{g.login(w,r);return true}
 s,ok:=g.current(r)
 if r.URL.Path=="/auth/session"{
  if r.Method!="GET"{deny(w,405);return true}
  if !ok{deny(w,401);return true}
  w.Header().Set("Content-Type","application/json")
  _=json.NewEncoder(w).Encode(map[string]string{"username":s.username,"role":s.role,"csrf_token":s.csrf})
  return true
 }
 if r.URL.Path=="/auth/logout"{g.logout(w,r);return true}
 if strings.HasPrefix(r.URL.Path,"/auth/agent-"){
  if !ok{deny(w,401);return true}
  if s.role!="admin"{deny(w,403);return true}
  if r.URL.Path=="/auth/agent-platforms"&&r.Method=="GET"{
   w.Header().Set("Content-Type","application/json")
   _=json.NewEncoder(w).Encode(map[string]bool{"windows":g.payloadReady("windows"),"linux":g.payloadReady("linux")})
   return true
  }
  if r.URL.Path=="/auth/agent-generate"&&r.Method=="POST"{
   if !g.csrfAndOrigin(r,s){deny(w,403);return true}
   g.generate(w,r);return true
  }
  deny(w,404);return true
 }
 return false
}
func (g *gateway) ServeHTTP(w http.ResponseWriter,r *http.Request){
 w.Header().Set("Cache-Control","no-store")
 w.Header().Set("X-Content-Type-Options","nosniff")
 w.Header().Set("Referrer-Policy","no-referrer")
 w.Header().Set("X-Frame-Options","DENY")
 if r.TLS==nil||r.TLS.Version<tls.VersionTLS13 {deny(w,403);return}
 if r.URL.RawPath!=""||r.URL.EscapedPath()!=r.URL.Path||r.URL.RawQuery!=""{
  // Auth and SOC endpoints expect well-formed URLs; normal read API paging has queries.
  if !strings.HasPrefix(r.URL.Path,"/soc/v1/")||r.URL.RawPath!=""||r.URL.EscapedPath()!=r.URL.Path{deny(w,404);return}
 }
 if strings.HasPrefix(r.URL.Path,"/auth/"){if g.handleAuth(w,r){return};deny(w,404);return}
 public:=r.URL.Path=="/"||r.URL.Path=="/soc/"||strings.HasPrefix(r.URL.Path,"/assets/")
 private:=strings.HasPrefix(r.URL.Path,"/soc/v1/")
 if !public&&!private{deny(w,404);return}
 if public && r.Method!="GET"&&r.Method!="HEAD"{deny(w,405);return}
 s,ok:=g.current(r)
 if !public&&!ok{deny(w,401);return}
 if r.Method!="GET"&&r.Method!="HEAD"&&r.Method!="POST"{deny(w,405);return}
 if r.Method=="POST"&&(!ok||!g.csrfAndOrigin(r,s)){deny(w,403);return}
 user:="viewer"
 if ok{user=s.username}
 g.proxy[user].ServeHTTP(w,r)
}
func (g *gateway) payloadReady(platform string)bool{
 _,e:=g.payload(platform);return e==nil
}
type artifact struct{Name string `json:"name"`;SHA256 string `json:"sha256"`}
type manifest struct{Files []artifact `json:"files"`}
func requiredAssets(platform string)[]string{
 if platform=="windows"{return []string{"TuranSec-Agent-Setup.exe","ClamAV.zip","Sysmon64.exe"}}
 if platform=="linux"{return []string{"TuranSec-Agent-Setup","ClamAV.deb","SysmonForLinux.deb"}}
 return nil
}
func (g *gateway) payload(platform string)([]string,error){
 required:=requiredAssets(platform)
 if required==nil{return nil,errors.New("unsupported platform")}
 directory:=filepath.Join(g.cfg.PayloadDir,platform)
 raw,e:=regular(filepath.Join(directory,"approved.json"),false,16384);if e!=nil{return nil,e}
 var m manifest;if json.Unmarshal(raw,&m)!=nil||len(m.Files)!=len(required){return nil,errors.New("missing approved manifest")}
 out:=make([]string,0,len(required))
 for _,name:=range required{
  match:=""
  for _,item:=range m.Files{if item.Name==name{match=item.SHA256}}
  if len(match)!=64{return nil,errors.New("missing pinned sha")}
  data,e:=regular(filepath.Join(directory,name),false,300<<20);if e!=nil{return nil,e}
  sum:=sha256.Sum256(data)
  if !strings.EqualFold(hex.EncodeToString(sum[:]),match){return nil,errors.New("vendor payload mismatch")}
  out=append(out,filepath.Join(directory,name))
 }
 return out,nil
}
func (g *gateway) generate(w http.ResponseWriter,r *http.Request){
 var input struct{Platform string `json:"platform"`;TenantID string `json:"tenant_id"`;AgentID string `json:"agent_id"`}
 if readJSON(r,1024,&input)!=nil||input.TenantID!="lab"||!safeID.MatchString(input.AgentID)||input.AgentID=="."||input.AgentID==".."{deny(w,400);return}
 paths,e:=g.payload(input.Platform);if e!=nil{deny(w,503);return}
 w.Header().Set("Content-Type","application/zip")
 w.Header().Set("Content-Disposition",fmt.Sprintf("attachment; filename=%q","TuranSec-"+input.Platform+"-"+input.AgentID+".zip"))
 w.WriteHeader(200)
 writer:=zip.NewWriter(w)
 meta,_:=writer.Create("enrollment.json")
 _=json.NewEncoder(meta).Encode(map[string]any{"tenant_id":input.TenantID,"agent_id":input.AgentID,"platform":input.Platform,
  "agent_enrollment_required":true,"approved_publisher_verification_required":true,
  "credential_material_not_embedded":true})
 for _,path:=range paths{
  f,e:=os.Open(path);if e!=nil{break}
  entry,e:=writer.Create(filepath.Base(path));if e==nil{_,_=io.Copy(entry,f)};_ = f.Close()
 }
 _=writer.Close()
}
func main(){
 path:=flag.String("config","","absolute gateway config path");flag.Parse()
 if *path==""||flag.NArg()!=0{fmt.Fprintln(os.Stderr,"usage: socgateway --config /absolute/gateway.json");os.Exit(2)}
 raw,e:=regular(*path,true,16384);if e!=nil{fmt.Fprintln(os.Stderr,"gateway configuration unavailable");os.Exit(1)}
 var c config
 if json.Unmarshal(raw,&c)!=nil{fmt.Fprintln(os.Stderr,"invalid gateway configuration");os.Exit(1)}
 g,e:=newGateway(c);if e!=nil{fmt.Fprintln(os.Stderr,"gateway configuration or certificate invalid:",e);os.Exit(1)}
 server:=&http.Server{Addr:c.Listen,Handler:g,ReadHeaderTimeout:5*time.Second,ReadTimeout:20*time.Second,WriteTimeout:120*time.Second,IdleTimeout:45*time.Second,MaxHeaderBytes:16384,
  TLSConfig:&tls.Config{MinVersion:tls.VersionTLS13,ClientAuth:tls.NoClientCert}}
 fmt.Println("TuranSec SOC password gateway started (loopback HTTPS, endpoint mTLS unchanged)")
 if e=server.ListenAndServeTLS(c.ServerCert,c.ServerKey);e!=nil{fmt.Fprintln(os.Stderr,"gateway HTTPS stopped");os.Exit(1)}
}
