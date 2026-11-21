package edr

import (
 "context"
 "crypto/sha256"
 "crypto/subtle"
 "crypto/tls"
 "crypto/x509"
 "database/sql"
 "errors"
 "net/http"
 "net/url"
 "strings"
 "time"
)

type SOCOperatorPrincipal struct {
 TenantID string
 OperatorID string
 Role string // viewer or scanner, supplied only by database registry
}
type socOperatorContextKey struct{}
func socPrincipal(ctx context.Context)(SOCOperatorPrincipal,bool){
 p,ok:=ctx.Value(socOperatorContextKey{}).(SOCOperatorPrincipal)
 return p,ok&&validQueueIdentity(p.TenantID,p.OperatorID)&&
  (p.Role=="viewer"||p.Role=="scanner")
}
func parseSOCOperatorSAN(u *url.URL)(tenant,operator string,ok bool){
 if u==nil||u.Scheme!="spiffe"||u.Host!="turansec.local"||
  u.User!=nil||u.RawQuery!=""||u.Fragment!=""||u.Opaque!=""||u.RawPath!=""{
  return "","",false
 }
 parts:=strings.Split(u.Path,"/")
 if len(parts)!=5||parts[0]!=""||parts[1]!="tenants"||parts[3]!="operators"||
  !validQueueIdentity(parts[2],parts[4]){return "","",false}
 return parts[2],parts[4],true
}
func socTenantRoute(u *url.URL)(string,bool){
 if u==nil||u.RawPath!=""||u.EscapedPath()!=u.Path{return "",false}
 parts:=strings.Split(u.Path,"/")
 if len(parts)<6||parts[0]!=""||parts[1]!="soc"||parts[2]!="v1"||
  parts[3]!="tenants"||!validID(parts[4])||
  parts[4]=="."||parts[4]==".."||parts[5]==""{return "",false}
 for _,part:=range parts[5:]{
  if part==""||part=="."||part==".."{return "",false}
 }
 return parts[4],true
}
var errSOCNotAuthorized=errors.New("SOC operator not authorized")
var errSOCRegistryUnavailable=errors.New("SOC operator registry unavailable")
const socOperatorLookupSQL=`SELECT o.fingerprint_sha256,o.role
FROM edr_soc_operators AS o JOIN edr_tenants AS t
ON t.tenant_id=o.tenant_id
WHERE o.tenant_id=$1 AND o.operator_id=$2
AND o.revoked_at IS NULL AND t.disabled_at IS NULL`
func verifySOCOperator(ctx context.Context,st *tls.ConnectionState,db *sql.DB,
 now time.Time)(SOCOperatorPrincipal,error){
 var deny SOCOperatorPrincipal
 if st==nil||st.Version!=tls.VersionTLS13||db==nil||
  len(st.PeerCertificates)==0||len(st.VerifiedChains)==0||
  len(st.VerifiedChains[0])==0||st.VerifiedChains[0][0]==nil{
  return deny,errSOCNotAuthorized
 }
 cert:=st.PeerCertificates[0]
 if cert==nil||cert.IsCA||len(cert.Raw)==0||
  now.Before(cert.NotBefore)||!now.Before(cert.NotAfter)||
  cert.KeyUsage&x509.KeyUsageDigitalSignature==0||
  !hasClientAuthenticationEKU(cert)||
  len(st.VerifiedChains[0][0].Raw)==0||
  subtle.ConstantTimeCompare(cert.Raw,st.VerifiedChains[0][0].Raw)!=1||
  len(cert.URIs)!=1 {return deny,errSOCNotAuthorized}
 tenant,operator,ok:=parseSOCOperatorSAN(cert.URIs[0])
 if !ok{return deny,errSOCNotAuthorized}
 var fingerprint []byte
 var role string
 err:=db.QueryRowContext(ctx,socOperatorLookupSQL,tenant,operator).Scan(&fingerprint,&role)
 if errors.Is(err,sql.ErrNoRows){return deny,errSOCNotAuthorized}
 if err!=nil{return deny,errSOCRegistryUnavailable}
 digest:=sha256.Sum256(cert.Raw)
 if len(fingerprint)!=32||subtle.ConstantTimeCompare(fingerprint,digest[:])!=1||
  (role!="viewer"&&role!="scanner"){return deny,errSOCNotAuthorized}
 return SOCOperatorPrincipal{TenantID:tenant,OperatorID:operator,Role:role},nil
}

// SOCOperatorHTTPGuard must only be mounted on a TLS 1.3 listener that
// requires VERIFIED client certs from a separately controlled SOC operator CA.
func SOCOperatorHTTPGuard(db *sql.DB,next http.Handler)http.Handler{
 return http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  w.Header().Set("Cache-Control","no-store")
  p,err:=verifySOCOperator(r.Context(),r.TLS,db,time.Now().UTC())
  if err!=nil {
   code:=http.StatusUnauthorized
   if errors.Is(err,errSOCRegistryUnavailable){code=http.StatusServiceUnavailable}
   http.Error(w,http.StatusText(code),code);return
  }
  tenant,ok:=socTenantRoute(r.URL)
  if !ok {http.NotFound(w,r);return}
  if tenant!=p.TenantID {http.Error(w,"forbidden",http.StatusForbidden);return}
  next.ServeHTTP(w,r.WithContext(context.WithValue(r.Context(),socOperatorContextKey{},p)))
 })
}

// NewSOCMTLSServer is independent of agent and dev-bearer listeners.
// The caller must provision an operator CA, known server cert and database;
// this constructor does not start a listener or enroll operators.
func NewSOCMTLSServer(addr string,db *sql.DB,serverCert tls.Certificate,
 operatorCAs *x509.CertPool)(*http.Server,error){
 // Share the same reviewed TLS/address/keypair limits. The returned listener
 // has its own operator CA and handler; no agent route is mounted here.
 server,err:=NewAgentMTLSServer(addr,db,serverCert,operatorCAs)
 if err!=nil{return nil,errors.New("SOC mTLS requires explicit loopback address, database, valid server keypair and nonempty operator CA")}
 server.Handler=SOCOperatorHTTPGuard(db,SOCScanHandler(PostgresScanJobQueue{DB:db}))
 return server,nil
}
