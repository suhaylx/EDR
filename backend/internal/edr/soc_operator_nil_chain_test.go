package edr

import (
 "context"
 "crypto/tls"
 "crypto/x509"
 "database/sql"
 "errors"
 "testing"
 "time"
)

// A caller-supplied/incomplete tls.ConnectionState must fail closed without
// ever dereferencing a nil verified-chain element or consulting the database.
func TestQASOCOperatorAuthRejectsMalformedVerifiedChainWithoutPanic(t *testing.T){
 leaf:=&x509.Certificate{
  Raw:[]byte{1,2,3},
  NotBefore:time.Now().UTC().Add(-time.Hour),
  NotAfter:time.Now().UTC().Add(time.Hour),
  KeyUsage:x509.KeyUsageDigitalSignature,
  ExtKeyUsage:[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
 }
 cases:=[]*tls.ConnectionState{
  nil,
  {},
  {PeerCertificates:[]*x509.Certificate{leaf}},
  {PeerCertificates:[]*x509.Certificate{leaf},VerifiedChains:[][]*x509.Certificate{{}}},
  {PeerCertificates:[]*x509.Certificate{leaf},VerifiedChains:[][]*x509.Certificate{{nil}}},
 }
 for i,state:=range cases{
  _,err:=verifySOCOperator(context.Background(),state,&sql.DB{},time.Now().UTC())
  if !errors.Is(err,errSOCNotAuthorized){
   t.Errorf("malformed TLS case %d: got %v want deny",i,err)
  }
 }
}
