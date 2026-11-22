package edr

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"reflect"
	"time"
)

// validAgentServerKeypair rejects invalid server credentials before opening a
// listener rather than deferring failures to an endpoint's TLS handshake.
// It always parses the authenticated certificate bytes, not an optional,
// potentially stale tls.Certificate.Leaf cache.
func validAgentServerKeypair(pair tls.Certificate) bool {
	if len(pair.Certificate) == 0 || pair.PrivateKey == nil {
		return false
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || leaf.IsCA || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return false
	}
	if !leaf.NotBefore.Before(leaf.NotAfter) || time.Now().Before(leaf.NotBefore) || !time.Now().Before(leaf.NotAfter) {
		return false
	}
	serverEKU := false
	for _, usage := range leaf.ExtKeyUsage {
		if usage == x509.ExtKeyUsageServerAuth {
			serverEKU = true
			break
		}
	}
	if !serverEKU {
		return false
	}
	signer, ok := pair.PrivateKey.(crypto.Signer)
	if !ok {
		return false
	}
	// A typed nil key satisfies crypto.Signer but cannot supply a public key.
	// Reject it before invoking methods, as required by the SEC-052 owner fix.
	value := reflect.ValueOf(signer)
	if value.Kind() == reflect.Pointer && value.IsNil() {
		return false
	}
	publicDER, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return false
	}
	return bytes.Equal(publicDER, leaf.RawSubjectPublicKeyInfo)
}
