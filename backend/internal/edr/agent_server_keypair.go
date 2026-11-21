package edr

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"reflect"
)

// validateAgentServerKeyPair verifies that the certificate leaf and private
// key configured for the agent mTLS listener belong together. tls.Config
// alone does not reject mismatched pairs until the first handshake; rejecting
// them during construction keeps a broken listener from being published.
// Certificate chain trust, EKU, validity and DNS name are separately checked
// during TLS handshakes by clients. This check is not a production CA audit.
func validateAgentServerKeyPair(pair tls.Certificate) error {
	if len(pair.Certificate) == 0 || len(pair.Certificate[0]) == 0 || pair.PrivateKey == nil {
		return errors.New("agent server certificate and private key required")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return errors.New("agent server leaf certificate is invalid")
	}
	signer, ok := pair.PrivateKey.(crypto.Signer)
	if !ok || signer == nil {
		return errors.New("agent server private key is not a supported signer")
	}
	// Go TLS signer types can contain typed nil pointers; reject them before
	// Signer.Public is called.
	v := reflect.ValueOf(signer)
	if v.Kind() == reflect.Pointer && v.IsNil() {
		return errors.New("agent server private key is empty")
	}
	// Avoid relying on pair.Leaf, which is caller-provided and may be stale.
	actualKey, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return errors.New("agent server private key has an invalid public component")
	}
	certKey, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil || !bytes.Equal(certKey, actualKey) {
		return errors.New("agent server certificate and private key do not match")
	}
	return nil
}
