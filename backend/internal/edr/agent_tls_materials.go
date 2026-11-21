package edr

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"runtime"
	"time"
)

// LoadAgentTLSMaterials reads a dedicated agent-listener server keypair and
// controlled client CA bundle. It does not open sockets or enroll endpoints.
// The caller must configure tls.RequireAndVerifyClientCert and TLS 1.3.
func LoadAgentTLSMaterials(certPath, keyPath, clientCAPath string, now time.Time) (tls.Certificate, *x509.CertPool, error) {
	var empty tls.Certificate
	if certPath == "" || keyPath == "" || clientCAPath == "" {
		return empty, nil, errors.New("agent TLS certificate, private key and client CA paths are required")
	}
	if err := validateAgentServerPrivateKeyFile(keyPath); err != nil {
		return empty, nil, err
	}
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return empty, nil, errors.New("cannot load agent listener server keypair")
	}
	if len(pair.Certificate) == 0 || pair.PrivateKey == nil {
		return empty, nil, errors.New("agent listener server keypair is incomplete")
	}
	leaf := pair.Leaf
	if leaf == nil {
		leaf, err = x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			return empty, nil, errors.New("agent listener server certificate is invalid")
		}
	}
	if leaf.IsCA || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) ||
		leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return empty, nil, errors.New("agent listener server certificate is not currently valid for TLS")
	}
	serverAuth := false
	for _, usage := range leaf.ExtKeyUsage {
		if usage == x509.ExtKeyUsageServerAuth {
			serverAuth = true
		}
	}
	if !serverAuth {
		return empty, nil, errors.New("agent listener certificate lacks explicit server authentication usage")
	}

	caPEM, err := os.ReadFile(clientCAPath)
	if err != nil {
		return empty, nil, errors.New("cannot read controlled agent client CA bundle")
	}
	roots := x509.NewCertPool()
	count := 0
	for len(caPEM) > 0 {
		var block *pem.Block
		block, caPEM = pem.Decode(caPEM)
		if block == nil {
			return empty, nil, errors.New("invalid agent CA PEM bundle")
		}
		if block.Type != "CERTIFICATE" {
			return empty, nil, errors.New("agent CA bundle contains non-certificate material")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !cert.BasicConstraintsValid || !cert.IsCA ||
			cert.KeyUsage&x509.KeyUsageCertSign == 0 ||
			now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
			return empty, nil, errors.New("agent client CA bundle contains invalid or expired CA certificate")
		}
		roots.AddCert(cert)
		count++
	}
	if count == 0 {
		return empty, nil, errors.New("agent client CA bundle is empty")
	}
	return pair, roots, nil
}

// validateAgentServerPrivateKeyFile rejects key-file mistakes on Unix.
// Windows file mode bits do not describe NTFS ACL; that requires a separate
// deployment-time ACL security check before production use.
func validateAgentServerPrivateKeyFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return errors.New("cannot stat agent server private key")
	}
	if !info.Mode().IsRegular() {
		return errors.New("agent server private key must be a regular file, not a symlink or device")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return errors.New("agent server private key must not be readable by group or others")
	}
	return nil
}
