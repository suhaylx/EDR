package edr

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func makeTestTLSCert(t *testing.T, start, end time.Time, isCA bool, usage x509.ExtKeyUsage) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "test-only"},
		NotBefore: start, NotAfter: end, BasicConstraintsValid: true, IsCA: isCA,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage},
		DNSNames: []string{"localhost"},
	}
	if isCA {
		template.KeyUsage |= x509.KeyUsageCertSign
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func TestLoadAgentTLSMaterialsGate(t *testing.T) {
	now := time.Now().UTC()
	serverPEM, serverKey := makeTestTLSCert(t, now.Add(-time.Hour), now.Add(time.Hour), false, x509.ExtKeyUsageServerAuth)
	caPEM, _ := makeTestTLSCert(t, now.Add(-time.Hour), now.Add(time.Hour), true, x509.ExtKeyUsageClientAuth)
	dir := t.TempDir()
	write := func(filename string, data []byte) string {
		t.Helper()
		path := filepath.Join(dir, filename)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	serverPath := write("server.pem", serverPEM)
	keyPath := write("server.key", serverKey)
	caPath := write("agent-ca.pem", caPEM)
	if cert, roots, err := LoadAgentTLSMaterials(serverPath, keyPath, caPath, now); err != nil || cert.PrivateKey == nil || roots == nil || len(roots.Subjects()) != 1 {
		t.Fatalf("valid server cert and client CA rejected: err=%v", err)
	}
	cases := []struct {
		name, cert, key, ca string
		when                time.Time
	}{
		{"no-cert", "", keyPath, caPath, now},
		{"no-key", serverPath, "", caPath, now},
		{"no-ca", serverPath, keyPath, "", now},
		{"absent-ca", serverPath, keyPath, filepath.Join(dir, "missing"), now},
		{"expired-server", serverPath, keyPath, caPath, now.Add(2 * time.Hour)},
		{"not-yet-valid-server", serverPath, keyPath, caPath, now.Add(-2 * time.Hour)},
		{"empty-ca", serverPath, keyPath, write("empty-ca.pem", nil), now},
		{"non-ca", serverPath, keyPath, write("wrong-ca.pem", serverPEM), now},
		{"garbage-ca", serverPath, keyPath, write("garbage.pem", []byte("junk")), now},
		{"extra-key-block", serverPath, keyPath, write("key-in-ca.pem", append(append([]byte{}, caPEM...), serverKey...)), now},
	}
	badServerPEM, badServerKey := makeTestTLSCert(t, now.Add(-time.Hour), now.Add(time.Hour), false, x509.ExtKeyUsageClientAuth)
	cases = append(cases, struct {
		name, cert, key, ca string
		when                time.Time
	}{"client-only-server-cert", write("client.pem", badServerPEM), write("client.key", badServerKey), caPath, now})
	_, otherKey := makeTestTLSCert(t, now.Add(-time.Hour), now.Add(time.Hour), false, x509.ExtKeyUsageServerAuth)
	cases = append(cases, struct {
		name, cert, key, ca string
		when                time.Time
	}{"mismatched-server-key", serverPath, write("other.key", otherKey), caPath, now})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := LoadAgentTLSMaterials(tc.cert, tc.key, tc.ca, tc.when)
			if err == nil {
				t.Fatal("expected fail-closed TLS validation")
			}
			if strings.Contains(err.Error(), "-----BEGIN") {
				t.Fatal("key material leaked in error")
			}
		})
	}
}
