package edr

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"math/big"
	"testing"
	"time"
)

func testAgentServerPair(t *testing.T, from, until time.Time, eku []x509.ExtKeyUsage, usage x509.KeyUsage, isCA bool) tls.Certificate {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Root"},
		NotBefore: time.Now().Add(-24 * time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Lab Listener"},
		NotBefore: from, NotAfter: until, KeyUsage: usage,
		ExtKeyUsage: eku, IsCA: isCA, BasicConstraintsValid: true,
		DNSNames: []string{"localhost"},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, root, &key.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{leafDER, rootDER}, PrivateKey: key}
}

func TestValidAgentServerKeypair(t *testing.T) {
	now := time.Now().UTC()
	good := testAgentServerPair(t, now.Add(-time.Hour), now.Add(time.Hour),
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, x509.KeyUsageDigitalSignature, false)
	if !validAgentServerKeypair(good) {
		t.Fatal("valid server certificate unexpectedly denied")
	}
	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	client := testAgentServerPair(t, now.Add(-time.Hour), now.Add(time.Hour),
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, x509.KeyUsageDigitalSignature, false)
	noSigningUsage := testAgentServerPair(t, now.Add(-time.Hour), now.Add(time.Hour),
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, x509.KeyUsageKeyEncipherment, false)
	noEKU := testAgentServerPair(t, now.Add(-time.Hour), now.Add(time.Hour),
		nil, x509.KeyUsageDigitalSignature, false)
	expired := testAgentServerPair(t, now.Add(-2*time.Hour), now.Add(-time.Hour),
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, x509.KeyUsageDigitalSignature, false)
	future := testAgentServerPair(t, now.Add(time.Hour), now.Add(2*time.Hour),
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, x509.KeyUsageDigitalSignature, false)
	ca := testAgentServerPair(t, now.Add(-time.Hour), now.Add(time.Hour),
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, x509.KeyUsageCertSign|x509.KeyUsageDigitalSignature, true)
	for _, tc := range []struct {
		name string
		pair tls.Certificate
	}{
		{"missing-key", tls.Certificate{Certificate: good.Certificate}},
		{"missing-cert", tls.Certificate{PrivateKey: good.PrivateKey}},
		{"invalid-DER", tls.Certificate{Certificate: [][]byte{{1, 2, 3}}, PrivateKey: good.PrivateKey}},
		{"mismatched-public-key", tls.Certificate{Certificate: good.Certificate, PrivateKey: wrongKey}},
		{"client-only-EKU", client},
		{"absent-server-EKU", noEKU},
		{"missing-signature-key-usage", noSigningUsage},
		{"expired", expired},
		{"not-yet-valid", future},
		{"CA-leaf", ca},
		{"non-signing-key", tls.Certificate{Certificate: good.Certificate, PrivateKey: "not a crypto.Signer"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if validAgentServerKeypair(tc.pair) {
				t.Fatal("unsafe server certificate was accepted")
			}
		})
	}
}

// TestNewAgentMTLSServerRejectsInvalidCredentials covers the real listener
// constructor. It prevents the anti-pattern of deferring credential/key mismatch
// until first handshake.
func TestNewAgentMTLSServerRejectsInvalidCredentials(t *testing.T) {
	now := time.Now().UTC()
	good := testAgentServerPair(t, now.Add(-time.Hour), now.Add(time.Hour),
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, x509.KeyUsageDigitalSignature, false)
	trustedRoot, err := x509.ParseCertificate(good.Certificate[1])
	if err != nil {
		t.Fatal(err)
	}
	trustedPool := x509.NewCertPool()
	trustedPool.AddCert(trustedRoot)
	if server, err := NewAgentMTLSServer("127.0.0.1:9443", &sql.DB{}, good, trustedPool); err != nil || server == nil {
		t.Fatalf("valid isolated server configuration rejected: %v", err)
	} else if server.TLSConfig.MinVersion != tls.VersionTLS13 ||
		server.TLSConfig.ClientAuth != tls.RequireAndVerifyClientCert || !server.TLSConfig.SessionTicketsDisabled {
		t.Fatal("listener TLS security invariant lost")
	}
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mismatch := good
	mismatch.PrivateKey = otherKey
	badLeaf := good
	badLeaf.Certificate = [][]byte{{0x01}, good.Certificate[1]}
	client := testAgentServerPair(t, now.Add(-time.Hour), now.Add(time.Hour),
		[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, x509.KeyUsageDigitalSignature, false)
	expired := testAgentServerPair(t, now.Add(-2*time.Hour), now.Add(-time.Hour),
		[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, x509.KeyUsageDigitalSignature, false)
	for _, tc := range []struct {
		name string
		pair tls.Certificate
	}{
		{"mismatched-key", mismatch},
		{"unparseable-leaf", badLeaf},
		{"client-only-EKU", client},
		{"expired-leaf", expired},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, err := NewAgentMTLSServer("127.0.0.1:9443", &sql.DB{}, tc.pair, trustedPool)
			if err == nil || server != nil {
				t.Fatalf("invalid %s certificate was accepted by listener", tc.name)
			}
		})
	}
}
