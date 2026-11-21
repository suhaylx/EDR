package edr

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/tls"
    "crypto/x509"
    "crypto/x509/pkix"
    "math/big"
    "strings"
    "testing"
    "time"
)

func TestSEC052ServerKeypairRejectedBeforeListenerStartup(t *testing.T) {
    correct, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil { t.Fatal(err) }
    wrong, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil { t.Fatal(err) }
    cert := &x509.Certificate{
        SerialNumber: big.NewInt(42),
        Subject: pkix.Name{CommonName: "localhost"},
        NotBefore: time.Now().Add(-time.Hour),
        NotAfter: time.Now().Add(time.Hour),
        KeyUsage: x509.KeyUsageDigitalSignature,
        ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
    }
    der, err := x509.CreateCertificate(rand.Reader, cert, cert, &correct.PublicKey, correct)
    if err != nil { t.Fatal(err) }
    tests := []struct {
        name string
        pair tls.Certificate
        valid bool
    }{
        {"matching", tls.Certificate{Certificate: [][]byte{der}, PrivateKey: correct}, true},
        {"wrong-private-key", tls.Certificate{Certificate: [][]byte{der}, PrivateKey: wrong}, false},
        {"malformed-leaf", tls.Certificate{Certificate: [][]byte{{0x00, 0xff}}, PrivateKey: correct}, false},
        {"empty-leaf", tls.Certificate{Certificate: [][]byte{{}}, PrivateKey: correct}, false},
        {"missing-key", tls.Certificate{Certificate: [][]byte{der}}, false},
        {"unsupported-key", tls.Certificate{Certificate: [][]byte{der}, PrivateKey: strings.NewReader("not a signer")}, false},
        {"typed-nil-signer", tls.Certificate{Certificate: [][]byte{der}, PrivateKey: (*ecdsa.PrivateKey)(nil)}, false},
    }
    for _, tc := range tests {
        t.Run(tc.name, func(t *testing.T) {
            err := validateAgentServerKeyPair(tc.pair)
            if tc.valid && err != nil {t.Fatalf("matching key pair rejected: %v",err)}
            if !tc.valid && err == nil {t.Fatal("invalid certificate/key pair accepted")}
        })
    }
}
