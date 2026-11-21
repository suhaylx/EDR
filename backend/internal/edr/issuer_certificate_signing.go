package edr

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"math/big"
	"time"
)

// AgentCASigningPolicy keeps CA key custody outside the EDR HTTP server.
// Signer may be a controlled HSM/KMS-backed crypto.Signer; never load a CA
// private key in the public agent API, issuer request body or database.
// This policy is supplied ONLY to an independently authorized issuance worker.
type AgentCASigningPolicy struct {
	CACertificate *x509.Certificate
	Signer        crypto.Signer
	TrustRoots    *x509.CertPool
	Validity      time.Duration
}

var ErrAgentSigningDenied = errors.New("agent certificate issuance denied")

// SignChallengeBoundAgentCertificate is a policy-constrained signing
// primitive, NOT an HTTP endpoint or permission check. The calling issuance
// worker MUST authenticate the issuer, prove tenant/device authorization,
// verify the original challenge against the database, and ensure the
// returned leaf is finalized through atomic enrollment before use.
// A CSR is signed only after verifying the signature, exact URI SAN and
// single-use challenge binding. A mismatched CA private key is rejected.
func SignChallengeBoundAgentCertificate(
	csrDER []byte, expected AgentIdentity, challengeID string,
	challengeSecret []byte, policy AgentCASigningPolicy, now time.Time,
) ([]byte, error) {
	if now.IsZero() || policy.CACertificate == nil || policy.Signer == nil ||
		policy.TrustRoots == nil || policy.Validity < time.Minute ||
		policy.Validity > 24*time.Hour {
		return nil, ErrAgentSigningDenied
	}
	ca := policy.CACertificate
	if !ca.IsCA || !ca.BasicConstraintsValid ||
		ca.KeyUsage&x509.KeyUsageCertSign == 0 ||
		now.Before(ca.NotBefore) || !now.Add(policy.Validity).Before(ca.NotAfter) {
		return nil, ErrAgentSigningDenied
	}
	caPublicDER, err := x509.MarshalPKIXPublicKey(ca.PublicKey)
	if err != nil {
		return nil, ErrAgentSigningDenied
	}
	signingPublicDER, err := x509.MarshalPKIXPublicKey(policy.Signer.Public())
	if err != nil ||
		subtle.ConstantTimeCompare(caPublicDER, signingPublicDER) != 1 {
		return nil, ErrAgentSigningDenied
	}
	// Verify the issuer's own chain against an explicit CA trust store, never
	// operating-system roots. If the CA is an intermediate, the worker must
	// configure the approved intermediate chain separately.
	if _, err := ca.Verify(x509.VerifyOptions{
		Roots: policy.TrustRoots, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return nil, ErrAgentSigningDenied
	}
	if err := ValidateChallengeBoundAgentCSR(csrDER, expected, challengeID, challengeSecret); err != nil {
		return nil, ErrAgentSigningDenied
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil || len(csr.URIs) != 1 {
		return nil, ErrAgentSigningDenied
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, ErrAgentSigningDenied
	}
	if serial.Sign() == 0 {
		serial = big.NewInt(1)
	}
	start := now.UTC().Truncate(time.Second)
	leaf := &x509.Certificate{
		SerialNumber: serial,
		NotBefore: start,
		NotAfter:  start.Add(policy.Validity),
		KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA: false,
		URIs: csr.URIs,
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, csr.PublicKey, policy.Signer)
	if err != nil {
		return nil, ErrAgentSigningDenied
	}
	// Verify what was actually issued, not only the template.
	if _, err := ValidateTrustedIssuedCertificateForCSR(
		csrDER, der, expected, policy.TrustRoots, nil, now,
	); err != nil {
		return nil, ErrAgentSigningDenied
	}
	// Ensure a compromised/incorrect signer cannot silently substitute a key.
	issued, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, ErrAgentSigningDenied
	}
	requested := sha256.Sum256(csr.RawSubjectPublicKeyInfo)
	issuedKey := sha256.Sum256(issued.RawSubjectPublicKeyInfo)
	if subtle.ConstantTimeCompare(requested[:], issuedKey[:]) != 1 {
		return nil, ErrAgentSigningDenied
	}
	return der, nil
}
