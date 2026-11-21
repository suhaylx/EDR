package edr

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/url"
	"strings"
	"time"
)

// AgentIdentity is a server-authorized device principal. It must never be
// derived from a request body, HTTP header, or an unverified certificate CN.
// A single enrolled identity represents the Rust core and its supervised
// ClamAV/Sysmon workers, not separate products or device registrations.
type AgentIdentity struct {
	TenantID string
	AgentID  string
}

// EnrolledAgentCertificate is the authoritative registration state that the
// persistence layer must return. The fingerprint binds the specific leaf
// certificate to the enrolled tenant/device, even if a trusted CA erroneously
// issued an additional certificate with the same SAN.
type EnrolledAgentCertificate struct {
	Identity          AgentIdentity
	FingerprintSHA256 [32]byte
	Revoked           bool
}

type AgentIdentityRegistry interface {
	LookupAgentCertificate(ctx context.Context, tenantID, agentID string) (EnrolledAgentCertificate, error)
}

var (
	ErrAgentUnauthenticated     = errors.New("agent identity is not authenticated")
	ErrAgentNotEnrolled         = errors.New("agent certificate is not enrolled")
	ErrAgentRegistryUnavailable = errors.New("agent identity registry unavailable")
)

// VerifyAgentCertificate validates a *TLS-authenticated* device identity.
//
// Call only on a direct TLS connection with a server tls.Config using
// RequireAndVerifyClientCert and a private, controlled agent CA. The caller
// must use the returned identity for tenant/device scoping of every operation.
// VerifiedChains is deliberately mandatory; a self-declared certificate in
// PeerCertificates without a verified trust chain is never an identity.
//
// The required URI SAN contract is exactly:
//
//	spiffe://turansec.local/tenants/{tenant_id}/agents/{agent_id}
//
// This is an initial, internal trust-domain convention subject to InfoSec
// review. It does not itself implement SPIFFE federation or enrollment.
func VerifyAgentCertificate(ctx context.Context, state *tls.ConnectionState, registry AgentIdentityRegistry, now time.Time) (AgentIdentity, error) {
	deny := AgentIdentity{}
	if registry == nil || state == nil || len(state.PeerCertificates) == 0 || len(state.VerifiedChains) == 0 {
		return deny, ErrAgentUnauthenticated
	}
	cert := state.PeerCertificates[0]
	if cert == nil || len(cert.Raw) == 0 || cert.IsCA || !now.Before(cert.NotAfter) || now.Before(cert.NotBefore) {
		return deny, ErrAgentUnauthenticated
	}
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 || !hasClientAuthenticationEKU(cert) {
		return deny, ErrAgentUnauthenticated
	}
	// The verified chain must have *the same* leaf as the peer certificate.
	// We do not try alternative verified chains if an inconsistent state is
	// supplied by a proxy or misconfigured test harness.
	if len(state.VerifiedChains[0]) == 0 || state.VerifiedChains[0][0] == nil ||
		subtle.ConstantTimeCompare(cert.Raw, state.VerifiedChains[0][0].Raw) != 1 {
		return deny, ErrAgentUnauthenticated
	}
	if len(cert.URIs) != 1 {
		return deny, ErrAgentUnauthenticated
	}
	identity, ok := parseAgentIdentityURI(cert.URIs[0])
	if !ok {
		return deny, ErrAgentUnauthenticated
	}

	record, err := registry.LookupAgentCertificate(ctx, identity.TenantID, identity.AgentID)
	if err != nil {
		// Never fall back to the certificate SAN when registration is missing
		// or the registry is down. Both failures deny the request.
		if errors.Is(err, ErrAgentNotEnrolled) {
			return deny, ErrAgentUnauthenticated
		}
		return deny, ErrAgentRegistryUnavailable
	}
	if record.Revoked || record.Identity != identity {
		return deny, ErrAgentUnauthenticated
	}
	fp := sha256.Sum256(cert.Raw)
	if subtle.ConstantTimeCompare(fp[:], record.FingerprintSHA256[:]) != 1 {
		return deny, ErrAgentUnauthenticated
	}
	return identity, nil
}

func hasClientAuthenticationEKU(cert *x509.Certificate) bool {
	for _, use := range cert.ExtKeyUsage {
		if use == x509.ExtKeyUsageClientAuth {
			return true
		}
	}
	return false
}

func parseAgentIdentityURI(uri *url.URL) (AgentIdentity, bool) {
	if uri == nil || uri.Scheme != "spiffe" || uri.Host != "turansec.local" || uri.User != nil ||
		uri.RawQuery != "" || uri.Fragment != "" || uri.Opaque != "" || uri.RawPath != "" {
		return AgentIdentity{}, false
	}
	parts := strings.Split(uri.Path, "/")
	if len(parts) != 5 || parts[0] != "" || parts[1] != "tenants" || parts[3] != "agents" {
		return AgentIdentity{}, false
	}
	if !validID(parts[2]) || !validID(parts[4]) || parts[2] == "." || parts[2] == ".." || parts[4] == "." || parts[4] == ".." {
		return AgentIdentity{}, false
	}
	return AgentIdentity{TenantID: parts[2], AgentID: parts[4]}, true
}
