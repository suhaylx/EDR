package edr

import (
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"errors"
	"net"
	"net/http"
	"time"
)

// NewIssuerEnrollmentMTLSServer is intentionally separate from the agent API
// listener and the localhost-only developer bearer-token dashboard.
// Issuer CAs must be a dedicated, controlled trust pool (not system roots or
// the ordinary agent CA). The leaf allowlist is an additional tenant-scoped
// authorization gate. No certificate private key or issuer API secret is loaded
// by this constructor, and it does not start or expose the listener.
func NewIssuerEnrollmentMTLSServer(
	addr string,
	db *sql.DB,
	serverCert tls.Certificate,
	issuerClientCAs *x509.CertPool,
	agentIssuerRoots *x509.CertPool,
	agentIntermediates *x509.CertPool,
	allowedIssuers []TrustedEnrollmentIssuer,
) (*http.Server, error) {
	if db == nil || issuerClientCAs == nil || agentIssuerRoots == nil ||
		len(serverCert.Certificate) == 0 || serverCert.PrivateKey == nil {
		return nil, errors.New("issuer listener requires database, server keypair, issuer client CAs, and agent CA roots")
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" || host == "0.0.0.0" || host == "::" {
		return nil, errors.New("issuer listener requires a specific, approved host:port")
	}
	handler, err := NewIssuerEnrollmentHandler(PostgresEnrollmentStore{DB: db}, agentIssuerRoots, agentIntermediates, allowedIssuers)
	if err != nil {
		return nil, err
	}
	return &http.Server{
		Addr:    addr,
		Handler: handler,
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    issuerClientCAs,
			Certificates: []tls.Certificate{serverCert},
		},
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       45 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}, nil
}
