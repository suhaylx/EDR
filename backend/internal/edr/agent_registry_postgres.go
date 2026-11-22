package edr

import (
	"context"
	"database/sql"
	"errors"
)

// PostgresAgentIdentityRegistry implements the certificate-registration lookup
// with database/sql. DB must use a PostgreSQL driver, an application read-only
// database role, and a bounded connection pool. Database setup and migration
// are deliberately outside this type.
type PostgresAgentIdentityRegistry struct {
	DB *sql.DB
}

const lookupAgentCertificateSQL = `
SELECT c.fingerprint_sha256
FROM edr_agent_certificates AS c
JOIN edr_agents AS a
  ON a.tenant_id = c.tenant_id AND a.agent_id = c.agent_id
JOIN edr_tenants AS t
  ON t.tenant_id = c.tenant_id
WHERE c.tenant_id = $1 AND c.agent_id = $2
  AND c.revoked_at IS NULL
  AND c.not_before <= CURRENT_TIMESTAMP
  AND c.not_after > CURRENT_TIMESTAMP
  AND a.revoked_at IS NULL
  AND t.disabled_at IS NULL
LIMIT 1`

// LookupAgentCertificate returns only an actively enrolled certificate for an
// enabled tenant and non-revoked agent. A missing, revoked or disabled identity
// is indistinguishable from a never-enrolled identity to the caller.
//
// This lookup alone is insufficient to authenticate a connection: the caller
// must also verify the TLS chain, SAN, leaf fingerprint, EKU and validity using
// VerifyAgentCertificate. Certificate rotation must revoke the prior active
// row in the same audited transaction as the new certificate insertion.
func (r PostgresAgentIdentityRegistry) LookupAgentCertificate(ctx context.Context, tenantID, agentID string) (EnrolledAgentCertificate, error) {
	var empty EnrolledAgentCertificate
	if !validID(tenantID) || !validID(agentID) || tenantID == "." || tenantID == ".." || agentID == "." || agentID == ".." {
		return empty, ErrAgentNotEnrolled
	}
	if r.DB == nil {
		return empty, ErrAgentRegistryUnavailable
	}

	var fingerprint []byte
	err := r.DB.QueryRowContext(ctx, lookupAgentCertificateSQL, tenantID, agentID).Scan(&fingerprint)
	if errors.Is(err, sql.ErrNoRows) {
		return empty, ErrAgentNotEnrolled
	}
	if err != nil || len(fingerprint) != 32 {
		// Do not expose database errors to unauthenticated callers.
		return empty, ErrAgentRegistryUnavailable
	}
	record := EnrolledAgentCertificate{Identity: AgentIdentity{TenantID: tenantID, AgentID: agentID}}
	copy(record.FingerprintSHA256[:], fingerprint)
	return record, nil
}
