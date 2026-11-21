-- TuranSec EDR BE-001: PostgreSQL tenant/device/certificate registry.
-- Apply with an operator-controlled migration role before enabling any
-- production agent listener. Never grant schema migrations to the API role.
BEGIN;

CREATE TABLE edr_tenants (
    tenant_id varchar(96) PRIMARY KEY,
    display_name text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 256),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    disabled_at timestamptz,
    CONSTRAINT edr_tenant_id_format CHECK (
        tenant_id ~ '^[A-Za-z0-9_.-]{1,96}$' AND tenant_id NOT IN ('.', '..')
    )
);

CREATE TABLE edr_agents (
    tenant_id varchar(96) NOT NULL REFERENCES edr_tenants(tenant_id) ON DELETE RESTRICT,
    agent_id varchar(96) NOT NULL,
    platform text NOT NULL CHECK (platform IN ('windows', 'linux')),
    enrolled_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    revoked_at timestamptz,
    PRIMARY KEY (tenant_id, agent_id),
    CONSTRAINT edr_agent_id_format CHECK (
        agent_id ~ '^[A-Za-z0-9_.-]{1,96}$' AND agent_id NOT IN ('.', '..')
    )
);

CREATE TABLE edr_agent_certificates (
    tenant_id varchar(96) NOT NULL,
    agent_id varchar(96) NOT NULL,
    fingerprint_sha256 bytea NOT NULL CHECK (octet_length(fingerprint_sha256) = 32),
    not_before timestamptz NOT NULL,
    not_after timestamptz NOT NULL,
    enrolled_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    revoked_at timestamptz,
    revoke_reason text CHECK (revoke_reason IS NULL OR length(revoke_reason) <= 512),
    PRIMARY KEY (tenant_id, agent_id, fingerprint_sha256),
    FOREIGN KEY (tenant_id, agent_id) REFERENCES edr_agents(tenant_id, agent_id) ON DELETE RESTRICT,
    CONSTRAINT edr_certificate_dates CHECK (not_before < not_after),
    CONSTRAINT edr_certificate_revoke_consistency CHECK (revoked_at IS NOT NULL OR revoke_reason IS NULL)
);

-- Certificate rotation must revoke the old row first, in one transaction.
CREATE UNIQUE INDEX edr_one_active_certificate_per_agent
    ON edr_agent_certificates (tenant_id, agent_id)
    WHERE revoked_at IS NULL;

-- Append-only audit intent: enforce INSERT-only grants for application roles.
CREATE TABLE edr_enrollment_audit (
    audit_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id varchar(96) NOT NULL,
    agent_id varchar(96),
    event_type text NOT NULL CHECK (event_type IN (
        'tenant_created', 'tenant_disabled', 'tenant_enabled',
        'agent_enrolled', 'agent_revoked', 'agent_reinstated',
        'certificate_enrolled', 'certificate_revoked'
    )),
    fingerprint_sha256 bytea CHECK (fingerprint_sha256 IS NULL OR octet_length(fingerprint_sha256) = 32),
    actor_id text NOT NULL CHECK (length(actor_id) BETWEEN 1 AND 256),
    occurred_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    FOREIGN KEY (tenant_id) REFERENCES edr_tenants(tenant_id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, agent_id) REFERENCES edr_agents(tenant_id, agent_id) ON DELETE RESTRICT
);
CREATE INDEX edr_enrollment_audit_agent_time
    ON edr_enrollment_audit(tenant_id, agent_id, occurred_at DESC);

COMMIT;
