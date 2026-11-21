-- BE-001: single-use, expiring enrollment challenges.
-- The challenge secret is never stored: persist only SHA-256 digest.
-- Enrollment issuer and proof-of-possession are separate required controls.
BEGIN;

CREATE TABLE edr_enrollment_challenges (
    challenge_id uuid PRIMARY KEY,
    tenant_id varchar(96) NOT NULL REFERENCES edr_tenants(tenant_id) ON DELETE RESTRICT,
    agent_id varchar(96) NOT NULL,
    challenge_digest bytea NOT NULL CHECK (octet_length(challenge_digest) = 32),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    CONSTRAINT edr_challenge_agent_id CHECK (
        agent_id ~ '^[A-Za-z0-9_.-]{1,96}$' AND agent_id NOT IN ('.', '..')
    ),
    CONSTRAINT edr_challenge_expiry CHECK (expires_at > created_at),
    CONSTRAINT edr_challenge_consumed_after_create CHECK (
        consumed_at IS NULL OR consumed_at >= created_at
    )
);
CREATE UNIQUE INDEX edr_challenge_digest_unique
    ON edr_enrollment_challenges(challenge_digest);
CREATE INDEX edr_challenge_active_lookup
    ON edr_enrollment_challenges(tenant_id,agent_id,expires_at)
    WHERE consumed_at IS NULL;

-- Returns true exactly once for a matching, unexpired challenge.
-- The authenticated enrollment service must independently authorize the
-- tenant/device and validate private-key proof of possession before consuming.
CREATE FUNCTION edr_consume_enrollment_challenge(
    p_challenge_id uuid,
    p_tenant_id varchar,
    p_agent_id varchar,
    p_digest bytea
) RETURNS boolean
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, public
AS $$
DECLARE changed integer;
BEGIN
    IF p_challenge_id IS NULL OR p_tenant_id IS NULL OR p_agent_id IS NULL
       OR p_digest IS NULL OR octet_length(p_digest) <> 32 THEN
        RETURN false;
    END IF;
    UPDATE public.edr_enrollment_challenges AS c
    SET consumed_at = transaction_timestamp()
    FROM public.edr_tenants AS t
    WHERE c.challenge_id = p_challenge_id
      AND c.tenant_id = p_tenant_id AND c.agent_id = p_agent_id
      AND c.challenge_digest = p_digest
      AND c.tenant_id = t.tenant_id AND t.disabled_at IS NULL
      AND c.consumed_at IS NULL AND c.expires_at > transaction_timestamp();
    GET DIAGNOSTICS changed = ROW_COUNT;
    RETURN changed = 1;
END;
$$;

REVOKE ALL ON FUNCTION edr_consume_enrollment_challenge(uuid,varchar,varchar,bytea) FROM PUBLIC;

COMMIT;
