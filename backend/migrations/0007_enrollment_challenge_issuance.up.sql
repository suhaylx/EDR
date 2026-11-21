-- P0 / BE-001: one outstanding tenant/device challenge and auditable
-- issuer-controlled challenge creation. Apply after migrations 0001..0006.
-- Migration intentionally FAILS if preexisting multiple unconsumed challenges
-- share a tenant/agent. Operators must investigate duplicates; never silently
-- delete enrollment secrets or advance a production migration automatically.
BEGIN;

CREATE UNIQUE INDEX edr_one_outstanding_challenge_per_agent
    ON edr_enrollment_challenges(tenant_id,agent_id)
    WHERE consumed_at IS NULL;

CREATE TABLE edr_enrollment_challenge_audit (
    audit_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id varchar(96) NOT NULL REFERENCES edr_tenants(tenant_id) ON DELETE RESTRICT,
    agent_id varchar(96) NOT NULL,
    challenge_id uuid NOT NULL,
    event_type text NOT NULL CHECK (event_type IN ('challenge_issued','challenge_expired')),
    actor_id text NOT NULL CHECK (length(actor_id) BETWEEN 1 AND 256),
    occurred_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    CONSTRAINT edr_challenge_audit_agent_id CHECK (
        agent_id ~ '^[A-Za-z0-9_.-]{1,96}$' AND agent_id NOT IN ('.','..')
    )
);
CREATE INDEX edr_challenge_audit_agent_time
    ON edr_enrollment_challenge_audit(tenant_id,agent_id,occurred_at DESC);

-- Reuse the existing append-only guard from migration 0002.
CREATE TRIGGER edr_challenge_audit_no_update_delete
BEFORE UPDATE OR DELETE ON edr_enrollment_challenge_audit
FOR EACH ROW EXECUTE FUNCTION edr_reject_audit_mutation();
CREATE TRIGGER edr_challenge_audit_no_truncate
BEFORE TRUNCATE ON edr_enrollment_challenge_audit
FOR EACH STATEMENT EXECUTE FUNCTION edr_reject_audit_mutation();

-- SECURITY INVOKER and no public execute: the privileged issuer DB role
-- needs explicit EXECUTE and narrowly scoped table rights. The public/agent
-- identity/scan roles MUST NOT be able to issue, read or update challenges.
-- The database stores only SHA256(secret), never plaintext credentials.
CREATE FUNCTION edr_issue_enrollment_challenge(
    p_challenge_id uuid, p_tenant_id varchar, p_agent_id varchar,
    p_challenge_digest bytea, p_ttl_seconds integer, p_actor_id text
) RETURNS boolean
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,public
AS $$
DECLARE
    expired_count integer;
BEGIN
    IF p_challenge_id IS NULL OR p_tenant_id IS NULL OR p_agent_id IS NULL
       OR p_tenant_id !~ '^[A-Za-z0-9_.-]{1,96}$'
       OR p_agent_id !~ '^[A-Za-z0-9_.-]{1,96}$'
       OR p_tenant_id IN ('.','..') OR p_agent_id IN ('.','..')
       OR p_challenge_digest IS NULL OR octet_length(p_challenge_digest) <> 32
       OR p_ttl_seconds IS NULL OR p_ttl_seconds NOT BETWEEN 60 AND 600
       OR p_actor_id IS NULL OR length(p_actor_id) NOT BETWEEN 1 AND 256
    THEN RETURN false; END IF;

    -- Serialize issuance with tenant disablement AND initial enrollment.
    -- This also serializes two issuers racing to provision the same device.
    PERFORM 1 FROM public.edr_tenants
    WHERE tenant_id=p_tenant_id AND disabled_at IS NULL FOR UPDATE;
    IF NOT FOUND THEN RETURN false; END IF;

    -- Initial enrollment must never replace an already enrolled/revoked
    -- agent. Recovery requires a separate audited authorization workflow.
    PERFORM 1 FROM public.edr_agents
    WHERE tenant_id=p_tenant_id AND agent_id=p_agent_id;
    IF FOUND THEN RETURN false; END IF;

    -- Invalidate expired unconsumed challenges before any new issuance.
    -- Keep the historical rows and an append-only audit trail.
    WITH expired AS (
        UPDATE public.edr_enrollment_challenges
        SET consumed_at=transaction_timestamp()
        WHERE tenant_id=p_tenant_id AND agent_id=p_agent_id
          AND consumed_at IS NULL AND expires_at <= transaction_timestamp()
        RETURNING challenge_id
    )
    INSERT INTO public.edr_enrollment_challenge_audit(
        tenant_id,agent_id,challenge_id,event_type,actor_id)
    SELECT p_tenant_id,p_agent_id,challenge_id,'challenge_expired',p_actor_id
    FROM expired;

    IF EXISTS(
        SELECT 1 FROM public.edr_enrollment_challenges
        WHERE tenant_id=p_tenant_id AND agent_id=p_agent_id
          AND consumed_at IS NULL
    ) THEN RETURN false; END IF;

    INSERT INTO public.edr_enrollment_challenges(
        challenge_id,tenant_id,agent_id,challenge_digest,created_at,expires_at)
    VALUES (
        p_challenge_id,p_tenant_id,p_agent_id,p_challenge_digest,
        transaction_timestamp(),transaction_timestamp()+make_interval(secs=>p_ttl_seconds)
    );
    INSERT INTO public.edr_enrollment_challenge_audit(
        tenant_id,agent_id,challenge_id,event_type,actor_id)
    VALUES (p_tenant_id,p_agent_id,p_challenge_id,'challenge_issued',p_actor_id);
    RETURN true;
END;
$$;

REVOKE ALL ON FUNCTION edr_issue_enrollment_challenge(
    uuid,varchar,varchar,bytea,integer,text) FROM PUBLIC;
COMMIT;
