-- Atomic first enrollment: consumes a challenge, inserts the agent and
-- certificate, and records audit events in one PostgreSQL transaction.
-- IMPORTANT: caller MUST first authenticate an authorized issuer, validate
-- the issued X.509 certificate and SAN, and verify private-key possession.
-- This function alone is NOT a public enrollment protocol.
BEGIN;

CREATE FUNCTION edr_complete_agent_enrollment(
    p_challenge_id uuid, p_tenant_id varchar, p_agent_id varchar,
    p_digest bytea, p_platform text, p_fingerprint bytea,
    p_not_before timestamptz, p_not_after timestamptz, p_actor text
) RETURNS boolean
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,public
AS $$
DECLARE
    consumed boolean;
BEGIN
    IF p_challenge_id IS NULL OR p_tenant_id IS NULL OR p_agent_id IS NULL
       OR p_digest IS NULL OR octet_length(p_digest) <> 32
       OR p_platform NOT IN ('windows','linux')
       OR p_fingerprint IS NULL OR octet_length(p_fingerprint) <> 32
       OR p_not_before IS NULL OR p_not_after IS NULL
       OR p_not_before > transaction_timestamp()
       OR p_not_after <= transaction_timestamp()
       OR p_not_after <= p_not_before
       OR p_actor IS NULL OR length(p_actor) NOT BETWEEN 1 AND 256 THEN
        RETURN false;
    END IF;

    -- Lock the tenant to serialize concurrent tenant disable/enrollment.
    PERFORM 1 FROM public.edr_tenants
    WHERE tenant_id=p_tenant_id AND disabled_at IS NULL FOR UPDATE;
    IF NOT FOUND THEN RETURN false; END IF;

    -- No re-enrollment through this path, even if the existing device is
    -- revoked. Recovery and rotation require distinct approved workflows.
    PERFORM 1 FROM public.edr_agents
    WHERE tenant_id=p_tenant_id AND agent_id=p_agent_id FOR UPDATE;
    IF FOUND THEN RETURN false; END IF;

    consumed := public.edr_consume_enrollment_challenge(
        p_challenge_id,p_tenant_id,p_agent_id,p_digest);
    IF NOT consumed THEN RETURN false; END IF;

    INSERT INTO public.edr_agents(tenant_id,agent_id,platform)
    VALUES(p_tenant_id,p_agent_id,p_platform);

    INSERT INTO public.edr_agent_certificates(
        tenant_id,agent_id,fingerprint_sha256,not_before,not_after)
    VALUES(p_tenant_id,p_agent_id,p_fingerprint,p_not_before,p_not_after);

    INSERT INTO public.edr_enrollment_audit(
        tenant_id,agent_id,event_type,actor_id)
    VALUES(p_tenant_id,p_agent_id,'agent_enrolled',p_actor);
    INSERT INTO public.edr_enrollment_audit(
        tenant_id,agent_id,event_type,fingerprint_sha256,actor_id)
    VALUES(p_tenant_id,p_agent_id,'certificate_enrolled',p_fingerprint,p_actor);
    RETURN true;
END;
$$;

REVOKE ALL ON FUNCTION edr_complete_agent_enrollment(
    uuid,varchar,varchar,bytea,text,bytea,timestamptz,timestamptz,text)
    FROM PUBLIC;
COMMIT;
