-- BE-001: atomic certificate rotation with an append-only audit trail.
-- Migration role only. No direct EXECUTE grant to the endpoint/API role.
BEGIN;

CREATE FUNCTION edr_rotate_agent_certificate(
    p_tenant_id varchar,
    p_agent_id varchar,
    p_old_fingerprint bytea,
    p_new_fingerprint bytea,
    p_not_before timestamptz,
    p_not_after timestamptz,
    p_actor_id text
) RETURNS boolean
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, public
AS $$
DECLARE
    changed integer;
BEGIN
    IF p_tenant_id IS NULL OR p_agent_id IS NULL
       OR p_actor_id IS NULL OR length(p_actor_id) NOT BETWEEN 1 AND 256
       OR p_old_fingerprint IS NULL OR octet_length(p_old_fingerprint) <> 32
       OR p_new_fingerprint IS NULL OR octet_length(p_new_fingerprint) <> 32
       OR p_old_fingerprint = p_new_fingerprint
       OR p_not_before IS NULL OR p_not_after IS NULL
       OR p_not_before >= p_not_after THEN
        RAISE EXCEPTION 'invalid certificate rotation parameters'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    -- Serialize rotations with both agent revocation AND tenant disablement.
    -- An agent-only lock can observe an apparently active tenant while an
    -- administrator is updating disabled_at in an uncommitted transaction.
    -- FOR SHARE OF t blocks that update without serializing rotations on
    -- unrelated devices in the same active tenant. The tenant/device pair
    -- is never taken from an unauthenticated header.
    PERFORM 1 FROM public.edr_agents AS a
    JOIN public.edr_tenants AS t ON t.tenant_id = a.tenant_id
    WHERE a.tenant_id = p_tenant_id AND a.agent_id = p_agent_id
      AND a.revoked_at IS NULL AND t.disabled_at IS NULL
    FOR UPDATE OF a
    FOR SHARE OF t;
    IF NOT FOUND THEN RETURN false; END IF;

    UPDATE public.edr_agent_certificates
    SET revoked_at = transaction_timestamp(), revoke_reason = 'rotation'
    WHERE tenant_id = p_tenant_id AND agent_id = p_agent_id
      AND fingerprint_sha256 = p_old_fingerprint AND revoked_at IS NULL;
    GET DIAGNOSTICS changed = ROW_COUNT;
    IF changed <> 1 THEN RETURN false; END IF;

    INSERT INTO public.edr_enrollment_audit(
        tenant_id, agent_id, event_type, fingerprint_sha256, actor_id
    ) VALUES (
        p_tenant_id, p_agent_id, 'certificate_revoked',
        p_old_fingerprint, p_actor_id
    );

    INSERT INTO public.edr_agent_certificates(
        tenant_id, agent_id, fingerprint_sha256, not_before, not_after
    ) VALUES (
        p_tenant_id, p_agent_id, p_new_fingerprint, p_not_before, p_not_after
    );

    INSERT INTO public.edr_enrollment_audit(
        tenant_id, agent_id, event_type, fingerprint_sha256, actor_id
    ) VALUES (
        p_tenant_id, p_agent_id, 'certificate_enrolled',
        p_new_fingerprint, p_actor_id
    );

    RETURN true;
END;
$$;

REVOKE ALL ON FUNCTION edr_rotate_agent_certificate(
    varchar,varchar,bytea,bytea,timestamptz,timestamptz,text
) FROM PUBLIC;

COMMIT;
