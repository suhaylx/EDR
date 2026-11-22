-- BE-001 hardening: append-only audit, transactional certificate revocation.
-- Run only after 0001_agent_enrollment.up.sql with a migration-only role.
BEGIN;

CREATE FUNCTION edr_reject_audit_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'enrollment audit is append-only'
        USING ERRCODE = 'insufficient_privilege';
END;
$$;

CREATE TRIGGER edr_enrollment_audit_no_update_delete
BEFORE UPDATE OR DELETE ON edr_enrollment_audit
FOR EACH ROW EXECUTE FUNCTION edr_reject_audit_mutation();

CREATE TRIGGER edr_enrollment_audit_no_truncate
BEFORE TRUNCATE ON edr_enrollment_audit
FOR EACH STATEMENT EXECUTE FUNCTION edr_reject_audit_mutation();

-- SECURITY INVOKER is intentional: caller must have explicit UPDATE rights
-- on certificates and INSERT rights on audit. Do not grant these to the
-- unauthenticated agent HTTP or identity-read roles.
CREATE FUNCTION edr_revoke_agent_certificate(
    p_tenant_id varchar,
    p_agent_id varchar,
    p_fingerprint bytea,
    p_actor_id text,
    p_reason text
) RETURNS boolean
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, public
AS $$
DECLARE
    changed integer;
BEGIN
    IF p_actor_id IS NULL OR length(p_actor_id) NOT BETWEEN 1 AND 256
       OR p_reason IS NULL OR length(p_reason) NOT BETWEEN 1 AND 512
       OR p_fingerprint IS NULL OR octet_length(p_fingerprint) <> 32 THEN
        RAISE EXCEPTION 'invalid revocation metadata'
            USING ERRCODE = 'invalid_parameter_value';
    END IF;

    UPDATE public.edr_agent_certificates
    SET revoked_at = transaction_timestamp(), revoke_reason = p_reason
    WHERE tenant_id = p_tenant_id
      AND agent_id = p_agent_id
      AND fingerprint_sha256 = p_fingerprint
      AND revoked_at IS NULL;
    GET DIAGNOSTICS changed = ROW_COUNT;
    IF changed = 0 THEN
        RETURN false;
    END IF;

    INSERT INTO public.edr_enrollment_audit(
        tenant_id, agent_id, event_type, fingerprint_sha256, actor_id
    ) VALUES (
        p_tenant_id, p_agent_id, 'certificate_revoked', p_fingerprint, p_actor_id
    );
    RETURN true;
END;
$$;

-- A revoked leaf must never be silently made active again.
CREATE FUNCTION edr_prevent_certificate_reactivation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS NULL THEN
        RAISE EXCEPTION 'revoked certificate cannot be reactivated'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER edr_certificate_no_reactivation
BEFORE UPDATE ON edr_agent_certificates
FOR EACH ROW EXECUTE FUNCTION edr_prevent_certificate_reactivation();

-- Function execution is not granted to PUBLIC. A separately provisioned
-- privileged enrollment writer must be granted EXECUTE explicitly.
REVOKE ALL ON FUNCTION edr_revoke_agent_certificate(varchar,varchar,bytea,text,text) FROM PUBLIC;

COMMIT;
