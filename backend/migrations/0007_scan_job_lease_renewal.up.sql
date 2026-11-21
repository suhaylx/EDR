-- BE-002: extend a live scan lease only for its authorized tenant/device/worker.
-- Run after 0006_atomic_agent_enrollment.up.sql. No public execution grants.
BEGIN;
CREATE FUNCTION edr_renew_scan_job_lease(
    p_tenant_id varchar, p_agent_id varchar, p_job_id uuid,
    p_lease_owner text, p_lease_token uuid, p_lease_seconds integer
) RETURNS boolean
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,public
AS $$
DECLARE changed integer;
BEGIN
    IF p_tenant_id IS NULL OR p_agent_id IS NULL OR p_job_id IS NULL
       OR p_lease_owner IS NULL OR length(p_lease_owner) NOT BETWEEN 1 AND 256
       OR p_lease_token IS NULL OR p_lease_seconds IS NULL
       OR p_lease_seconds NOT BETWEEN 5 AND 300 THEN RETURN false; END IF;

    -- Serialize authorization with concurrent tenant/device revocation.
    PERFORM 1 FROM public.edr_tenants AS t
    JOIN public.edr_agents AS a ON a.tenant_id=t.tenant_id
    WHERE t.tenant_id=p_tenant_id AND a.agent_id=p_agent_id
      AND t.disabled_at IS NULL AND a.revoked_at IS NULL
    FOR SHARE OF t,a;
    IF NOT FOUND THEN RETURN false; END IF;

    UPDATE public.edr_scan_jobs AS j
    SET lease_expires_at=transaction_timestamp()+make_interval(secs=>p_lease_seconds),
        updated_at=transaction_timestamp()
    WHERE j.tenant_id=p_tenant_id AND j.agent_id=p_agent_id AND j.job_id=p_job_id
      AND j.state='leased' AND j.lease_owner=p_lease_owner
      AND j.lease_token=p_lease_token
      AND j.lease_expires_at > transaction_timestamp();
    GET DIAGNOSTICS changed=ROW_COUNT;
    RETURN changed=1;
END;
$$;
REVOKE ALL ON FUNCTION edr_renew_scan_job_lease(varchar,varchar,uuid,text,uuid,integer) FROM PUBLIC;
COMMIT;
