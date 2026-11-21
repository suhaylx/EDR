-- BE-001 / P0: persistent, tenant-scoped scan-job queue foundation.
-- Migration role only. Agent/API identity, authorization and dispatch are
-- intentionally separate; no production worker is enabled by this migration.
BEGIN;

CREATE TABLE edr_scan_jobs (
    job_id uuid PRIMARY KEY,
    tenant_id varchar(96) NOT NULL,
    agent_id varchar(96) NOT NULL,
    scan_root text NOT NULL CHECK (length(scan_root) BETWEEN 1 AND 4096),
    state text NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending','leased','succeeded','failed','cancelled')),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    lease_owner text,
    lease_token uuid,
    lease_expires_at timestamptz,
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    max_attempts integer NOT NULL DEFAULT 3 CHECK (max_attempts BETWEEN 1 AND 20),
    CONSTRAINT edr_scan_job_agent_fk
        FOREIGN KEY (tenant_id,agent_id) REFERENCES edr_agents(tenant_id,agent_id)
        ON DELETE RESTRICT,
    CONSTRAINT edr_scan_job_lease_consistency CHECK (
        (state = 'leased' AND lease_owner IS NOT NULL
            AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL)
        OR
        (state <> 'leased' AND lease_owner IS NULL
            AND lease_token IS NULL AND lease_expires_at IS NULL)
    )
);
CREATE INDEX edr_scan_jobs_pending ON edr_scan_jobs(tenant_id,agent_id,created_at)
    WHERE state = 'pending';
CREATE INDEX edr_scan_jobs_expired ON edr_scan_jobs(lease_expires_at)
    WHERE state = 'leased';

-- Called only after the service authenticates and authorizes the agent.
-- SKIP LOCKED prevents two concurrent pollers from leasing the same row.
-- Caller-generated lease token must be cryptographically random and unique.
CREATE FUNCTION edr_claim_scan_job(
    p_tenant_id varchar, p_agent_id varchar, p_lease_owner text,
    p_lease_token uuid, p_lease_seconds integer
) RETURNS TABLE(job_id uuid, scan_root text, attempt_count integer)
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, public
AS $$
BEGIN
    IF p_tenant_id IS NULL OR p_agent_id IS NULL
       OR p_lease_owner IS NULL OR length(p_lease_owner) NOT BETWEEN 1 AND 256
       OR p_lease_token IS NULL OR p_lease_seconds NOT BETWEEN 5 AND 300 THEN
        RAISE EXCEPTION 'invalid lease parameters' USING ERRCODE='invalid_parameter_value';
    END IF;
    RETURN QUERY
    WITH picked AS (
        SELECT j.job_id FROM public.edr_scan_jobs AS j
        JOIN public.edr_agents AS a
          ON a.tenant_id=j.tenant_id AND a.agent_id=j.agent_id
        JOIN public.edr_tenants AS t ON t.tenant_id=j.tenant_id
        WHERE j.tenant_id=p_tenant_id AND j.agent_id=p_agent_id
          AND a.revoked_at IS NULL AND t.disabled_at IS NULL
          AND j.state='pending' AND j.attempt_count < j.max_attempts
        ORDER BY j.created_at, j.job_id
        FOR UPDATE OF j SKIP LOCKED LIMIT 1
    )
    UPDATE public.edr_scan_jobs AS j
    SET state='leased', lease_owner=p_lease_owner, lease_token=p_lease_token,
        lease_expires_at=transaction_timestamp()+make_interval(secs=>p_lease_seconds),
        attempt_count=j.attempt_count+1, updated_at=transaction_timestamp()
    FROM picked
    WHERE j.job_id=picked.job_id
    RETURNING j.job_id,j.scan_root,j.attempt_count;
END;
$$;

-- A completion requires the matching tenant, agent, job and current lease
-- token; stale or cross-device completions fail closed.
CREATE FUNCTION edr_complete_scan_job(
    p_tenant_id varchar, p_agent_id varchar, p_job_id uuid,
    p_lease_token uuid, p_success boolean
) RETURNS boolean
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, public
AS $$
DECLARE changed integer;
BEGIN
    IF p_tenant_id IS NULL OR p_agent_id IS NULL OR p_job_id IS NULL
       OR p_lease_token IS NULL OR p_success IS NULL THEN RETURN false; END IF;
    -- A lease alone cannot authorize completion after revocation/disablement.
    -- Lock the current principal and tenant for the duration of the update,
    -- serializing this authorization check with administrative revocations.
    PERFORM 1 FROM public.edr_tenants AS t
    JOIN public.edr_agents AS a ON a.tenant_id=t.tenant_id
    WHERE t.tenant_id=p_tenant_id AND a.agent_id=p_agent_id
      AND t.disabled_at IS NULL AND a.revoked_at IS NULL
    FOR SHARE OF t,a;
    IF NOT FOUND THEN RETURN false; END IF;

    UPDATE public.edr_scan_jobs AS j
    SET state=CASE WHEN p_success THEN 'succeeded' ELSE 'failed' END,
        lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,
        updated_at=transaction_timestamp()
    WHERE j.tenant_id=p_tenant_id AND j.agent_id=p_agent_id AND j.job_id=p_job_id
      AND j.state='leased' AND j.lease_token=p_lease_token
      AND j.lease_expires_at > transaction_timestamp();
    GET DIAGNOSTICS changed = ROW_COUNT;
    RETURN changed=1;
END;
$$;

-- Recovery is explicit: expired leases are returned to pending when retries
-- remain, or marked failed when attempts are exhausted.
CREATE FUNCTION edr_recover_expired_scan_jobs(p_limit integer)
RETURNS integer LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,public
AS $$
DECLARE changed integer;
BEGIN
    IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 1000 THEN
        RAISE EXCEPTION 'invalid recovery limit' USING ERRCODE='invalid_parameter_value';
    END IF;
    WITH expired AS (
        SELECT job_id FROM public.edr_scan_jobs
        WHERE state='leased' AND lease_expires_at <= transaction_timestamp()
        ORDER BY lease_expires_at,job_id FOR UPDATE SKIP LOCKED LIMIT p_limit
    )
    UPDATE public.edr_scan_jobs AS j
    SET state=CASE WHEN j.attempt_count < j.max_attempts THEN 'pending' ELSE 'failed' END,
        lease_owner=NULL,lease_token=NULL,lease_expires_at=NULL,
        updated_at=transaction_timestamp()
    FROM expired WHERE j.job_id=expired.job_id;
    GET DIAGNOSTICS changed = ROW_COUNT;
    RETURN changed;
END;
$$;

REVOKE ALL ON FUNCTION edr_claim_scan_job(varchar,varchar,text,uuid,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION edr_complete_scan_job(varchar,varchar,uuid,uuid,boolean) FROM PUBLIC;
REVOKE ALL ON FUNCTION edr_recover_expired_scan_jobs(integer) FROM PUBLIC;

COMMIT;
